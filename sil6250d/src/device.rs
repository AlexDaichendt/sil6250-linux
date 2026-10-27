use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, MutexGuard};
use zbus::{interface, object_server::SignalEmitter};

use crate::engine::{Engine, Features, Frame};
use crate::storage;

const ENROLL_STAGES: u32 = 15;
/// How long one capture call waits for a finger. The loops just call again on
/// timeout, so this only bounds how quickly they notice cancellation or sleep.
const POLL_SLICE_MS: u32 = 500;
const LIFT_MS: u32 = 4_000;
const MAX_SHIFT: i32 = 14;
const MIN_OVERLAP: i32 = 1200;
const ENROLL_MAX_NCC: f32 = 0.85;
const ENROLL_MAX_REDUNDANT: u32 = ENROLL_STAGES * 4;
const QUALITY_MIN: f32 = 0.52;
const SIFT_THRESHOLD: i32 = 5;
/// Attempts (and the delay between them) to reopen the sensor after a sleep.
const REOPEN_ATTEMPTS: u32 = 5;
const REOPEN_DELAY: Duration = Duration::from_millis(500);

pub const OBJECT_PATH: &str = "/io/github/uunicorn/Fprint/Device";

pub struct DeviceService {
    devpath: String,
    /// Cancellation flag of the operation currently running, if any.
    current: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    /// Serializes access to the sensor. The engine drives a single MMIO mailbox
    /// and one pair of strobe GPIOs, so two engines open on `/dev/sil6250` at
    /// once corrupt each other's frames and no TLS handshake ever completes.
    dev_lock: Arc<Mutex<()>>,
}

#[derive(Clone)]
struct Operation {
    cancelled: Arc<AtomicBool>,
    current: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}

impl Operation {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    async fn lock_current(&self) -> Option<MutexGuard<'_, Option<Arc<AtomicBool>>>> {
        let current = self.current.lock().await;
        if self.is_cancelled()
            || !current.as_ref().is_some_and(|token| Arc::ptr_eq(token, &self.cancelled))
        {
            return None;
        }
        // Serialize publication and storage with cancellation and replacement.
        Some(current)
    }
}

impl DeviceService {
    pub fn new(devpath: String) -> Self {
        DeviceService {
            devpath,
            current: Arc::default(),
            dev_lock: Arc::default(),
        }
    }

    async fn begin_op(&self) -> Operation {
        let mut current = self.current.lock().await;
        if let Some(previous) = current.take() {
            previous.store(true, Ordering::Relaxed);
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        *current = Some(Arc::clone(&cancelled));
        Operation { cancelled, current: Arc::clone(&self.current) }
    }

    async fn cancel_current(&self) {
        if let Some(current) = self.current.lock().await.take() {
            current.store(true, Ordering::Relaxed);
        }
    }
}

#[interface(name = "io.github.uunicorn.Fprint.Device")]
impl DeviceService {
    #[zbus(property)]
    fn name(&self) -> &str {
        "sil6250"
    }

    #[zbus(property)]
    fn num_enroll_stages(&self) -> u32 {
        ENROLL_STAGES
    }

    #[zbus(property)]
    fn scan_type(&self) -> &str {
        "press"
    }

    async fn list_enrolled_fingers(&self, username: &str) -> Vec<String> {
        storage::list_enrolled(username)
    }

    async fn delete_enrolled_fingers(&self, username: &str) -> zbus::fdo::Result<()> {
        storage::delete_enrolled(username)
            .map_err(|e| zbus::fdo::Error::Failed(format!("delete failed: {e}")))
    }

    async fn enroll_start(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        username: &str,
        finger_name: &str,
    ) -> zbus::fdo::Result<()> {
        let operation = self.begin_op().await;
        let dev_lock = Arc::clone(&self.dev_lock);

        let devpath = self.devpath.clone();
        let username = username.to_owned();
        let finger_name = finger_name.to_owned();
        let emitter = emitter.to_owned();

        tokio::task::spawn(async move {
            let (status, done) = {
                // Wait for any previous engine to let go of the sensor.
                let _device = dev_lock.lock().await;

                if operation.is_cancelled() {
                    tracing::debug!("enroll superseded before it reached the sensor");
                    ("enroll-failed", true)
                } else {
                    let result = tokio::task::spawn_blocking({
                        let operation = operation.clone();
                        let emitter = emitter.clone();
                        let username = username.clone();
                        let finger_name = finger_name.clone();
                        move || {
                            enroll_blocking(&devpath, &username, &finger_name, &operation, emitter)
                        }
                    })
                    .await;

                    match result {
                        Ok(Ok(())) => ("enroll-completed", true),
                        Ok(Err(e)) => {
                            tracing::error!("enroll error: {e}");
                            ("enroll-failed", true)
                        }
                        Err(e) => {
                            tracing::error!("enroll task panicked: {e}");
                            ("enroll-failed", true)
                        }
                    }
                }
            };

            if let Some(mut current) = operation.lock_current().await {
                let _ = DeviceService::enroll_status(&emitter, status, done).await;
                *current = None;
            };
        });

        Ok(())
    }

    async fn enroll_stop(&self) -> zbus::fdo::Result<()> {
        self.cancel_current().await;
        Ok(())
    }

    async fn verify_start(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        username: &str,
        finger_name: &str,
    ) -> zbus::fdo::Result<()> {
        let operation = self.begin_op().await;
        let dev_lock = Arc::clone(&self.dev_lock);

        let devpath = self.devpath.clone();
        let username = username.to_owned();
        let finger_name = finger_name.to_owned();
        let emitter = emitter.to_owned();

        tokio::task::spawn(async move {
            // Only the terminal decision is emitted here; the non-terminal
            // "verify-retry-scan" signals for poor scans are emitted from inside
            // verify_blocking as the user re-presses, so any error returned here
            // is final and must complete the operation (done = true).
            let (status, done) = {
                // Wait for any previous engine to let go of the sensor.
                let _device = dev_lock.lock().await;

                if operation.is_cancelled() {
                    // A newer verify owns the sensor now; opening a second
                    // engine here is what used to wedge the handshake.
                    tracing::debug!("verify superseded before it reached the sensor");
                    ("verify-no-match", true)
                } else {
                    let result = tokio::task::spawn_blocking({
                        let operation = operation.clone();
                        let emitter = emitter.clone();
                        let username = username.clone();
                        let finger_name = finger_name.clone();
                        move || {
                            verify_blocking(&devpath, &username, &finger_name, &operation, emitter)
                        }
                    })
                    .await;

                    match result {
                        Ok(Ok(true)) => ("verify-match", true),
                        Ok(Ok(false)) => ("verify-no-match", true),
                        Ok(Err(e)) => {
                            tracing::warn!("verify error: {e}");
                            ("verify-no-match", true)
                        }
                        Err(e) => {
                            tracing::error!("verify task panicked: {e}");
                            ("verify-no-match", true)
                        }
                    }
                }
            };

            if let Some(mut current) = operation.lock_current().await {
                let _ = DeviceService::verify_status(&emitter, status, done).await;
                *current = None;
            };
        });

        Ok(())
    }

    async fn verify_stop(&self) -> zbus::fdo::Result<()> {
        self.cancel_current().await;
        Ok(())
    }

    async fn cancel(&self) -> zbus::fdo::Result<()> {
        self.cancel_current().await;
        Ok(())
    }

    // Sent by open-fprintd's optional suspend/resume units, and too late to
    // act on: open-fprintd-suspend runs alongside the suspend, not before it.
    // The capture loops notice a sleep themselves (Engine::slept) and reopen
    // the sensor. Cancelling here would strand a client mid-verify, such as
    // pam_fprintd in a lock screen, until its own timeout.
    async fn suspend(&self) {
        tracing::debug!("suspend requested");
    }

    async fn resume(&self) {
        tracing::debug!("resume requested");
    }

    async fn run_cmd(&self, _cmd: &str) -> zbus::fdo::Result<String> {
        Err(zbus::fdo::Error::NotSupported(
            "RunCmd not implemented".into(),
        ))
    }

    #[zbus(signal)]
    async fn enroll_status(
        emitter: &SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn verify_status(
        emitter: &SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn verify_finger_selected(emitter: &SignalEmitter<'_>, finger: &str) -> zbus::Result<()>;
}

/// Open a fresh engine after the system slept under the old one.
///
/// The sensor loses its state (TLS session included) across suspend/hibernate.
/// The running operation carries on with the new engine, so a client waiting
/// on it, such as pam_fprintd in a lock screen, never notices the sleep.
fn reopen_after_sleep(devpath: &str, operation: &Operation) -> anyhow::Result<Engine> {
    tracing::debug!("system slept; reopening the sensor");
    let mut attempt = 1;
    loop {
        if operation.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        match Engine::open(devpath) {
            Ok(engine) => {
                tracing::info!(attempt, "sensor reopened after sleep");
                return Ok(engine);
            }
            // The device can take a moment to come back after resume.
            Err(e) if attempt < REOPEN_ATTEMPTS => {
                tracing::debug!(attempt, "reopening the sensor failed: {e}");
                std::thread::sleep(REOPEN_DELAY);
                attempt += 1;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn enroll_blocking(
    devpath: &str,
    username: &str,
    finger_name: &str,
    operation: &Operation,
    emitter: SignalEmitter<'_>,
) -> anyhow::Result<()> {
    let mut engine = Engine::open(devpath)?;
    let rt = tokio::runtime::Handle::current();

    let mut kept_features: Vec<Features> = Vec::new();
    let mut kept_frames: Vec<Frame> = Vec::new();
    let mut got: u32 = 0;
    let mut redundant: u32 = 0;

    while got < ENROLL_STAGES {
        if operation.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        if engine.slept() {
            engine = reopen_after_sleep(devpath, operation)?;
        }

        // Single capture per presentation; classify quality ourselves rather
        // than letting capture() force a low-quality frame through on its last
        // retry. No finger / unusable read just keeps waiting for a press.
        let Some((frame, _raw)) = engine.capture(POLL_SLICE_MS, 0.0, 0) else {
            continue;
        };

        // Reject poor scans outright: a weak frame pollutes the gallery and
        // drags down genuine match scores. Ask the user to present again.
        if operation.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        let q = frame.quality();
        if q < QUALITY_MIN {
            tracing::debug!(q, quality_min = QUALITY_MIN, "enroll: poor scan, retry");
            let em = emitter.clone();
            rt.block_on(async move {
                if let Some(_current) = operation.lock_current().await {
                    let _ = DeviceService::enroll_status(&em, "enroll-retry-scan", false).await;
                }
            });
            redundant += 1;
            if redundant >= ENROLL_MAX_REDUNDANT {
                break;
            }
            engine.wait_finger_up(LIFT_MS);
            continue;
        }

        let too_similar = kept_frames
            .iter()
            .any(|kept| frame.ncc_vs(kept, MAX_SHIFT, MIN_OVERLAP) > ENROLL_MAX_NCC);

        if too_similar {
            redundant += 1;
            if redundant >= ENROLL_MAX_REDUNDANT {
                break;
            }
        } else {
            kept_features.push(Features::extract(&frame));
            kept_frames.push(frame);
            got += 1;
            let em = emitter.clone();
            rt.block_on(async move {
                if let Some(_current) = operation.lock_current().await {
                    let _ = DeviceService::enroll_status(&em, "enroll-stage-passed", false).await;
                }
            });
        }

        if got < ENROLL_STAGES {
            engine.wait_finger_up(LIFT_MS);
        }
    }

    if got != ENROLL_STAGES {
        anyhow::bail!("incomplete enrollment ({got}/{ENROLL_STAGES} frames)");
    }

    let kp_counts: Vec<usize> = kept_features.iter().map(|f| f.kp.len()).collect();
    tracing::debug!(stages = got, ?kp_counts, "enroll complete");
    rt.block_on(async {
        let _current = operation.lock_current().await
            .ok_or_else(|| anyhow::anyhow!("cancelled"))?;
        storage::save_features(username, finger_name, &kept_features)
            .map_err(anyhow::Error::from)
    })?;
    Ok(())
}

fn verify_blocking(
    devpath: &str,
    username: &str,
    finger_name: &str,
    operation: &Operation,
    emitter: SignalEmitter<'_>,
) -> anyhow::Result<bool> {
    // fprintd uses the sentinel finger "any" to mean "match against any
    // enrolled finger". Build a combined gallery from every stored finger in
    // that case; otherwise load the single requested finger.
    let gallery = if finger_name == "any" {
        let mut all = Vec::new();
        for finger in storage::list_enrolled(username) {
            all.extend(storage::load_features(username, &finger)?);
        }
        all
    } else {
        storage::load_features(username, finger_name)?
    };
    if gallery.is_empty() {
        anyhow::bail!("no enrolled data for {username}/{finger_name}");
    }

    let mut engine = Engine::open(devpath)?;
    let rt = tokio::runtime::Handle::current();

    // Canonical press-sensor loop: one finger presentation per round. A poor or
    // unusable scan is reported as a non-terminal "verify-retry-scan" so the user
    // simply re-presses with no penalty and no client round-trip; only a
    // good-quality capture yields a match / no-match decision.
    loop {
        if operation.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        if engine.slept() {
            engine = reopen_after_sleep(devpath, operation)?;
        }

        // quality_min = 0, max_retry = 0: take a single frame and classify the
        // scan ourselves rather than letting capture() silently re-prompt.
        let Some((frame, _raw)) = engine.capture(POLL_SLICE_MS, 0.0, 0) else {
            // No finger or an unusable read this round — keep waiting for a press.
            continue;
        };

        if operation.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        let q = frame.quality();
        if q < QUALITY_MIN {
            tracing::debug!(q, quality_min = QUALITY_MIN, "verify: poor scan, retry");
            let em = emitter.clone();
            rt.block_on(async move {
                if let Some(_current) = operation.lock_current().await {
                    let _ = DeviceService::verify_status(&em, "verify-retry-scan", false).await;
                }
            });
            engine.wait_finger_up(LIFT_MS);
            continue;
        }

        let probe = Features::extract(&frame);
        let score = probe.verify_against(&gallery);
        if tracing::enabled!(tracing::Level::DEBUG) {
            let per: Vec<i32> = gallery
                .iter()
                .map(|g| probe.verify_against(std::slice::from_ref(g)))
                .collect();
            tracing::debug!(
                probe_kp = probe.kp.len(),
                gallery = gallery.len(),
                ?per,
                "verify inliers"
            );
        }
        tracing::debug!(score, q, threshold = SIFT_THRESHOLD, "verify result");
        if operation.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        return Ok(score >= SIFT_THRESHOLD);
    }
}

#[cfg(test)]
mod operation_tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_operation_cannot_publish() {
        let service = DeviceService::new(String::new());
        let operation = service.begin_op().await;
        service.cancel_current().await;
        assert!(operation.is_cancelled());
        assert!(operation.lock_current().await.is_none());
    }

    #[tokio::test]
    async fn replaced_operation_cannot_publish() {
        let service = DeviceService::new(String::new());
        let previous = service.begin_op().await;
        let current = service.begin_op().await;
        assert!(previous.is_cancelled());
        assert!(previous.lock_current().await.is_none());
        assert!(current.lock_current().await.is_some());
    }

    #[tokio::test]
    async fn cancellation_waits_for_in_flight_publication() {
        let service = DeviceService::new(String::new());
        let operation = service.begin_op().await;
        let publication = operation.lock_current().await.unwrap();
        let cancellation = service.cancel_current();
        tokio::pin!(cancellation);
        assert!(futures_util::poll!(cancellation.as_mut()).is_pending());
        assert!(!operation.is_cancelled());
        drop(publication);
        cancellation.await;
        assert!(operation.lock_current().await.is_none());
    }

    #[tokio::test]
    async fn suspend_keeps_operation_alive() {
        let service = DeviceService::new(String::new());
        let operation = service.begin_op().await;
        service.suspend().await;
        service.resume().await;
        assert!(!operation.is_cancelled());
        assert!(operation.lock_current().await.is_some());
    }
}
