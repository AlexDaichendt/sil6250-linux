use std::io;

use sil6250::PskMode;
pub use sil6250::{engine::IMG_SIZE, Features, Frame};

pub struct Engine(sil6250::Engine);

// SAFETY: Engine is used from spawn_blocking (single thread at a time).
unsafe impl Send for Engine {}

impl Engine {
    pub fn open(devpath: &str) -> io::Result<Self> {
        let mut e = sil6250::Engine::open(devpath)?;
        e.set_key(Some("shiba"))?;
        // SIL6250_VERBOSE=1 enables the library's low-level transport tracing
        // (TX/RX dumps, finger polls, checksum mismatches) on stderr, which the
        // service captures into the journal. Diagnostic only; off by default.
        if std::env::var_os("SIL6250_VERBOSE").is_some() {
            e.set_verbose(true);
        }
        // SIL6250_PSK_MODE picks where the TLS PSK comes from:
        //   auto      (default) provision, fall back to legacy if that fails
        //   provision push a fresh random key to the sensor before each handshake
        //   replay    push the key blob captured from the Windows driver
        //   legacy    no provisioning; firmware fallback key ("shiba") only
        if let Some(mode) = std::env::var_os("SIL6250_PSK_MODE") {
            match mode.to_str().and_then(|m| m.parse::<PskMode>().ok()) {
                Some(m) => e.set_psk_mode(m),
                None => tracing::warn!(?mode, "unknown SIL6250_PSK_MODE; using auto"),
            }
        }
        Ok(Engine(e))
    }

    /// Capture one frame with quality gating.
    ///
    /// Returns `None` on timeout or after exhausting `max_retry` quality failures.
    pub fn capture(
        &mut self,
        finger_ms: u32,
        quality_min: f32,
        max_retry: u32,
    ) -> Option<(Frame, Box<[u8; IMG_SIZE]>)> {
        let mut raw = Box::new([0u8; IMG_SIZE]);
        for attempt in 0..=max_retry {
            let arr = self.0.capture_frame(finger_ms).ok()?;
            *raw = arr;
            let frame = Frame::from_raw(&raw);
            let q = frame.quality();
            let ok = q >= quality_min || attempt >= max_retry;
            tracing::debug!(attempt, q, quality_min, ok, "capture quality");
            if ok {
                return Some((frame, raw));
            }
            self.wait_finger_up(4000);
        }
        None
    }

    pub fn wait_finger_up(&mut self, timeout_ms: u32) -> bool {
        self.0.wait_finger_up(timeout_ms)
    }
}
