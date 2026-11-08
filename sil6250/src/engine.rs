// SPDX-License-Identifier: GPL-2.0
//! SIL6250 TLS-PSK capture engine.

use std::io::{self, Read, Write};
use std::ptr::NonNull;
use std::str::FromStr;
use std::thread::sleep;
use std::time::{Duration, Instant};

use openssl::ssl::{HandshakeError, Ssl, SslContext, SslContextBuilder, SslMethod, SslStream,
                   SslVerifyMode, SslVersion};

use crate::proto::{
    checksum, PETAIT_ACCESS_WIDTH_32BIT, PETAIT_CMD_INIT, PETAIT_CMD_KEY_ID,
    PETAIT_CMD_MODULE_INFO, PETAIT_CMD_POLL, PETAIT_CMD_SET_PSK, PETAIT_CMD_TLS_CTRL,
    PETAIT_CMD_TLS_DATA, PETAIT_DIR_IN, PETAIT_DIR_OUT, PETAIT_OUTER_TYPE_STD,
};
use crate::psk;
use crate::transport::{
    slept_error, PetaicDev, PETAIC_READ_CHUNK_MAX, PETAIC_XFER_NO_IRQ, PETAIC_XFER_READ_ONLY,
};

// ---- PSK keys --------------------------------------------------------------

// Firmware fallback keys. A sensor that has never been handed a key (cmd 0x27,
// see psk.rs) accepts one of these on some units and none of them on others.
struct PskEntry {
    name: &'static str,
    key: [u8; 32],
}

static PSK_KEYS: &[PskEntry] = &[
    PskEntry {
        name: "shiba",
        key: [
            0x73, 0x50, 0x10, 0x37, 0x39, 0xbf, 0xbc, 0x8e, 0x68, 0xd6, 0xc9, 0xa8, 0x94, 0x27,
            0x99, 0x34, 0x3d, 0x82, 0xc7, 0x2f, 0x01, 0x5d, 0x00, 0x62, 0x0f, 0x79, 0x14, 0x2c,
            0xdf, 0xc3, 0x4c, 0x81,
        ],
    },
    PskEntry {
        name: "saintbernard",
        key: [
            0xee, 0x9a, 0xbb, 0x5a, 0x2b, 0x9e, 0xc3, 0x4a, 0x81, 0x66, 0x4b, 0x53, 0xc2, 0xcf,
            0xcd, 0xd8, 0x55, 0xf2, 0x0a, 0x62, 0x2c, 0x4d, 0xa2, 0xe8, 0xf5, 0x1e, 0xe2, 0x4e,
            0x95, 0x10, 0xdd, 0x2b,
        ],
    },
    PskEntry {
        name: "chihuahua",
        key: [
            0x58, 0x7d, 0x3f, 0x96, 0x2e, 0x3d, 0x7e, 0xa1, 0xf0, 0x8c, 0x0f, 0xb7, 0x9c, 0x03,
            0x78, 0x4d, 0x9f, 0xec, 0x2d, 0x1f, 0x97, 0xf7, 0x6c, 0x7f, 0x5d, 0x2f, 0x66, 0xed,
            0x43, 0x2d, 0x9f, 0xe9,
        ],
    },
    PskEntry {
        name: "bordercollie",
        key: [
            0x10, 0x58, 0x5a, 0x35, 0xac, 0x1e, 0x78, 0xce, 0x4f, 0x30, 0x8d, 0xe7, 0x35, 0x2d,
            0xd1, 0xaf, 0x62, 0x53, 0x95, 0x00, 0xdb, 0xe7, 0x1b, 0xe2, 0x15, 0xd7, 0xab, 0x51,
            0xae, 0x9f, 0xe3, 0x40,
        ],
    },
];

/// Where the handshake PSK comes from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PskMode {
    /// `Provision`, then `Legacy` if the sensor does not take the key.
    #[default]
    Auto,
    /// Push a fresh random key to the sensor (cmd 0x27) before each handshake.
    Provision,
    /// Push the exact blob the Windows driver was traced sending.
    Replay,
    /// No provisioning: handshake with the firmware fallback key ring.
    Legacy,
}

impl PskMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PskMode::Auto => "auto",
            PskMode::Provision => "provision",
            PskMode::Replay => "replay",
            PskMode::Legacy => "legacy",
        }
    }
}

impl FromStr for PskMode {
    type Err = io::Error;

    fn from_str(s: &str) -> io::Result<Self> {
        match s {
            "auto" => Ok(PskMode::Auto),
            "provision" => Ok(PskMode::Provision),
            "replay" => Ok(PskMode::Replay),
            "legacy" => Ok(PskMode::Legacy),
            _ => Err(io::Error::from_raw_os_error(nix::libc::EINVAL)),
        }
    }
}

// One handshake attempt: the key to use and, if it has to be pushed to the
// sensor first, the cmd 0x27 blob carrying it.
#[derive(Clone)]
struct KeyPlan {
    name: &'static str,
    key: [u8; 32],
    blob: Option<[u8; psk::PSK_BLOB_LEN]>,
}

impl KeyPlan {
    fn ring(idx: usize) -> Self {
        KeyPlan { name: PSK_KEYS[idx].name, key: PSK_KEYS[idx].key, blob: None }
    }

    fn provision() -> io::Result<Self> {
        let (key, blob) = psk::random_blob()?;
        Ok(KeyPlan { name: "provision", key, blob: Some(blob) })
    }

    fn replay() -> Self {
        KeyPlan { name: "replay", key: psk::WINDOWS_KEY, blob: Some(psk::WINDOWS_BLOB) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsDir {
    HostToSensor,
    SensorToHost,
}

/// Everything observed during one handshake attempt, for diagnostics.
/// The `Vec` fields hold raw mailbox reads (data at offset 7).
#[derive(Clone, Debug)]
pub struct HandshakeAttempt {
    /// `"provision"`, `"replay"`, or the fallback ring key name.
    pub key_name: &'static str,
    pub key: [u8; 32],
    /// The key was pushed to the sensor with cmd 0x27 first.
    pub provisioned: bool,
    pub module_info: Option<Vec<u8>>,
    pub key_id_before: Option<Vec<u8>>,
    pub set_psk_ack: Option<Vec<u8>>,
    pub set_psk_acked: bool,
    pub turn_on_tls: Option<Vec<u8>>,
    /// Only with [`Engine::set_key_id_readback`].
    pub key_id_after: Option<Vec<u8>>,
    /// TLS byte stream as it crossed the mailbox, in order.
    pub tls: Vec<(TlsDir, Vec<u8>)>,
    /// PSK identity from the sensor's ClientKeyExchange.
    pub identity: Option<Vec<u8>>,
    /// `SHA384(key)[..32]` for a provisioned key.
    pub expected_identity: Option<[u8; psk::IDENTITY_LEN]>,
    /// `None` if the handshake completed.
    pub error: Option<String>,
}

// ---- image geometry --------------------------------------------------------

pub const IMG_W: usize = 64;
pub const IMG_H: usize = 80;
pub const IMG_SIZE: usize = IMG_W * IMG_H; // 5120
const IMG_CKSUM_LEN: usize = 4;
const IMG_TOTAL: usize = IMG_SIZE + IMG_CKSUM_LEN;

const SC_RX_OFF: usize = 7; // data window offset in raw mailbox reads
const SC_TX_MAX: usize = 480;
const IMG_CTRL_PARAM: u8 = 0x3c;
const IMG_BULK0_LEN: u32 = 3109;
const IMG_BULK0_RETRIES: u32 = 6;
const IMG_CONT_RETRIES: u32 = 8;
const CAPTURE_ATTEMPTS: u32 = 6;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const HANDSHAKE_MAX_WOULD_BLOCKS: usize = 64;

// Windows waits ~100 ms before sending the key, up to 500 ms for its ack, and
// ~150 ms after turning TLS on. Only the provisioning path takes these sleeps.
const SET_PSK_PRE_MS: u64 = 100;
const SET_PSK_ACK_MS: u32 = 500;
const SET_PSK_TLS_ON_MS: u64 = 150;
const HS_TRACE_MAX: usize = 16 * 1024;

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Handshake,
    Image,
}

// ---- shared engine state ---------------------------------------------------

struct EngineShared {
    dev: PetaicDev,
    verbose: bool,
    skip_prelude_20: bool,
    phase: Phase,
    // image-phase record buffer
    rec: [u8; 4096],
    rec_len: usize,
    rec_off: usize,
    rec_idx: i32,
    last_head: [u8; 16],
    // handshake-phase stream leftover
    hs_leftover: [u8; 512],
    hs_leftover_len: usize,
    hs_leftover_off: usize,
    handshake_deadline: Option<Instant>,
    // handshake-phase TLS transcript (diagnostics)
    hs_trace: Vec<(TlsDir, Vec<u8>)>,
    hs_trace_len: usize,
}

impl EngineShared {
    fn hs_trace_push(&mut self, dir: TlsDir, data: &[u8]) {
        if self.phase != Phase::Handshake || self.hs_trace_len + data.len() > HS_TRACE_MAX {
            return;
        }
        self.hs_trace_len += data.len();
        self.hs_trace.push((dir, data.to_vec()));
    }
}

// ---- custom BIO ------------------------------------------------------------

struct TransportBio(NonNull<EngineShared>);

impl std::fmt::Debug for TransportBio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransportBio")
    }
}

// SAFETY: Engine is used single-threaded (spawn_blocking).
unsafe impl Send for TransportBio {}

impl Read for TransportBio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let e = unsafe { self.0.as_mut() };

        if e.phase == Phase::Image {
            if e.rec_off >= e.rec_len {
                img_pull_record(e)?;
            }
            let n = (e.rec_len - e.rec_off).min(buf.len());
            buf[..n].copy_from_slice(&e.rec[e.rec_off..e.rec_off + n]);
            e.rec_off += n;
            return Ok(n);
        }

        // Handshake phase: drain leftover first.
        if e.hs_leftover_len > e.hs_leftover_off {
            let n = (e.hs_leftover_len - e.hs_leftover_off).min(buf.len());
            buf[..n]
                .copy_from_slice(&e.hs_leftover[e.hs_leftover_off..e.hs_leftover_off + n]);
            e.hs_leftover_off += n;
            return Ok(n);
        }
        e.hs_leftover_len = 0;
        e.hs_leftover_off = 0;

        // Read into a local buffer first to avoid borrowing e.hs_leftover
        // and &mut e simultaneously.
        let deadline = e.handshake_deadline;
        for _ in 0..12 {
            let mut tmp = [0u8; 512];
            let got = read_chunk(&mut e.dev, &mut tmp, deadline)?;
            if got > 0 {
                e.hs_trace_push(TlsDir::SensorToHost, &tmp[..got]);
                e.hs_leftover[..got].copy_from_slice(&tmp[..got]);
                e.hs_leftover_len = got;
                let n = got.min(buf.len());
                buf[..n].copy_from_slice(&e.hs_leftover[..n]);
                e.hs_leftover_off = n;
                return Ok(n);
            }
        }
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }
}

impl Write for TransportBio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let e = unsafe { self.0.as_mut() };
        e.hs_trace_push(TlsDir::HostToSensor, buf);
        bio_send(&mut e.dev, buf, e.handshake_deadline)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---- low-level transport helpers -------------------------------------------

fn bounded_timeout(deadline: Option<Instant>, default_ms: u32) -> io::Result<u32> {
    let Some(deadline) = deadline else {
        return Ok(default_ms);
    };
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
    let remaining_ms = remaining.as_millis().max(1).min(u32::MAX as u128) as u32;
    Ok(default_ms.min(remaining_ms))
}

fn write_chunk(
    dev: &mut PetaicDev,
    data: &[u8],
    deadline: Option<Instant>,
) -> io::Result<()> {
    if data.is_empty() || data.len() > 255 {
        return Err(io::Error::from_raw_os_error(nix::libc::EINVAL));
    }
    let payload_len = (data.len() - 1) + 4;
    if payload_len > SC_TX_MAX {
        return Err(io::Error::from_raw_os_error(nix::libc::EINVAL));
    }
    let mut tx = [0u8; SC_TX_MAX];
    if data.len() > 1 {
        tx[..data.len() - 1].copy_from_slice(&data[1..]);
    }
    let mut rx = [0u8; 64];
    let timeout_ms = bounded_timeout(deadline, 500)?;
    dev.xfer_raw(
        0x00,                        // SC_CMD_WRITE
        0x02,                        // SC_DIR_WRITE
        data.len() as u8,
        (data.len() as u8).wrapping_add(15),
        data[0] as u32,
        &tx[..payload_len],
        &mut rx,
        1,
        timeout_ms,
        0,
    )?;
    Ok(())
}

// Drain one TLS stream chunk from cmd 0x22 reads into `out`. Returns byte count.
fn read_chunk(
    dev: &mut PetaicDev,
    out: &mut [u8],
    deadline: Option<Instant>,
) -> io::Result<usize> {
    let want = out.len().min(512);
    let rx_cap = (SC_RX_OFF + want + 16).min(PETAIC_READ_CHUNK_MAX) & !7;
    let mut rx = [0u8; PETAIC_READ_CHUNK_MAX];

    // Bound the lone-marker continuation loop: a wedged sensor that keeps
    // returning the 0x5A continuation marker would otherwise spin forever,
    // hanging the capture thread (and the login sensor) indefinitely.
    const MAX_CONTINUATIONS: u32 = 64;
    let mut continuations = 0u32;

    loop {
        let timeout_ms = bounded_timeout(deadline, 350)?;
        let r = dev.xfer_raw(
            0,
            0,
            0,
            0,
            0,
            &[],
            &mut rx[..rx_cap],
            1,
            timeout_ms,
            PETAIC_XFER_READ_ONLY,
        );
        match r {
            Err(ref e) if e.raw_os_error() == Some(nix::libc::ETIMEDOUT) => return Ok(0),
            Err(e) => return Err(e),
            Ok(n) if n < SC_RX_OFF || rx[0] == 0xff || rx[0] != 0x5a => return Ok(0),
            Ok(_) => {}
        }
        let navail = rx[3] as usize;
        if navail == 0 {
            return Ok(0);
        }
        // Skip lone 0x5A continuation marker.
        if navail == 1 && rx[SC_RX_OFF] == 0x5a {
            continuations += 1;
            if continuations >= MAX_CONTINUATIONS {
                return Ok(0);
            }
            continue;
        }
        let n = navail.min(want).min(rx_cap.saturating_sub(SC_RX_OFF));
        out[..n].copy_from_slice(&rx[SC_RX_OFF..SC_RX_OFF + n]);
        return Ok(n);
    }
}

// bio_send: fragment a TLS record stream into write_chunk calls.
fn bio_send(
    dev: &mut PetaicDev,
    buf: &[u8],
    deadline: Option<Instant>,
) -> io::Result<()> {
    let mut p = buf;
    while !p.is_empty() {
        if p.len() < 5 {
            write_chunk(dev, p, deadline)?;
            break;
        }
        let rlen = ((p[3] as usize) << 8) | p[4] as usize;
        write_chunk(dev, &p[..5], deadline)?;
        p = &p[5..];
        let mut body = rlen.min(p.len());
        while body > 0 {
            let c = body.min(255);
            write_chunk(dev, &p[..c], deadline)?;
            p = &p[c..];
            body -= c;
        }
    }
    Ok(())
}

// ---- handshake prelude -----------------------------------------------------

fn hex(p: &[u8]) -> String {
    p.iter().map(|b| format!("{b:02x}")).collect()
}

// Length of a raw mailbox response carrying `data_len` bytes: 7-byte head,
// data, 4-byte checksum, qword padding.
fn resp_len(data_len: usize) -> usize {
    (SC_RX_OFF + data_len + 4 + 7) & !7
}

fn read_key_id(dev: &mut PetaicDev) -> Option<Vec<u8>> {
    let tx = [0u8; 7];
    let mut rx = [0u8; 256];
    dev.xfer_raw(PETAIT_CMD_KEY_ID, 0x01, 0x04, 0x13, psk::KEY_ID_LEN as u32, &tx, &mut rx, 0, 0, 0)
        .ok()
        .map(|_| rx[..resp_len(psk::KEY_ID_LEN)].to_vec())
}

// Hand the sensor its PSK (cmd 0x27) and wait for the 0xaa ack.
fn send_psk(
    dev: &mut PetaicDev,
    blob: &[u8; psk::PSK_BLOB_LEN],
    verbose: bool,
    att: &mut HandshakeAttempt,
) -> io::Result<()> {
    let (be32, payload) = psk::set_psk_args(blob);
    let mut rx = [0u8; 64];
    // One try only: a missing ack is the caller's cue to fall back, not to
    // push the key again.
    dev.xfer_raw(
        PETAIT_CMD_SET_PSK, psk::SET_PSK_DIR, psk::SET_PSK_WIDTH, psk::SET_PSK_OUTER, be32,
        &payload, &mut rx, 1, SET_PSK_ACK_MS, 0,
    )?;
    // The level IRQ can fire on the previous transaction's leftover and hand
    // us that response again; give the real answer one more window.
    if rx[0] != 0x5a || rx[1] != PETAIT_CMD_SET_PSK {
        let _ = dev.xfer_raw(0, 0, 0, 0, 0, &[], &mut rx, 1, SET_PSK_ACK_MS, PETAIC_XFER_READ_ONLY);
    }
    att.set_psk_ack = Some(rx[..resp_len(1)].to_vec());
    att.set_psk_acked = psk::is_set_psk_ack(&rx);
    if verbose {
        eprintln!(
            "[engine] cmd 0x27 response {} -> {}",
            hex(&rx[..resp_len(1)]),
            if att.set_psk_acked { "acked" } else { "NOT acked" }
        );
    }
    if !att.set_psk_acked {
        return Err(io::Error::from_raw_os_error(nix::libc::EPROTO));
    }
    Ok(())
}

// 0x20 module info, 0x01, 0x28 key id, [0x27 set PSK], 0x22 "turn on TLS".
fn sc_prelude(
    dev: &mut PetaicDev,
    skip_20: bool,
    blob: Option<&[u8; psk::PSK_BLOB_LEN]>,
    verbose: bool,
    att: &mut HandshakeAttempt,
) -> io::Result<()> {
    let tx = [0u8; 11];
    let mut rx = [0u8; 256];
    if !skip_20
        && dev.xfer_raw(PETAIT_CMD_MODULE_INFO, 0x01, 0x04, 0x13, 128, &tx[..7], &mut rx, 0, 0, 0).is_ok()
    {
        att.module_info = Some(rx[..resp_len(128)].to_vec());
    }
    let reg01: &[u8] = &[0x01, 0x08, 0xff, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let _ = dev.xfer_raw(0x01, 0x00, 0x08, 0x17, 0x08, reg01, &mut rx, 0, 0, 0);
    att.key_id_before = read_key_id(dev);
    if verbose {
        // All zeros on a sensor that has not been keyed since power-up.
        match att.key_id_before.as_deref().and_then(psk::key_id_from_response) {
            Some(id) => eprintln!("[engine] key id (cmd 0x28): {}", hex(id)),
            None => eprintln!("[engine] key id (cmd 0x28): no valid response"),
        }
    }
    if let Some(blob) = blob {
        sleep(Duration::from_millis(SET_PSK_PRE_MS));
        send_psk(dev, blob, verbose, att)?;
    }
    if dev.xfer_raw(0x22, 0x01, 0x04, 0x13, 1, &tx[..7], &mut rx, 0, 0, 0).is_ok() {
        att.turn_on_tls = Some(rx[..resp_len(1)].to_vec());
    }
    if blob.is_some() {
        sleep(Duration::from_millis(SET_PSK_TLS_ON_MS));
    }
    Ok(())
}

// ---- image-phase bulk record reader ----------------------------------------

fn img_pull_record(e: &mut EngineShared) -> io::Result<()> {
    let mut rx = [0u8; PETAIC_READ_CHUNK_MAX];

    let r = if e.rec_idx == 0 {
        let region = [((IMG_BULK0_LEN >> 8) & 0xff) as u8, 0, 0, 0, 0, 0, 0];
        let mut result = Err(io::Error::from_raw_os_error(nix::libc::ETIMEDOUT));
        for _ in 0..IMG_BULK0_RETRIES {
            result = e.dev.xfer_raw(
                PETAIT_CMD_TLS_DATA, PETAIT_DIR_OUT, PETAIT_ACCESS_WIDTH_32BIT,
                PETAIT_OUTER_TYPE_STD, IMG_BULK0_LEN & 0xff, &region, &mut rx, 1, 400, 0,
            );
            match &result {
                Err(e2) if e2.raw_os_error() == Some(nix::libc::ETIMEDOUT) => continue,
                Err(_) => break,
                Ok(n) if *n > SC_RX_OFF
                    && (rx[SC_RX_OFF] == 0x17 || rx[SC_RX_OFF] == 0x16) =>
                {
                    break
                }
                Ok(_) => sleep(Duration::from_millis(60)),
            }
        }
        result
    } else {
        let mut result = Err(io::Error::from_raw_os_error(nix::libc::ETIMEDOUT));
        for _ in 0..IMG_CONT_RETRIES {
            sleep(Duration::from_millis(40));
            result = e.dev.xfer_raw(0, 0, 0, 0, 0, &[], &mut rx, 2, 700, PETAIC_XFER_READ_ONLY);
            match &result {
                Err(e2) if e2.raw_os_error() == Some(nix::libc::ETIMEDOUT) => continue,
                Err(_) => break,
                // Stale duplicate: head matches the previous accepted record.
                Ok(n) if *n >= 16 && rx[..16] == e.last_head => continue,
                Ok(_) => break,
            }
        }
        result
    };

    let n = r?;
    if n < SC_RX_OFF || rx[0] != 0x5a {
        return Err(io::Error::from_raw_os_error(nix::libc::EPROTO));
    }
    let data_len = (rx[3] as usize) | ((rx[4] as usize) << 8);
    if data_len == 0 || SC_RX_OFF + data_len > n || data_len > e.rec.len() {
        return Err(io::Error::from_raw_os_error(nix::libc::EPROTO));
    }
    e.rec[..data_len].copy_from_slice(&rx[SC_RX_OFF..SC_RX_OFF + data_len]);
    e.last_head.copy_from_slice(&rx[..16]);
    e.rec_len = data_len;
    e.rec_off = 0;
    e.rec_idx += 1;
    Ok(())
}

// ---- finger polling --------------------------------------------------------

fn poll_finger(dev: &mut PetaicDev, timeout_ms: u32) -> bool {
    let mut waited = 0u32;
    while waited < timeout_ms && !dev.slept() {
        let mut st = [0xffu8];
        if dev
            .xfer(PETAIT_CMD_POLL, PETAIT_DIR_OUT, PETAIT_ACCESS_WIDTH_32BIT, &[], &mut st, 1, 2, 10)
            .is_ok()
            && st[0] == 0x01
        {
            return true;
        }
        sleep(Duration::from_millis(40));
        waited += 40;
    }
    false
}

fn poll_finger_up(dev: &mut PetaicDev, timeout_ms: u32) -> bool {
    let mut waited = 0u32;
    while waited < timeout_ms && !dev.slept() {
        let mut st = [0xffu8];
        if dev
            .xfer(PETAIT_CMD_POLL, PETAIT_DIR_OUT, PETAIT_ACCESS_WIDTH_32BIT, &[], &mut st, 1, 2, 10)
            .is_ok()
            && st[0] == 0x00
        {
            return true;
        }
        sleep(Duration::from_millis(40));
        waited += 40;
    }
    false
}

fn request_image(dev: &mut PetaicDev) -> io::Result<()> {
    let region = [IMG_CTRL_PARAM, 0, 0, 0, 0, 0, 0];
    let mut rx = [0u8; 64];
    dev.xfer_raw(
        PETAIT_CMD_TLS_CTRL, PETAIT_DIR_IN, PETAIT_ACCESS_WIDTH_32BIT,
        PETAIT_OUTER_TYPE_STD, 0, &region, &mut rx, 1, 10, PETAIC_XFER_NO_IRQ,
    )?;
    Ok(())
}

// ---- TLS session -----------------------------------------------------------

fn build_ssl_context(
    key: [u8; 32],
    expected_identity: Option<[u8; psk::IDENTITY_LEN]>,
    verbose: bool,
) -> io::Result<SslContext> {
    let mut b = SslContextBuilder::new(SslMethod::tls_server())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    b.set_verify(SslVerifyMode::NONE);
    b.set_cipher_list("PSK-AES256-GCM-SHA384:PSK-AES128-GCM-SHA256")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    b.set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    b.set_max_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    b.set_psk_server_callback(move |_ssl, identity, psk_buf| {
        if verbose {
            // OpenSSL passes the identity as a C string: it stops at the first
            // zero byte, so an unkeyed sensor's all-zero identity shows up
            // empty. A mismatch is only logged; the Finished MAC decides.
            let id = identity.unwrap_or(&[]);
            eprintln!("[engine] sensor PSK identity [{}]: {}", id.len(), hex(id));
            if let Some(want) = &expected_identity {
                eprintln!(
                    "[engine] identity {} SHA384(key)[..32] {}",
                    if psk::cstr_identity_matches(id, want) { "==" } else { "!=" },
                    hex(want)
                );
            }
        }
        let len = 32.min(psk_buf.len());
        psk_buf[..len].copy_from_slice(&key[..len]);
        Ok(len)
    });
    Ok(b.build())
}

fn do_accept(
    ssl: Ssl,
    bio: TransportBio,
    deadline: Instant,
) -> io::Result<SslStream<TransportBio>> {
    let mut mid = match ssl.accept(bio) {
        Ok(s) => return Ok(s),
        Err(HandshakeError::WouldBlock(m)) => m,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("{e:?}"))),
    };
    for _ in 0..HANDSHAKE_MAX_WOULD_BLOCKS {
        if Instant::now() >= deadline {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        mid = match mid.handshake() {
            Ok(s) => return Ok(s),
            Err(HandshakeError::WouldBlock(m)) => m,
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("{e:?}"))),
        };
    }
    Err(io::Error::from(io::ErrorKind::TimedOut))
}

// ---- public Engine ---------------------------------------------------------

/// SIL6250 capture engine: owns the device, TLS session, and all state.
///
/// Blocking; run inside `tokio::task::spawn_blocking` for async callers.
pub struct Engine {
    // Must be declared before `shared` so it is dropped first,
    // since TransportBio holds a raw pointer into shared.
    session: Option<SslStream<TransportBio>>,
    shared: Box<EngineShared>,
    forced_key: Option<usize>,
    psk_mode: PskMode,
    // Auto mode: the sensor did not ack cmd 0x27, stop offering it.
    provision_refused: bool,
    key_id_readback: bool,
    attempts: Vec<HandshakeAttempt>,
}

// SAFETY: Engine is self-contained and used from one thread at a time.
unsafe impl Send for Engine {}

impl Engine {
    /// Open the kernel device at `devpath`. No TLS handshake yet.
    pub fn open(devpath: &str) -> io::Result<Self> {
        let dev = PetaicDev::open(devpath)?;
        Ok(Engine {
            session: None,
            shared: Box::new(EngineShared {
                dev,
                verbose: false,
                skip_prelude_20: false,
                phase: Phase::Handshake,
                rec: [0; 4096],
                rec_len: 0,
                rec_off: 0,
                rec_idx: 0,
                last_head: [0; 16],
                hs_leftover: [0; 512],
                hs_leftover_len: 0,
                hs_leftover_off: 0,
                handshake_deadline: None,
                hs_trace: Vec::new(),
                hs_trace_len: 0,
            }),
            forced_key: None,
            psk_mode: PskMode::default(),
            provision_refused: false,
            key_id_readback: false,
            attempts: Vec::new(),
        })
    }

    pub fn set_verbose(&mut self, v: bool) {
        self.shared.verbose = v;
        self.shared.dev.verbose = v;
    }

    /// With verbose on: dump whole mailbox frames, not just the first 32
    /// bytes. For diagnostic tools; far too noisy for the daemon's journal.
    pub fn set_full_dump(&mut self, v: bool) {
        self.shared.dev.dump_full = v;
    }

    /// Choose where the handshake PSK comes from (default [`PskMode::Auto`]).
    pub fn set_psk_mode(&mut self, mode: PskMode) {
        self.psk_mode = mode;
        self.provision_refused = false;
    }

    pub fn psk_mode(&self) -> PskMode {
        self.psk_mode
    }

    /// Re-read the key id (cmd 0x28) after every handshake attempt, to see
    /// whether the sensor took a provisioned key. Diagnostic only: Windows
    /// never issues this read on a live TLS session, so do not capture on a
    /// session established with this on.
    pub fn set_key_id_readback(&mut self, v: bool) {
        self.key_id_readback = v;
    }

    /// Force a specific fallback PSK by name (`"shiba"` etc.); `None` cycles
    /// all four. Applies to [`PskMode::Legacy`] and the legacy leg of `Auto`.
    pub fn set_key(&mut self, name: Option<&str>) -> io::Result<()> {
        match name {
            None => {
                self.forced_key = None;
                Ok(())
            }
            Some(n) => {
                let idx = PSK_KEYS
                    .iter()
                    .position(|k| k.name == n)
                    .ok_or_else(|| io::Error::from_raw_os_error(nix::libc::EINVAL))?;
                self.forced_key = Some(idx);
                Ok(())
            }
        }
    }

    /// Whether the system has suspended or hibernated since this engine was
    /// opened. The sensor loses its state across sleep, so every operation on
    /// this engine now fails with `ESTALE`; open a new one.
    pub fn slept(&self) -> bool {
        self.shared.dev.slept()
    }

    fn session_drop(&mut self) {
        self.session = None;
    }

    fn session_handshake(&mut self, plan: &KeyPlan, deadline: Instant) -> io::Result<()> {
        self.session = None;
        self.shared.phase = Phase::Handshake;
        self.shared.hs_leftover_len = 0;
        self.shared.hs_leftover_off = 0;
        self.shared.hs_trace.clear();
        self.shared.hs_trace_len = 0;

        let verbose = self.shared.verbose;
        if verbose {
            eprintln!(
                "[engine] handshake with key '{}'{}",
                plan.name,
                if plan.blob.is_some() { " (provisioned via cmd 0x27)" } else { "" }
            );
        }

        let mut att = HandshakeAttempt {
            key_name: plan.name,
            key: plan.key,
            provisioned: plan.blob.is_some(),
            module_info: None,
            key_id_before: None,
            set_psk_ack: None,
            set_psk_acked: false,
            turn_on_tls: None,
            key_id_after: None,
            tls: Vec::new(),
            identity: None,
            expected_identity: plan.blob.map(|_| psk::identity(&plan.key)),
            error: None,
        };

        let ctx = build_ssl_context(plan.key, att.expected_identity, verbose)?;
        let ssl = Ssl::new(&ctx).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let prelude = sc_prelude(
            &mut self.shared.dev,
            self.shared.skip_prelude_20,
            plan.blob.as_ref(),
            verbose,
            &mut att,
        );
        let res = match prelude {
            Ok(()) => {
                // SAFETY: shared is heap-allocated (Box) so the pointer is stable for
                // the lifetime of Engine. session is dropped before shared (field order).
                let ptr = unsafe { NonNull::new_unchecked(&mut *self.shared as *mut EngineShared) };
                self.shared.handshake_deadline = Some(deadline);
                let result = do_accept(ssl, TransportBio(ptr), deadline);
                self.shared.handshake_deadline = None;
                result
            }
            Err(e) => Err(e),
        };

        att.tls = std::mem::take(&mut self.shared.hs_trace);
        let from_sensor: Vec<u8> = att
            .tls
            .iter()
            .filter(|(dir, _)| *dir == TlsDir::SensorToHost)
            .flat_map(|(_, data)| data.iter().copied())
            .collect();
        att.identity = psk::client_psk_identity(&from_sensor);

        if self.key_id_readback {
            att.key_id_after = read_key_id(&mut self.shared.dev);
            if verbose {
                let id = att.key_id_after.as_deref().and_then(psk::key_id_from_response);
                eprintln!(
                    "[engine] key id readback: {}{}",
                    id.map_or("no valid response".into(), hex),
                    match (id, plan.blob) {
                        (Some(id), Some(_)) if id == psk::key_id_data(&plan.key) =>
                            " == SHA384(key)",
                        (Some(_), Some(_)) => " != SHA384(key)",
                        _ => "",
                    }
                );
            }
        }

        let res = match res {
            Ok(stream) => {
                if verbose {
                    eprintln!("[engine] *** HANDSHAKE OK ***");
                }
                self.session = Some(stream);
                Ok(())
            }
            Err(e) => {
                if verbose {
                    eprintln!("[engine] handshake with key '{}' failed: {}", plan.name, e);
                }
                att.error = Some(e.to_string());
                Err(e)
            }
        };
        self.attempts.push(att);
        res
    }

    fn legacy_handshake(&mut self, deadline: Instant) -> io::Result<()> {
        if let Some(k) = self.forced_key {
            return self.session_handshake(&KeyPlan::ring(k), deadline);
        }
        for k in 0..PSK_KEYS.len() {
            if Instant::now() >= deadline {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            if self.shared.dev.slept() {
                return Err(slept_error());
            }
            if self.session_handshake(&KeyPlan::ring(k), deadline).is_ok() {
                return Ok(());
            }
        }
        Err(io::Error::from_raw_os_error(nix::libc::EIO))
    }

    fn session_ensure(&mut self) -> io::Result<()> {
        if self.session.is_some() {
            return Ok(());
        }
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        self.attempts.clear();
        match self.psk_mode {
            PskMode::Legacy => self.legacy_handshake(deadline),
            PskMode::Provision => self.session_handshake(&KeyPlan::provision()?, deadline),
            PskMode::Replay => self.session_handshake(&KeyPlan::replay(), deadline),
            PskMode::Auto => {
                if !self.provision_refused {
                    // An RNG failure must not cost us the legacy attempt either.
                    let provisioned = match KeyPlan::provision() {
                        Ok(plan) => self.session_handshake(&plan, deadline),
                        Err(e) => Err(e),
                    };
                    if provisioned.is_ok() {
                        return Ok(());
                    }
                    // Interrupted by a suspend: says nothing about the
                    // firmware, and no key can work until the device reopens.
                    if self.shared.dev.slept() {
                        return Err(slept_error());
                    }
                    // No ack means this firmware does not take cmd 0x27 (or
                    // choked on it): don't offer it again on this engine. An
                    // acked key whose handshake then failed may just be a
                    // flaky handshake, so that is retried next time round.
                    if self.attempts.last().is_some_and(|a| !a.set_psk_acked) {
                        self.provision_refused = true;
                    }
                    if self.shared.verbose {
                        eprintln!("[engine] provisioning failed; falling back to legacy keys");
                    }
                    // Let the sensor settle; the legacy attempt then restarts
                    // from a full prelude, exactly as it did before cmd 0x27.
                    sleep(Duration::from_millis(150));
                }
                self.legacy_handshake(deadline)
            }
        }
    }

    /// Drop any session and run the prelude + TLS handshake now, without
    /// waiting for a finger. See [`Engine::handshake_attempts`] for details.
    pub fn handshake(&mut self) -> io::Result<()> {
        self.session_drop();
        self.session_ensure()
    }

    /// What happened in each attempt of the most recent (re)handshake, in
    /// order; on success the last entry is the one that completed.
    pub fn handshake_attempts(&self) -> &[HandshakeAttempt] {
        &self.attempts
    }

    /// Firmware version (cmd 0x1b), e.g. `[0, 0, 32, 15]`.
    pub fn firmware_version(&mut self) -> io::Result<[u8; 4]> {
        let mut fw = [0u8; 4];
        self.shared.dev.xfer(
            PETAIT_CMD_INIT, PETAIT_DIR_OUT, PETAIT_ACCESS_WIDTH_32BIT, &[], &mut fw, 4, 3, 10,
        )?;
        Ok(fw)
    }

    fn capture_through_session(
        &mut self,
        img: &mut [u8; IMG_SIZE],
        finger_ms: u32,
    ) -> io::Result<()> {
        self.shared.phase = Phase::Image;
        self.shared.rec_len = 0;
        self.shared.rec_off = 0;
        self.shared.rec_idx = 0;
        self.shared.last_head = [0; 16];

        if !poll_finger(&mut self.shared.dev, finger_ms) {
            return Err(io::Error::from_raw_os_error(nix::libc::ETIMEDOUT));
        }

        // Arm only after finger is confirmed down; 0x37 is one-shot.
        request_image(&mut self.shared.dev)?;
        sleep(Duration::from_millis(120));

        let mut plain = [0u8; IMG_TOTAL];
        let mut off = 0usize;
        let ssl = self.session.as_mut().unwrap();
        while off < IMG_TOTAL {
            match ssl.read(&mut plain[off..]) {
                Ok(0) => return Err(io::Error::from_raw_os_error(nix::libc::EIO)),
                Ok(n) => off += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Err(io::Error::from_raw_os_error(nix::libc::ETIMEDOUT));
                }
                Err(e) => return Err(e),
            }
        }

        let want = checksum(&plain[..IMG_SIZE]);
        let got = u32::from_le_bytes(plain[IMG_SIZE..IMG_SIZE + 4].try_into().unwrap());
        if want != got {
            if self.shared.verbose {
                eprintln!(
                    "[engine] checksum mismatch got 0x{:08x} want 0x{:08x}",
                    got, want
                );
            }
            return Err(io::Error::from_raw_os_error(nix::libc::EIO));
        }
        img.copy_from_slice(&plain[..IMG_SIZE]);
        Ok(())
    }

    /// Capture one raw 5120-byte image frame.
    ///
    /// Waits up to `finger_ms` for a finger, lazily (re)establishes the TLS
    /// session, and retries on a desynced GCM stream.
    ///
    /// Fails with `ESTALE` once the system has slept since [`Engine::open`]:
    /// the sensor has lost its state, so open a new engine.
    pub fn capture_frame(&mut self, finger_ms: u32) -> io::Result<[u8; IMG_SIZE]> {
        let mut img = [0u8; IMG_SIZE];
        for attempt in 0..CAPTURE_ATTEMPTS {
            if self.slept() {
                self.session_drop();
                return Err(slept_error());
            }
            self.session_ensure()?;
            let fm = if attempt == 0 { finger_ms } else { 3000 };
            match self.capture_through_session(&mut img, fm) {
                Ok(()) => return Ok(img),
                Err(_) if self.slept() => {
                    self.session_drop();
                    return Err(slept_error());
                }
                Err(ref e) if e.raw_os_error() == Some(nix::libc::ETIMEDOUT) && attempt == 0 => {
                    return Err(io::Error::from_raw_os_error(nix::libc::ETIMEDOUT));
                }
                Err(e) => {
                    self.session_drop();
                    if self.shared.verbose {
                        eprintln!(
                            "[engine] attempt {} failed ({}); re-handshaking",
                            attempt + 1,
                            e
                        );
                    }
                    sleep(Duration::from_millis(150));
                }
            }
        }
        Err(io::Error::from_raw_os_error(nix::libc::ETIMEDOUT))
    }

    /// Wait for the finger to lift (returns `true`) or for `timeout_ms` to elapse.
    pub fn wait_finger_up(&mut self, timeout_ms: u32) -> bool {
        poll_finger_up(&mut self.shared.dev, timeout_ms)
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    #[test]
    fn expired_handshake_budget_is_rejected() {
        let deadline = Instant::now() - Duration::from_millis(1);
        assert_eq!(
            bounded_timeout(Some(deadline), 350).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ssl::SslConnector;
    use std::os::unix::net::UnixStream;

    // Records everything the peer sends, like the handshake transcript does.
    #[derive(Debug)]
    struct Tap(UnixStream, Vec<u8>);

    impl Read for Tap {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.0.read(buf)?;
            self.1.extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }

    impl Write for Tap {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    // Play the sensor: a TLS 1.2 PSK client presenting SHA384(key)[..32].
    fn sensor(sock: UnixStream, key: [u8; 32]) -> std::thread::JoinHandle<bool> {
        std::thread::spawn(move || {
            let mut b = SslConnector::builder(SslMethod::tls_client()).unwrap();
            b.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
            b.set_cipher_list("PSK-AES256-GCM-SHA384").unwrap();
            b.set_psk_client_callback(move |_ssl, _hint, identity, psk| {
                identity[..psk::IDENTITY_LEN].copy_from_slice(&psk::identity(&key));
                identity[psk::IDENTITY_LEN] = 0;
                psk[..32].copy_from_slice(&key);
                Ok(32)
            });
            let ctx = b.build().into_context();
            Ssl::new(&ctx).unwrap().connect(sock).is_ok()
        })
    }

    #[test]
    fn provisioned_key_handshake_and_identity() {
        let (host, dev) = UnixStream::pair().unwrap();
        let client = sensor(dev, psk::WINDOWS_KEY);
        let want = psk::identity(&psk::WINDOWS_KEY);
        let ctx = build_ssl_context(psk::WINDOWS_KEY, Some(want), false).unwrap();
        let stream = Ssl::new(&ctx).unwrap().accept(Tap(host, Vec::new())).unwrap();
        assert!(client.join().unwrap());
        assert_eq!(stream.ssl().current_cipher().unwrap().name(), "PSK-AES256-GCM-SHA384");
        assert_eq!(psk::client_psk_identity(&stream.get_ref().1).as_deref(), Some(&want[..]));
    }

    #[test]
    fn wrong_key_fails_handshake() {
        let (host, dev) = UnixStream::pair().unwrap();
        let client = sensor(dev, psk::WINDOWS_KEY);
        let ctx = build_ssl_context(PSK_KEYS[0].key, None, false).unwrap();
        assert!(Ssl::new(&ctx).unwrap().accept(Tap(host, Vec::new())).is_err());
        assert!(!client.join().unwrap());
    }

    #[test]
    fn psk_mode_parse() {
        for m in [PskMode::Auto, PskMode::Provision, PskMode::Replay, PskMode::Legacy] {
            assert_eq!(m.as_str().parse::<PskMode>().unwrap(), m);
        }
        assert!("shiba".parse::<PskMode>().is_err());
        assert_eq!(PskMode::default(), PskMode::Auto);
    }
}
