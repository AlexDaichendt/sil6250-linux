// SPDX-License-Identifier: GPL-2.0
//! SIL6250 TLS-PSK capture engine.

use std::io::{self, Read, Write};
use std::ptr::NonNull;
use std::thread::sleep;
use std::time::{Duration, Instant};

use openssl::ssl::{HandshakeError, Ssl, SslContext, SslContextBuilder, SslMethod, SslStream,
                   SslVerifyMode, SslVersion};

use crate::proto::{
    checksum, PETAIT_ACCESS_WIDTH_32BIT, PETAIT_CMD_POLL, PETAIT_CMD_TLS_CTRL,
    PETAIT_CMD_TLS_DATA, PETAIT_DIR_IN, PETAIT_DIR_OUT, PETAIT_OUTER_TYPE_STD,
};
use crate::transport::{
    PetaicDev, PETAIC_READ_CHUNK_MAX, PETAIC_XFER_NO_IRQ, PETAIC_XFER_READ_ONLY,
};

// ---- PSK keys --------------------------------------------------------------

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
    session_key: usize,
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

fn sc_prelude(dev: &mut PetaicDev, skip_20: bool) -> io::Result<()> {
    let tx = [0u8; 11];
    let mut rx = [0u8; 256];
    if !skip_20 {
        let _ = dev.xfer_raw(0x20, 0x01, 0x04, 0x13, 128, &tx[..7], &mut rx, 0, 0, 0);
    }
    let reg01: &[u8] = &[0x01, 0x08, 0xff, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let _ = dev.xfer_raw(0x01, 0x00, 0x08, 0x17, 0x08, reg01, &mut rx, 0, 0, 0);
    let _ = dev.xfer_raw(0x28, 0x01, 0x04, 0x13, 64, &tx[..7], &mut rx, 0, 0, 0);
    let _ = dev.xfer_raw(0x22, 0x01, 0x04, 0x13, 1, &tx[..7], &mut rx, 0, 0, 0);
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
    while waited < timeout_ms {
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
    while waited < timeout_ms {
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

fn build_ssl_context(key: [u8; 32]) -> io::Result<SslContext> {
    let mut b = SslContextBuilder::new(SslMethod::tls_server())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    b.set_verify(SslVerifyMode::NONE);
    b.set_cipher_list("PSK-AES256-GCM-SHA384:PSK-AES128-GCM-SHA256")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    b.set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    b.set_max_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    b.set_psk_server_callback(move |_ssl, _identity, psk_buf| {
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
                session_key: 0,
            }),
            forced_key: None,
        })
    }

    pub fn set_verbose(&mut self, v: bool) {
        self.shared.verbose = v;
        self.shared.dev.verbose = v;
    }

    /// Force a specific PSK by name (`"shiba"` etc.); `None` cycles all four.
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

    fn session_drop(&mut self) {
        self.session = None;
    }

    fn session_handshake(&mut self, key_idx: usize, deadline: Instant) -> io::Result<()> {
        self.session = None;
        self.shared.session_key = key_idx;
        self.shared.phase = Phase::Handshake;
        self.shared.hs_leftover_len = 0;
        self.shared.hs_leftover_off = 0;

        if self.shared.verbose {
            eprintln!("[engine] handshake with key '{}'", PSK_KEYS[key_idx].name);
        }

        let key = PSK_KEYS[key_idx].key;
        let ctx = build_ssl_context(key)?;
        let ssl = Ssl::new(&ctx).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        sc_prelude(&mut self.shared.dev, self.shared.skip_prelude_20)?;
        self.shared.handshake_deadline = Some(deadline);

        // SAFETY: shared is heap-allocated (Box) so the pointer is stable for the
        // lifetime of Engine. session is dropped before shared (field order).
        let ptr = unsafe { NonNull::new_unchecked(&mut *self.shared as *mut EngineShared) };
        let result = do_accept(ssl, TransportBio(ptr), deadline);
        self.shared.handshake_deadline = None;
        let stream = result?;

        if self.shared.verbose {
            eprintln!("[engine] *** HANDSHAKE OK ***");
        }
        self.session = Some(stream);
        Ok(())
    }

    fn session_ensure(&mut self) -> io::Result<()> {
        if self.session.is_some() {
            return Ok(());
        }
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        if let Some(k) = self.forced_key {
            return self.session_handshake(k, deadline);
        }
        for k in 0..PSK_KEYS.len() {
            if Instant::now() >= deadline {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            if self.session_handshake(k, deadline).is_ok() {
                return Ok(());
            }
        }
        Err(io::Error::from_raw_os_error(nix::libc::EIO))
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
    pub fn capture_frame(&mut self, finger_ms: u32) -> io::Result<[u8; IMG_SIZE]> {
        let mut img = [0u8; IMG_SIZE];
        for attempt in 0..CAPTURE_ATTEMPTS {
            self.session_ensure()?;
            let fm = if attempt == 0 { finger_ms } else { 3000 };
            match self.capture_through_session(&mut img, fm) {
                Ok(()) => return Ok(img),
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
