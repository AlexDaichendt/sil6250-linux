// SPDX-License-Identifier: GPL-2.0
//! Userspace Petaic mailbox transport over /dev/sil6250.

use std::fs::{File, OpenOptions};
use std::num::NonZeroUsize;
use std::os::unix::io::AsRawFd;
use std::thread::sleep;
use std::time::Duration;

use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};

use crate::proto::{build_frame, build_frame_ex, parse_frame, PETAIT_OUTER_TYPE_STD};

// ---- ioctl definitions (sil6250_uapi.h) ------------------------------------

const SIL6250_IOCTL_MAGIC: u8 = 0x5C;
pub const SIL6250_LINE_WRITE_DONE: u32 = 0;
pub const SIL6250_LINE_READ_DONE: u32 = 1;

#[repr(C)]
struct SilGpio {
    line: u32,
    value: u32,
}

#[repr(C)]
struct SilWaitIrq {
    timeout_ms: u32,
    _pad: u32,
}

nix::ioctl_write_ptr!(sil6250_set_gpio, SIL6250_IOCTL_MAGIC, 0x01, SilGpio);
nix::ioctl_write_ptr!(sil6250_wait_irq_raw, SIL6250_IOCTL_MAGIC, 0x02, SilWaitIrq);
nix::ioctl_read!(sil6250_get_window_size, SIL6250_IOCTL_MAGIC, 0x03, u32);

// ---- constants -------------------------------------------------------------

pub const PETAIC_RX_OFFSET: usize = 0x200;
pub const PETAIC_READ_CHUNK_MAX: usize = 0xe00;
pub const PETAIC_TX_BUF_SIZE: usize = 0x200;

pub const PETAIC_XFER_READ_ONLY: u32 = 1 << 0;
pub const PETAIC_XFER_NO_IRQ: u32 = 1 << 1;

const NOTIFY_HIGH_MS: u64 = 10;
const READ_POST_MS: u64 = 20;
const WAIT_IRQ_DEFAULT_MS: u32 = 500;

// ---- device ----------------------------------------------------------------

pub struct PetaicDev {
    file: File,
    window: std::ptr::NonNull<u8>,
    pub window_size: usize,
    seq: u8,
    pub verbose: bool,
}

// SAFETY: PetaicDev is self-contained; callers ensure no concurrent access.
unsafe impl Send for PetaicDev {}

impl PetaicDev {
    pub fn open(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let fd = file.as_raw_fd();

        let sz = unsafe {
            let mut val: u32 = 0;
            sil6250_get_window_size(fd, &mut val)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
            val
        };
        if sz == 0 {
            return Err(std::io::Error::from_raw_os_error(nix::libc::EINVAL));
        }
        let size = sz as usize;

        let window = unsafe {
            mmap(
                None,
                NonZeroUsize::new(size).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &file,
                0,
            )
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?
        };
        let window = std::ptr::NonNull::new(window.as_ptr() as *mut u8)
            .ok_or_else(|| std::io::Error::from_raw_os_error(nix::libc::EINVAL))?;

        Ok(PetaicDev { file, window, window_size: size, seq: 0, verbose: false })
    }

    fn set_gpio(&self, line: u32, value: u32) -> std::io::Result<()> {
        let g = SilGpio { line, value };
        unsafe {
            sil6250_set_gpio(self.file.as_raw_fd(), &g)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        }
        Ok(())
    }

    pub fn strobe_write_done(&self) -> std::io::Result<()> {
        if self.verbose {
            eprintln!("[strobe write_done]");
        }
        self.set_gpio(SIL6250_LINE_WRITE_DONE, 1)?;
        sleep(Duration::from_millis(NOTIFY_HIGH_MS));
        self.set_gpio(SIL6250_LINE_WRITE_DONE, 0)?;
        Ok(())
    }

    pub fn strobe_read_done(&self) -> std::io::Result<()> {
        if self.verbose {
            eprintln!("[strobe read_done]");
        }
        self.set_gpio(SIL6250_LINE_READ_DONE, 1)?;
        sleep(Duration::from_millis(NOTIFY_HIGH_MS));
        self.set_gpio(SIL6250_LINE_READ_DONE, 0)?;
        sleep(Duration::from_millis(READ_POST_MS));
        Ok(())
    }

    pub fn wait_irq(&self, timeout_ms: u32) -> std::io::Result<()> {
        let w = SilWaitIrq {
            timeout_ms: if timeout_ms == 0 { WAIT_IRQ_DEFAULT_MS } else { timeout_ms },
            _pad: 0,
        };
        unsafe {
            sil6250_wait_irq_raw(self.file.as_raw_fd(), &w)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        }
        Ok(())
    }

    /// Qword-aligned write into the TX region (+0x000).
    pub fn shm_write(&self, buf: &[u8]) -> std::io::Result<()> {
        if buf.len() % 8 != 0 || buf.len() > self.window_size {
            return Err(std::io::Error::from_raw_os_error(nix::libc::EINVAL));
        }
        let dst = self.window.as_ptr() as *mut u64;
        unsafe {
            for (i, chunk) in buf.chunks_exact(8).enumerate() {
                let v = u64::from_ne_bytes(chunk.try_into().unwrap());
                dst.add(i).write_volatile(v);
            }
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    /// Qword-aligned read from the RX region (+0x200).
    pub fn shm_read(&self, buf: &mut [u8]) -> std::io::Result<()> {
        if buf.len() % 8 != 0 || PETAIC_RX_OFFSET + buf.len() > self.window_size {
            return Err(std::io::Error::from_raw_os_error(nix::libc::EINVAL));
        }
        let src = unsafe { self.window.as_ptr().add(PETAIC_RX_OFFSET) } as *const u64;
        unsafe {
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            for (i, chunk) in buf.chunks_exact_mut(8).enumerate() {
                let v = src.add(i).read_volatile();
                chunk.copy_from_slice(&v.to_ne_bytes());
            }
        }
        Ok(())
    }

    fn dead_window(rx: &[u8]) -> bool {
        rx.len() >= 8 && rx[..8].iter().all(|&b| b == 0xff)
    }

    fn dump(tag: &str, p: &[u8]) {
        let n = p.len().min(32);
        eprint!("{} [{}]:", tag, p.len());
        for b in &p[..n] {
            eprint!(" {:02x}", b);
        }
        eprintln!();
    }

    /// Standard command round-trip (cmd 0x1b/0x14/0x11 bring-up path).
    pub fn xfer(
        &mut self,
        cmd: u8,
        dir: u8,
        width: u8,
        tx_payload: &[u8],
        rx_buf: &mut [u8],
        expected_rx_len: usize,
        tries: u32,
        timeout_ms: u32,
    ) -> std::io::Result<usize> {
        if expected_rx_len > rx_buf.len() {
            return Err(std::io::Error::from_raw_os_error(nix::libc::EINVAL));
        }
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let mut tx = [0u8; PETAIC_TX_BUF_SIZE];
        let frame_len = build_frame(
            cmd, dir, width, tx_payload, expected_rx_len, seq, PETAIT_OUTER_TYPE_STD, &mut tx,
        )
        .map_err(|_| std::io::Error::from_raw_os_error(nix::libc::EINVAL))?;
        if self.verbose {
            Self::dump("TX", &tx[..frame_len]);
        }

        let mut rx = [0u8; PETAIC_READ_CHUNK_MAX];
        let tries = if tries == 0 { 1 } else { tries };
        for _ in 0..tries {
            self.shm_write(&tx[..frame_len])?;
            self.strobe_write_done()?;
            sleep(Duration::from_millis(if timeout_ms == 0 { 10 } else { timeout_ms as u64 }));
            let read_len = PETAIC_READ_CHUNK_MAX & !7;
            self.shm_read(&mut rx[..read_len])?;
            if self.verbose {
                Self::dump("RX", &rx[..48.min(read_len)]);
            }
            if Self::dead_window(&rx[..read_len]) {
                continue;
            }
            // Win-style success: OutputBuffer at offset 7
            if rx[0] == 0x5A
                && rx[1] == cmd
                && rx[2] == 0x04
                && expected_rx_len > 0
                && 7 + expected_rx_len <= read_len
            {
                self.strobe_read_done()?;
                rx_buf[..expected_rx_len].copy_from_slice(&rx[7..7 + expected_rx_len]);
                return Ok(expected_rx_len);
            }
            if let Some(f) = parse_frame(&rx[..read_len]) {
                if f.cmd == cmd && f.checksum_ok {
                    self.strobe_read_done()?;
                    let n = f.payload.len().min(rx_buf.len());
                    rx_buf[..n].copy_from_slice(&f.payload[..n]);
                    return Ok(n);
                }
            }
        }
        Err(std::io::Error::from_raw_os_error(nix::libc::ETIMEDOUT))
    }

    /// Raw secure-channel round-trip (TLS records, image bulk).
    /// Returns the number of bytes written into `rx_buf`.
    pub fn xfer_raw(
        &mut self,
        cmd: u8,
        dir: u8,
        width: u8,
        outer_type: u8,
        be32: u32,
        tx_payload: &[u8],
        rx_buf: &mut [u8],
        tries: u32,
        timeout_ms: u32,
        flags: u32,
    ) -> std::io::Result<usize> {
        let read_only = flags & PETAIC_XFER_READ_ONLY != 0;
        let read_len = (rx_buf.len().min(PETAIC_READ_CHUNK_MAX)) & !7;
        if read_len == 0 {
            return Err(std::io::Error::from_raw_os_error(nix::libc::EINVAL));
        }

        let mut tx = [0u8; PETAIC_TX_BUF_SIZE];
        let frame_len = if !read_only {
            self.seq = self.seq.wrapping_add(1);
            let seq = self.seq;
            build_frame_ex(cmd, dir, width, tx_payload, be32, 0, seq, outer_type, &mut tx)
                .map_err(|_| std::io::Error::from_raw_os_error(nix::libc::EINVAL))?
        } else {
            0
        };
        if self.verbose && !read_only {
            Self::dump("TX-RAW", &tx[..frame_len]);
        }

        let mut rx = [0u8; PETAIC_READ_CHUNK_MAX];
        let tries = if tries == 0 { 1 } else { tries };
        for _ in 0..tries {
            if read_only {
                match self.wait_irq(timeout_ms) {
                    Ok(()) => {}
                    Err(e) if e.raw_os_error() == Some(nix::libc::ETIMEDOUT) => continue,
                    Err(e) => return Err(e),
                }
                self.shm_read(&mut rx[..read_len])?;
                if Self::dead_window(&rx[..read_len]) {
                    continue;
                }
                if self.verbose {
                    Self::dump("RX-RAW(ro)", &rx[..read_len]);
                }
                self.strobe_read_done()?;
                rx_buf[..read_len].copy_from_slice(&rx[..read_len]);
                return Ok(read_len);
            }

            self.shm_write(&tx[..frame_len])?;
            self.strobe_write_done()?;

            if flags & PETAIC_XFER_NO_IRQ != 0 {
                sleep(Duration::from_millis(if timeout_ms == 0 { 10 } else { timeout_ms as u64 }));
            } else if self
                .wait_irq(if timeout_ms == 0 { WAIT_IRQ_DEFAULT_MS } else { timeout_ms })
                .is_err()
            {
                continue;
            }

            self.shm_read(&mut rx[..read_len])?;
            if Self::dead_window(&rx[..read_len]) {
                continue;
            }
            if self.verbose {
                Self::dump("RX-RAW", &rx[..read_len]);
            }
            self.strobe_read_done()?;
            rx_buf[..read_len].copy_from_slice(&rx[..read_len]);
            return Ok(read_len);
        }
        Err(std::io::Error::from_raw_os_error(nix::libc::ETIMEDOUT))
    }
}

impl Drop for PetaicDev {
    fn drop(&mut self) {
        unsafe {
            let _ = munmap(
                std::ptr::NonNull::new(self.window.as_ptr() as *mut _).unwrap(),
                self.window_size,
            );
        }
    }
}
