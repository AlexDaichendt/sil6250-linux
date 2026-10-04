// SPDX-License-Identifier: GPL-2.0
//! Petaic/SIL6250 mailbox frame builder and parser.

pub const PETAIT_CMD_BULK: u8 = 0x00;
pub const PETAIT_CMD_POLL: u8 = 0x11;
pub const PETAIT_CMD_GET_SENSOR_INFO: u8 = 0x14;
pub const PETAIT_CMD_INIT: u8 = 0x1b;
pub const PETAIT_CMD_READ_STREAM: u8 = 0x22;
pub const PETAIT_CMD_TLS_CTRL: u8 = 0x37;
pub const PETAIT_CMD_TLS_DATA: u8 = 0x38;

pub const PETAIT_ACCESS_WIDTH_32BIT: u8 = 0x04;
pub const PETAIT_ACCESS_WIDTH_TLS: u8 = 0x05;

pub const PETAIT_DIR_IN: u8 = 0x00;
pub const PETAIT_DIR_OUT: u8 = 0x01;
pub const PETAIT_DIR_WRITE: u8 = 0x02;
pub const PETAIT_DIR_READ: u8 = 0x04;

pub const PETAIT_OUTER_TYPE_STD: u8 = 0x13;
pub const PETAIT_OUTER_TYPE_SHORT: u8 = 0x10;
pub const PETAIT_OUTER_TYPE_TLS: u8 = 0x14;

pub const PETAIT_STD_PAYLOAD_REGION: usize = 7;

const INNER_MAGIC: u8 = 0x5A;
const INNER_HEADER: usize = 8;
const OUTER_HEADER: usize = 8;
const CHECKSUM_SIZE: usize = 4;

/// Parsed frame returned by [`parse_frame`].
pub struct PetaicFrame<'a> {
    pub cmd: u8,
    pub dir: u8,
    pub access_width: u8,
    pub declared_len: u32,
    pub payload: &'a [u8],
    pub checksum_ok: bool,
}

/// Ones-complement folded-16 sum, inverted; stored LE32 on the wire.
pub fn checksum(buf: &[u8]) -> u32 {
    let mut sum: u32 = buf.iter().map(|&b| b as u32).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum
}

/// Build a frame into `out`; returns the 8-byte-aligned frame length.
pub fn build_frame_ex(
    cmd: u8,
    dir: u8,
    access_width: u8,
    payload: &[u8],
    be32_field: u32,
    min_region: usize,
    seq: u8,
    outer_type: u8,
    out: &mut [u8],
) -> Result<usize, ()> {
    let region_len = payload.len().max(min_region);
    let inner_len = INNER_HEADER
        .checked_add(region_len)
        .and_then(|n| n.checked_add(CHECKSUM_SIZE))
        .ok_or(())?;
    let frame_len = OUTER_HEADER.checked_add(inner_len).ok_or(())?;
    let padded_len = frame_len.checked_add(7).ok_or(())? & !7;
    if padded_len > out.len() {
        return Err(());
    }

    out[..padded_len].fill(0);

    // outer header
    out[0] = 0xF0;
    out[1] = outer_type;
    out[7] = seq;

    // inner header
    let inner = &mut out[OUTER_HEADER..];
    inner[0] = INNER_MAGIC;
    inner[1] = cmd;
    inner[2] = dir;
    inner[3] = access_width;
    inner[4..8].copy_from_slice(&be32_field.to_be_bytes());

    if !payload.is_empty() {
        inner[INNER_HEADER..INNER_HEADER + payload.len()].copy_from_slice(payload);
    }

    // checksum over inner header + full (zero-padded) region
    let ck = checksum(&inner[..INNER_HEADER + region_len]);
    let ck_off = INNER_HEADER + region_len;
    inner[ck_off..ck_off + 4].copy_from_slice(&ck.to_le_bytes());

    Ok(padded_len)
}

/// Convenience: standard command frame (BE32 = out_length, 7-byte payload region).
pub fn build_frame(
    cmd: u8,
    dir: u8,
    access_width: u8,
    payload: &[u8],
    out_length: usize,
    seq: u8,
    outer_type: u8,
    out: &mut [u8],
) -> Result<usize, ()> {
    build_frame_ex(
        cmd,
        dir,
        access_width,
        payload,
        out_length as u32,
        PETAIT_STD_PAYLOAD_REGION,
        seq,
        outer_type,
        out,
    )
}

/// Parse a response frame (handles both 0x5A-direct and 0xF0-wrapped).
pub fn parse_frame(buf: &[u8]) -> Option<PetaicFrame<'_>> {
    if buf.len() < INNER_HEADER + CHECKSUM_SIZE {
        return None;
    }
    let inner = if buf[0] == INNER_MAGIC {
        buf
    } else if buf[0] == 0xF0 && buf.len() >= OUTER_HEADER + INNER_HEADER + CHECKSUM_SIZE {
        &buf[OUTER_HEADER..]
    } else {
        return None;
    };
    parse_inner(inner)
}

fn try_parse_inner<'a>(inner: &'a [u8], payload_len: usize) -> Option<PetaicFrame<'a>> {
    if inner.len() < INNER_HEADER + payload_len + CHECKSUM_SIZE {
        return None;
    }
    let ck_stored =
        u32::from_le_bytes(inner[INNER_HEADER + payload_len..INNER_HEADER + payload_len + 4].try_into().unwrap());
    let ck_calc = checksum(&inner[..INNER_HEADER + payload_len]);
    if ck_stored != ck_calc {
        return None;
    }
    Some(PetaicFrame {
        cmd: inner[1],
        dir: inner[2],
        access_width: inner[3],
        declared_len: u32::from_be_bytes(inner[4..8].try_into().unwrap()),
        payload: &inner[INNER_HEADER..INNER_HEADER + payload_len],
        checksum_ok: true,
    })
}

fn parse_inner(inner: &[u8]) -> Option<PetaicFrame<'_>> {
    if inner[0] != INNER_MAGIC {
        return None;
    }
    // Try declared length first
    let declared = u32::from_be_bytes(inner[4..8].try_into().unwrap()) as usize;
    if declared <= 0x1000 {
        if let Some(f) = try_parse_inner(inner, declared) {
            return Some(f);
        }
    }
    // Fall back to known candidate lengths
    static CANDIDATES: &[usize] = &[0, 1, 2, 4, 8, 12, 16, 20, 24, 32, 48, 64, 128, 256];
    for &len in CANDIDATES {
        if len == declared {
            continue;
        }
        if let Some(f) = try_parse_inner(inner, len) {
            return Some(f);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_and_checksum_rejection() {
        let mut out = [0u8; 128];
        let n = build_frame_ex(
            0x14,
            PETAIT_DIR_OUT,
            PETAIT_ACCESS_WIDTH_32BIT,
            &[1, 2, 3],
            3,
            0,
            7,
            PETAIT_OUTER_TYPE_STD,
            &mut out,
        )
        .unwrap();
        let parsed = parse_frame(&out[..n]).unwrap();
        assert_eq!(parsed.cmd, 0x14);
        assert_eq!(&parsed.payload[..3], &[1, 2, 3]);

        out[OUTER_HEADER + INNER_HEADER] ^= 1;
        assert!(parse_frame(&out[..n]).is_none());
    }

    #[test]
    fn parser_never_panics_on_arbitrary_short_inputs() {
        let mut seed = 0x9e37_79b9_u32;
        for len in 0..=4096 {
            let mut input = vec![0u8; len];
            for byte in &mut input {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                *byte = seed as u8;
            }
            let _ = parse_frame(&input);
        }
    }
}
