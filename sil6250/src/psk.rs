// SPDX-License-Identifier: GPL-2.0
//! PSK provisioning (cmd 0x27): key blob wrap/unwrap, key-id, wire helpers.
//!
//! The Windows driver never relies on the firmware's built-in fallback keys.
//! Before every handshake it pushes its own 32-byte PSK to the sensor inside a
//! 128-byte blob (cmd 0x27) and then handshakes with that key. The blob is only
//! obfuscated, not encrypted: anyone who can see the mailbox can recover the
//! key, so nothing in here is a secret worth protecting.
//!
//! Once keyed, the sensor presents PSK identity `SHA384(key)[..32]` and answers
//! cmd 0x28 with `SHA384(key)` followed by 16 zero bytes. An unkeyed sensor
//! returns all zeros for both.

use std::io;

use crate::proto::{PETAIT_CMD_KEY_ID, PETAIT_CMD_SET_PSK};

pub const PSK_LEN: usize = 32;
pub const PSK_SALT_LEN: usize = 8;
pub const PSK_BLOB_LEN: usize = 128;
/// cmd 0x28 response length.
pub const KEY_ID_LEN: usize = 64;
/// PSK identity length on the TLS wire.
pub const IDENTITY_LEN: usize = 32;

const SALT_XOR: u8 = 0x86;
const KEY_XOR: u8 = 0x39;
const KEY_OFF: usize = 0x40;

// cmd 0x27 framing. Like the TLS record writes, the 128-byte blob starts in the
// low byte of the BE32 field and the length rides in the access-width byte.
pub const SET_PSK_DIR: u8 = 0x00;
pub const SET_PSK_WIDTH: u8 = PSK_BLOB_LEN as u8;
pub const SET_PSK_OUTER: u8 = 0x8f;
const SET_PSK_PAYLOAD: usize = PSK_BLOB_LEN - 1 + 4;

const RX_OFF: usize = 7; // data window offset in raw mailbox reads
const OP_ACK: u8 = 0x06;
const ACK_OK: u8 = 0xaa;

/// The blob the Windows driver sent in the reference ETW trace. Its salt, key
/// and filler all come from MSVC `rand()` with the default seed, so every
/// Windows install sends these exact bytes on its first handshake.
pub const WINDOWS_BLOB: [u8; PSK_BLOB_LEN] = [
    0x1f, 0xaf, 0x5a, 0xa5, 0x09, 0x38, 0x25, 0x02, 0x5d, 0x67, 0xcb, 0xea, 0x96, 0x50, 0x45, 0x28,
    0x13, 0x0d, 0x89, 0x0a, 0x1c, 0xdb, 0xae, 0x32, 0x20, 0x9a, 0x50, 0xee, 0x40, 0x78, 0x36, 0xfd,
    0x12, 0x49, 0x32, 0xf6, 0x9e, 0x7d, 0x49, 0xdc, 0xad, 0x4f, 0x14, 0xf2, 0x44, 0x40, 0x66, 0xd0,
    0x6b, 0xc4, 0x30, 0xb7, 0x32, 0x3b, 0xa1, 0x22, 0xf6, 0x22, 0x91, 0x9d, 0xe1, 0x8b, 0x1f, 0xda,
    0x42, 0x8a, 0xce, 0x4c, 0x29, 0xee, 0x06, 0x7c, 0xa3, 0xbc, 0x5c, 0x81, 0x5f, 0x59, 0xd1, 0x0e,
    0x34, 0x44, 0x8a, 0xa1, 0xde, 0xe2, 0xa8, 0x49, 0xa3, 0x08, 0xca, 0x75, 0x9b, 0xee, 0x64, 0x31,
    0x83, 0xef, 0x57, 0x49, 0x61, 0xff, 0x69, 0x8f, 0x61, 0xcd, 0xd1, 0x1e, 0x9d, 0x9c, 0x16, 0x72,
    0x72, 0xe6, 0x1d, 0xf0, 0x84, 0x4f, 0x4a, 0x77, 0x02, 0xd7, 0xe8, 0x39, 0x2c, 0x53, 0xcb, 0xc9,
];

/// The PSK inside [`WINDOWS_BLOB`].
pub const WINDOWS_KEY: [u8; PSK_LEN] = [
    0x52, 0x90, 0x49, 0xf1, 0xf1, 0xbb, 0xe9, 0xeb, 0xb3, 0xa6, 0xdb, 0x3c, 0x87, 0x0c, 0x3e, 0x99,
    0x24, 0x5e, 0x0d, 0x1c, 0x06, 0xb7, 0x47, 0xde, 0xb3, 0x12, 0x4d, 0xc8, 0x43, 0xbb, 0x8b, 0xa6,
];

/// Hide `key` in `filler`: salt on the odd bytes 1..=15, key at 0x40. Every
/// other byte of `filler` is sent as-is and ignored by the sensor.
pub fn wrap(
    salt: &[u8; PSK_SALT_LEN],
    key: &[u8; PSK_LEN],
    filler: [u8; PSK_BLOB_LEN],
) -> [u8; PSK_BLOB_LEN] {
    let mut out = filler;
    for i in 0..PSK_SALT_LEN {
        out[1 + 2 * i] = salt[i] ^ SALT_XOR;
    }
    for i in 0..PSK_LEN {
        out[KEY_OFF + i] = key[i] ^ salt[i % PSK_SALT_LEN] ^ KEY_XOR;
    }
    out
}

/// Inverse of [`wrap`]: recover `(salt, key)` from a blob.
pub fn unwrap(blob: &[u8; PSK_BLOB_LEN]) -> ([u8; PSK_SALT_LEN], [u8; PSK_LEN]) {
    let mut salt = [0u8; PSK_SALT_LEN];
    for i in 0..PSK_SALT_LEN {
        salt[i] = blob[1 + 2 * i] ^ SALT_XOR;
    }
    let mut key = [0u8; PSK_LEN];
    for i in 0..PSK_LEN {
        key[i] = blob[KEY_OFF + i] ^ KEY_XOR ^ salt[i % PSK_SALT_LEN];
    }
    (salt, key)
}

/// Fresh random key in a fresh random blob (OpenSSL CSPRNG).
pub fn random_blob() -> io::Result<([u8; PSK_LEN], [u8; PSK_BLOB_LEN])> {
    let mut key = [0u8; PSK_LEN];
    let mut salt = [0u8; PSK_SALT_LEN];
    let mut filler = [0u8; PSK_BLOB_LEN];
    for buf in [&mut key[..], &mut salt[..], &mut filler[..]] {
        openssl::rand::rand_bytes(buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    }
    Ok((key, wrap(&salt, &key, filler)))
}

/// `SHA384(key)`: what a keyed sensor reports as its key id.
pub fn key_id(key: &[u8; PSK_LEN]) -> [u8; 48] {
    openssl::sha::sha384(key)
}

/// The PSK identity a sensor keyed with `key` presents: `SHA384(key)[..32]`.
pub fn identity(key: &[u8; PSK_LEN]) -> [u8; IDENTITY_LEN] {
    let mut id = [0u8; IDENTITY_LEN];
    id.copy_from_slice(&key_id(key)[..IDENTITY_LEN]);
    id
}

/// The cmd 0x28 data a sensor keyed with `key` returns: key id + 16 zeros.
pub fn key_id_data(key: &[u8; PSK_LEN]) -> [u8; KEY_ID_LEN] {
    let mut out = [0u8; KEY_ID_LEN];
    out[..48].copy_from_slice(&key_id(key));
    out
}

/// `(be32, payload)` arguments that make `xfer_raw` emit the cmd 0x27 frame.
pub fn set_psk_args(blob: &[u8; PSK_BLOB_LEN]) -> (u32, [u8; SET_PSK_PAYLOAD]) {
    let mut payload = [0u8; SET_PSK_PAYLOAD];
    payload[..PSK_BLOB_LEN - 1].copy_from_slice(&blob[1..]);
    (blob[0] as u32, payload)
}

/// True if a raw mailbox read is the sensor's "key accepted" answer to 0x27.
pub fn is_set_psk_ack(rx: &[u8]) -> bool {
    rx.len() > RX_OFF
        && rx[0] == 0x5a
        && rx[1] == PETAIT_CMD_SET_PSK
        && rx[2] == OP_ACK
        && rx[RX_OFF] == ACK_OK
}

/// The 64 data bytes of a raw cmd 0x28 mailbox read.
pub fn key_id_from_response(rx: &[u8]) -> Option<&[u8]> {
    if rx.len() < RX_OFF + KEY_ID_LEN || rx[0] != 0x5a || rx[1] != PETAIT_CMD_KEY_ID {
        return None;
    }
    Some(&rx[RX_OFF..RX_OFF + KEY_ID_LEN])
}

/// Compare the identity OpenSSL hands the PSK callback against the expected
/// one. OpenSSL treats the identity as a C string, so one containing a zero
/// byte arrives cut short; only the surviving prefix can be compared there.
pub fn cstr_identity_matches(seen: &[u8], expected: &[u8; IDENTITY_LEN]) -> bool {
    let n = expected.iter().position(|&b| b == 0).unwrap_or(IDENTITY_LEN);
    seen == &expected[..n]
}

/// Pull the PSK identity out of the sensor's side of a TLS 1.2 handshake
/// (`stream` = the concatenated sensor→host bytes): the ClientKeyExchange
/// body, untouched by the C-string truncation of the PSK callback.
pub fn client_psk_identity(stream: &[u8]) -> Option<Vec<u8>> {
    // Reassemble the plaintext handshake messages (everything before CCS).
    let mut hs = Vec::new();
    let mut p = stream;
    while p.len() >= 5 {
        let len = ((p[3] as usize) << 8) | p[4] as usize;
        if p[0] != 0x16 || p.len() < 5 + len {
            break;
        }
        hs.extend_from_slice(&p[5..5 + len]);
        p = &p[5 + len..];
    }
    let mut m = &hs[..];
    while m.len() >= 4 {
        let len = ((m[1] as usize) << 16) | ((m[2] as usize) << 8) | m[3] as usize;
        if m.len() < 4 + len {
            break;
        }
        let body = &m[4..4 + len];
        if m[0] == 0x10 {
            // ClientKeyExchange, plain PSK: opaque psk_identity<0..2^16-1>
            if body.len() < 2 {
                return None;
            }
            let id_len = ((body[0] as usize) << 8) | body[1] as usize;
            return body.get(2..2 + id_len).map(|id| id.to_vec());
        }
        m = &m[4 + len..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::build_frame_ex;

    // cmd 0x27 as sent by the Windows driver (ETW trace), sequence byte 0x0a.
    const TRACE_FRAME: [u8; 152] = [
        0xf0, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x5a, 0x27, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x1f, 0xaf, 0x5a, 0xa5, 0x09, 0x38, 0x25, 0x02, 0x5d, 0x67, 0xcb, 0xea, 0x96, 0x50, 0x45,
        0x28, 0x13, 0x0d, 0x89, 0x0a, 0x1c, 0xdb, 0xae, 0x32, 0x20, 0x9a, 0x50, 0xee, 0x40, 0x78,
        0x36, 0xfd, 0x12, 0x49, 0x32, 0xf6, 0x9e, 0x7d, 0x49, 0xdc, 0xad, 0x4f, 0x14, 0xf2, 0x44,
        0x40, 0x66, 0xd0, 0x6b, 0xc4, 0x30, 0xb7, 0x32, 0x3b, 0xa1, 0x22, 0xf6, 0x22, 0x91, 0x9d,
        0xe1, 0x8b, 0x1f, 0xda, 0x42, 0x8a, 0xce, 0x4c, 0x29, 0xee, 0x06, 0x7c, 0xa3, 0xbc, 0x5c,
        0x81, 0x5f, 0x59, 0xd1, 0x0e, 0x34, 0x44, 0x8a, 0xa1, 0xde, 0xe2, 0xa8, 0x49, 0xa3, 0x08,
        0xca, 0x75, 0x9b, 0xee, 0x64, 0x31, 0x83, 0xef, 0x57, 0x49, 0x61, 0xff, 0x69, 0x8f, 0x61,
        0xcd, 0xd1, 0x1e, 0x9d, 0x9c, 0x16, 0x72, 0x72, 0xe6, 0x1d, 0xf0, 0x84, 0x4f, 0x4a, 0x77,
        0x02, 0xd7, 0xe8, 0x39, 0x2c, 0x53, 0xcb, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x24, 0xc3, 0xff,
        0xff, 0x00,
    ];
    const TRACE_SALT: [u8; PSK_SALT_LEN] = [0x29, 0x23, 0xbe, 0x84, 0xe1, 0x6c, 0xd6, 0xae];
    const TRACE_KEY_ID: [u8; 48] = [
        0x5b, 0x74, 0xa3, 0x21, 0x87, 0x3a, 0xaf, 0x6e, 0x02, 0xbb, 0x14, 0x4c, 0x47, 0x07, 0xfe,
        0x8d, 0xb7, 0x44, 0xdb, 0xdc, 0x6b, 0x38, 0x62, 0xbf, 0x28, 0xe4, 0xf2, 0x9f, 0xa3, 0xbc,
        0xe6, 0x83, 0x9e, 0xc9, 0xba, 0x85, 0x5f, 0x7e, 0x98, 0xb9, 0xf3, 0x51, 0x23, 0x14, 0x98,
        0x65, 0x78, 0x68,
    ];

    #[test]
    fn windows_blob_is_the_trace_blob() {
        assert_eq!(WINDOWS_BLOB[..], TRACE_FRAME[15..15 + PSK_BLOB_LEN]);
    }

    #[test]
    fn unwrap_trace_blob() {
        let (salt, key) = unwrap(&WINDOWS_BLOB);
        assert_eq!(salt, TRACE_SALT);
        assert_eq!(key, WINDOWS_KEY);
    }

    #[test]
    fn wrap_places_salt_and_key() {
        // Same filler as the trace: the whole blob must come back.
        assert_eq!(wrap(&TRACE_SALT, &WINDOWS_KEY, WINDOWS_BLOB), WINDOWS_BLOB);

        // Different filler: only the salt and key bytes are touched.
        let blob = wrap(&TRACE_SALT, &WINDOWS_KEY, [0xee; PSK_BLOB_LEN]);
        for (i, &b) in blob.iter().enumerate() {
            let fixed = (i < 16 && i % 2 == 1) || (KEY_OFF..KEY_OFF + PSK_LEN).contains(&i);
            assert_eq!(b, if fixed { WINDOWS_BLOB[i] } else { 0xee }, "byte {i}");
        }
        assert_eq!(unwrap(&blob), (TRACE_SALT, WINDOWS_KEY));
    }

    #[test]
    fn random_blob_round_trips() {
        let (key, blob) = random_blob().unwrap();
        let (key2, blob2) = random_blob().unwrap();
        assert_eq!(unwrap(&blob).1, key);
        assert_eq!(unwrap(&blob2).1, key2);
        assert_ne!(key, key2);
        assert_ne!(blob, blob2);
    }

    #[test]
    fn key_id_matches_trace() {
        assert_eq!(key_id(&WINDOWS_KEY), TRACE_KEY_ID);
        assert_eq!(identity(&WINDOWS_KEY)[..], TRACE_KEY_ID[..32]);
        let data = key_id_data(&WINDOWS_KEY);
        assert_eq!(data[..48], TRACE_KEY_ID);
        assert_eq!(data[48..], [0u8; 16]);
    }

    #[test]
    fn set_psk_frame_matches_trace() {
        // Exactly what PetaicDev::xfer_raw does with these arguments.
        let (be32, payload) = set_psk_args(&WINDOWS_BLOB);
        let mut tx = [0u8; 0x200];
        let n = build_frame_ex(
            PETAIT_CMD_SET_PSK, SET_PSK_DIR, SET_PSK_WIDTH, &payload, be32, 0, 0x0a,
            SET_PSK_OUTER, &mut tx,
        )
        .unwrap();
        assert_eq!(n, TRACE_FRAME.len());
        assert_eq!(tx[..n], TRACE_FRAME);
    }

    #[test]
    fn set_psk_ack() {
        let ack = [
            0x5a, 0x27, 0x06, 0x01, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00, 0x00, 0xcd, 0xfe,
            0xff, 0xff,
        ];
        assert!(is_set_psk_ack(&ack));
        let mut bad = ack;
        bad[7] = 0x55;
        assert!(!is_set_psk_ack(&bad));
        let mut bad = ack;
        bad[1] = 0x28; // stale answer to the previous command
        assert!(!is_set_psk_ack(&bad));
        let mut bad = ack;
        bad[2] = 0x04;
        assert!(!is_set_psk_ack(&bad));
        assert!(!is_set_psk_ack(&ack[..7]));
        assert!(!is_set_psk_ack(&[0xff; 16]));
    }

    #[test]
    fn key_id_response() {
        let mut rx = [0u8; 80];
        rx[..4].copy_from_slice(&[0x5a, 0x28, 0x04, 0x40]);
        assert_eq!(key_id_from_response(&rx), Some(&[0u8; KEY_ID_LEN][..]));
        rx[7..71].copy_from_slice(&key_id_data(&WINDOWS_KEY));
        assert_eq!(key_id_from_response(&rx), Some(&key_id_data(&WINDOWS_KEY)[..]));
        rx[1] = 0x20;
        assert_eq!(key_id_from_response(&rx), None);
    }

    #[test]
    fn cstr_identity() {
        let id = identity(&WINDOWS_KEY);
        assert!(cstr_identity_matches(&id, &id));
        assert!(!cstr_identity_matches(&[], &id));
        // An unkeyed sensor's all-zero identity reaches the callback empty.
        assert!(cstr_identity_matches(&[], &[0u8; IDENTITY_LEN]));
        let mut with_nul = id;
        with_nul[5] = 0;
        assert!(cstr_identity_matches(&with_nul[..5], &with_nul));
        assert!(!cstr_identity_matches(&with_nul[..4], &with_nul));
    }

    fn record(ty: u8, body: &[u8]) -> Vec<u8> {
        let mut r = vec![ty, 3, 3, (body.len() >> 8) as u8, body.len() as u8];
        r.extend_from_slice(body);
        r
    }

    #[test]
    fn identity_from_client_key_exchange() {
        let id = identity(&WINDOWS_KEY);
        let hello = [0x01, 0x00, 0x00, 0x03, 0x03, 0x03, 0x00];
        let mut cke = vec![0x10, 0x00, 0x00, 0x22, 0x00, 0x20];
        cke.extend_from_slice(&id);

        let mut stream = record(0x16, &hello);
        stream.extend(record(0x16, &cke));
        stream.extend(record(0x14, &[0x01]));
        stream.extend(record(0x16, &[0x10; 40])); // encrypted Finished
        assert_eq!(client_psk_identity(&stream).as_deref(), Some(&id[..]));

        // Both messages in one record.
        let both = [&hello[..], &cke[..]].concat();
        assert_eq!(client_psk_identity(&record(0x16, &both)).as_deref(), Some(&id[..]));

        // ClientHello only (sensor went quiet), or a truncated record.
        assert_eq!(client_psk_identity(&record(0x16, &hello)), None);
        let cut = record(0x16, &cke);
        assert_eq!(client_psk_identity(&cut[..cut.len() - 1]), None);
        assert_eq!(client_psk_identity(&[]), None);
    }
}
