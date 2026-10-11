// SPDX-License-Identifier: GPL-2.0
//! Handshake diagnostic: prelude + PSK provisioning + TLS handshake, nothing
//! else. No finger needed. Stop the daemon first, then run as root:
//!
//!   systemctl stop sil6250d
//!   cargo build -p sil6250 --example hsdiag
//!   sudo target/debug/examples/hsdiag /dev/sil6250 replay 2>&1 | tee hsdiag-replay.txt
//!
//! The report goes to stdout, the raw mailbox trace to stderr.

use std::process::ExitCode;

use sil6250::{psk, Engine, HandshakeAttempt, PskMode, TlsDir};

const USAGE: &str = "\
usage: hsdiag [DEVPATH] [MODE] [options]

  DEVPATH          kernel device (default /dev/sil6250)
  MODE             auto | provision | replay | legacy (default auto)
                     provision  push a fresh random PSK (cmd 0x27), handshake with it
                     replay     push the blob captured from the Windows driver
                     legacy     no cmd 0x27; try the firmware fallback keys
                     auto       provision, then legacy if that fails (daemon default)

  --key NAME       legacy fallback key to try (shiba, saintbernard, chihuahua,
                   bordercollie); default: all four in turn
  --no-fw          skip the firmware version query (cmd 0x1b)
  --no-readback    skip the key-id re-read (cmd 0x28) after each attempt
  --quiet          no raw mailbox trace on stderr";

fn hexdump(p: &[u8]) {
    for (i, row) in p.chunks(32).enumerate() {
        let hex: Vec<String> = row.iter().map(|b| format!("{b:02x}")).collect();
        println!("    {:04x}: {}", i * 32, hex.join(" "));
    }
}

fn hex(p: &[u8]) -> String {
    p.iter().map(|b| format!("{b:02x}")).collect()
}

fn raw(label: &str, resp: &Option<Vec<u8>>) {
    match resp {
        Some(r) => {
            println!("  {label} [{} bytes, data at offset 7]:", r.len());
            hexdump(r);
        }
        None => println!("  {label}: no response"),
    }
}

fn key_id(label: &str, resp: &Option<Vec<u8>>, key: Option<&[u8; 32]>) {
    raw(label, resp);
    let Some(id) = resp.as_deref().and_then(psk::key_id_from_response) else {
        return;
    };
    let verdict = match key {
        Some(key) if id == psk::key_id_data(key) => "== SHA384(key) + 16 zero bytes",
        _ if id.iter().all(|&b| b == 0) => "all zeros (sensor not keyed)",
        Some(_) => "!= SHA384(key)",
        None => "non-zero (sensor holds a provisioned key)",
    };
    println!("    -> {verdict}");
}

// "match" / "MISMATCH" / ... for the identity the sensor presented.
fn identity_verdict(a: &HandshakeAttempt) -> &'static str {
    match (&a.identity, &a.expected_identity) {
        (None, _) => "not seen",
        (Some(id), Some(want)) if id[..] == want[..] => "match",
        (Some(_), Some(_)) => "MISMATCH",
        (Some(id), None) if id.iter().all(|&b| b == 0) => "all-zero",
        (Some(_), None) => "non-zero",
    }
}

fn print_attempt(n: usize, a: &HandshakeAttempt) {
    println!();
    println!("=== attempt {n}: key '{}' ===", a.key_name);
    if a.provisioned {
        // Printing this key gives nothing away: it was just sent to the sensor
        // over the mailbox under two fixed XORs, and this output includes that
        // frame. (The fallback ring keys are public too, see the RE notes.)
        println!("  key:               {}", hex(&a.key));
        println!("  SHA384(key):       {}", hex(&psk::key_id(&a.key)));
    }
    raw("module info (cmd 0x20)", &a.module_info);
    key_id("key id before (cmd 0x28)", &a.key_id_before, None);
    if a.provisioned {
        raw("set PSK response (cmd 0x27)", &a.set_psk_ack);
        println!("    -> {}", if a.set_psk_acked { "acked (0xaa)" } else { "NOT acked" });
    }
    raw("turn on TLS (cmd 0x22)", &a.turn_on_tls);

    println!("  TLS handshake stream ({} chunks):", a.tls.len());
    for (dir, data) in &a.tls {
        let arrow = match dir {
            TlsDir::HostToSensor => "host -> sensor",
            TlsDir::SensorToHost => "sensor -> host",
        };
        println!("   {arrow} [{}]:", data.len());
        hexdump(data);
    }

    match &a.identity {
        Some(id) => println!("  presented identity: {}", hex(id)),
        None => println!("  presented identity: (no ClientKeyExchange seen)"),
    }
    match &a.expected_identity {
        Some(id) => println!("  expected identity:  {}", hex(id)),
        None => println!("  expected identity:  n/a (fallback key; unkeyed sensors send zeros)"),
    }
    println!("  identity:           {}", identity_verdict(a));

    if a.key_id_after.is_some() {
        key_id("key id after (cmd 0x28)", &a.key_id_after, a.provisioned.then_some(&a.key));
    }
    match &a.error {
        None => println!("  handshake: OK"),
        Some(e) => println!("  handshake: FAILED: {e}"),
    }
}

fn main() -> ExitCode {
    let mut positional = Vec::new();
    let mut key = None;
    let (mut fw, mut readback, mut trace) = (true, true, true);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--key" => key = args.next(),
            "--no-fw" => fw = false,
            "--no-readback" => readback = false,
            "--quiet" => trace = false,
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ if a.starts_with('-') => {
                eprintln!("unknown option {a}\n{USAGE}");
                return ExitCode::from(2);
            }
            _ => positional.push(a),
        }
    }
    let devpath = positional.first().map_or("/dev/sil6250", |s| s.as_str());
    let mode_arg = positional.get(1).map_or("auto", |s| s.as_str());
    let Ok(mode) = mode_arg.parse::<PskMode>() else {
        eprintln!("unknown mode '{mode_arg}'\n{USAGE}");
        return ExitCode::from(2);
    };
    if positional.len() > 2 {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }

    let mut engine = match Engine::open(devpath) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("open {devpath}: {e} (is the module loaded? are you root?)");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = engine.set_key(key.as_deref()) {
        eprintln!("--key: {e}\n{USAGE}");
        return ExitCode::from(2);
    }
    engine.set_psk_mode(mode);
    engine.set_key_id_readback(readback);
    if trace {
        engine.set_verbose(true);
        engine.set_full_dump(true);
    }

    println!("sil6250 hsdiag: dev={devpath} mode={}", mode.as_str());
    if fw {
        match engine.firmware_version() {
            Ok(v) => println!(
                "firmware version (cmd 0x1b): {}.{}.{}.{} (raw {})",
                v[3], v[2], v[1], v[0], hex(&v)
            ),
            Err(e) => println!("firmware version (cmd 0x1b): no answer ({e})"),
        }
    }

    let result = engine.handshake();
    let attempts = engine.handshake_attempts();
    for (i, a) in attempts.iter().enumerate() {
        print_attempt(i + 1, a);
    }

    println!();
    match (&result, attempts.last()) {
        (Ok(()), Some(a)) => {
            println!(
                "RESULT: PASS  mode={}  key={}{}  identity={}",
                mode.as_str(),
                a.key_name,
                if a.provisioned { " (provisioned via cmd 0x27)" } else { " (firmware fallback)" },
                identity_verdict(a)
            );
            ExitCode::SUCCESS
        }
        _ => {
            let tried: Vec<String> = attempts
                .iter()
                .map(|a| {
                    let ack = if a.provisioned && !a.set_psk_acked { " [0x27 not acked]" } else { "" };
                    format!("{}{ack}", a.key_name)
                })
                .collect();
            println!(
                "RESULT: FAIL  mode={}  no handshake completed (tried: {})",
                mode.as_str(),
                tried.join(", ")
            );
            ExitCode::FAILURE
        }
    }
}
