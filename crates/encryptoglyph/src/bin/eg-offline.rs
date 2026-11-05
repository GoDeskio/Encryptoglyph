//! eg-offline: inspect / verify / decrypt Encryptoglyph envelopes with no network or server.
//!
//!   eg-offline inspect  < blob.hex
//!   eg-offline verify  --key-file K --ctx tenant,purpose,table,record_id,field,schema < blob.hex
//!   eg-offline decrypt --key-file K --ctx ... [--min-version N] < blob.hex   (plaintext to stdout)
//!
//! The key file holds `kid:hex32` lines (one per key, last line = current). Keys are never
//! accepted on the command line, so they don't land in shell history or `ps`.
use encryptoglyph::*;
use std::io::{Read, Write};
use std::process::ExitCode;

fn hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn keyring(path: &str) -> Result<Keyring, String> {
    let txt = std::fs::read_to_string(path).map_err(|e| format!("key file: {e}"))?;
    let mut kr: Option<Keyring> = None;
    for line in txt
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (kid, h) = line.split_once(':').ok_or("key line must be kid:hex")?;
        let k = zeroize::Zeroizing::new(hex(h).ok_or("bad key hex")?);
        match kr.as_mut() {
            None => kr = Some(Keyring::new(kid, &k).map_err(|e| e.to_string())?),
            Some(r) => r.add(kid, &k, true).map_err(|e| e.to_string())?,
        }
    }
    kr.ok_or_else(|| "key file has no keys".into())
}

fn ctx(s: &str) -> Result<RecordContext, String> {
    let p: Vec<&str> = s.split(',').collect();
    if p.len() != 6 {
        return Err("--ctx needs 6 comma-separated parts".into());
    }
    Ok(RecordContext {
        tenant: p[0].into(),
        purpose: p[1].into(),
        table: p[2].into(),
        record_id: p[3].into(),
        field: p[4].into(),
        schema_version: p[5]
            .parse()
            .map_err(|_| "schema_version must be a number")?,
    })
}

fn run() -> Result<(), String> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let cmd = a.first().map(String::as_str).unwrap_or("");
    let opt = |n: &str| {
        a.iter()
            .position(|x| x == n)
            .and_then(|i| a.get(i + 1))
            .cloned()
    };
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())?;
    let blob = hex(&input).ok_or("stdin must be a hex envelope")?;
    match cmd {
        "inspect" => {
            let h = parse_header(&blob).map_err(|e| e.to_string())?;
            println!(
                "version={} alg={} kid={} nonce_len={} body_len={}",
                h.version,
                h.alg,
                h.kid,
                h.nonce.len(),
                h.body.len()
            );
            Ok(())
        }
        "verify" | "decrypt" => {
            let kr = keyring(&opt("--key-file").ok_or("--key-file required")?)?;
            let c = ctx(&opt("--ctx").ok_or("--ctx required")?)?;
            let min = opt("--min-version").map(|v| v.parse::<u8>()).transpose().map_err(|_| "bad --min-version")?.unwrap_or(1);
            let pt = decrypt(&kr, &c, &blob, min).map_err(|e| e.to_string())?;
            if cmd == "verify" {
                println!("ok");
            } else {
                std::io::stdout().write_all(&pt).map_err(|e| e.to_string())?;
            }
            Ok(())
        }
        _ => Err("usage: eg-offline inspect|verify|decrypt [--key-file F --ctx t,p,tbl,id,f,v] < blob.hex".into()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("eg-offline: {e}");
            ExitCode::FAILURE
        }
    }
}
