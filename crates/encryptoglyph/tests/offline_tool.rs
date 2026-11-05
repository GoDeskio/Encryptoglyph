use std::io::Write;
use std::process::{Command, Stdio};

const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const CTX: &str = "tenant-a,field-enc,users,42,ssn,1";

fn vector(name: &str) -> String {
    let j = include_str!("../../../testvectors/envelope.json");
    let i = j.find(&format!("\"{name}\": \"")).unwrap() + name.len() + 5;
    j[i..i + j[i..].find('"').unwrap()].to_string()
}

fn run(args: &[&str], stdin: &str) -> (bool, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_eg-offline"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).into(),
        String::from_utf8_lossy(&o.stderr).into(),
    )
}

fn keyfile() -> String {
    let p = std::env::temp_dir().join(format!("eg-offline-{}.keys", std::process::id()));
    std::fs::write(&p, format!("# test\nkv1:{KEY}\n")).unwrap();
    p.to_string_lossy().into()
}

#[test]
fn inspect_needs_no_key() {
    let (ok, out, _) = run(&["inspect"], &vector("v2_hex"));
    assert!(ok);
    assert!(out.contains("version=2") && out.contains("kid=kv1"));
}

#[test]
fn verify_and_decrypt_vector() {
    let k = keyfile();
    let (ok, out, _) = run(
        &["verify", "--key-file", &k, "--ctx", CTX],
        &vector("v2_hex"),
    );
    assert!(ok && out.trim() == "ok");
    let (ok, out, _) = run(
        &["decrypt", "--key-file", &k, "--ctx", CTX],
        &vector("v1_hex"),
    );
    assert!(ok);
    assert_eq!(out, "hello encryptoglyph");
}

#[test]
fn verify_fails_closed() {
    let k = keyfile();
    let (ok, out, err) = run(
        &[
            "verify",
            "--key-file",
            &k,
            "--ctx",
            "x,field-enc,users,42,ssn,1",
        ],
        &vector("v2_hex"),
    );
    assert!(!ok && out.is_empty() && err.contains("decryption failed"));
    let (ok, _, err) = run(
        &[
            "decrypt",
            "--key-file",
            &k,
            "--ctx",
            CTX,
            "--min-version",
            "2",
        ],
        &vector("v1_hex"),
    );
    assert!(!ok && err.contains("minimum"));
    let (ok, _, _) = run(&["inspect"], "zz");
    assert!(!ok);
}
