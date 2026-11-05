use encryptoglyph::sign::{generate, sign, verify};
use encryptoglyph::Error;

#[test]
fn sign_verify_and_domain_separation() {
    let (sk, pk) = generate().unwrap();
    let s = sign(&sk, "audit-receipt", b"entry 1").unwrap();
    assert!(verify(&pk, "audit-receipt", b"entry 1", &s).is_ok());
    assert_eq!(verify(&pk, "export", b"entry 1", &s), Err(Error::Decrypt));
    assert_eq!(verify(&pk, "audit-receipt", b"entry 2", &s), Err(Error::Decrypt));
    let mut bad = s;
    bad[0] ^= 1;
    assert_eq!(verify(&pk, "audit-receipt", b"entry 1", &bad), Err(Error::Decrypt));
    let (_, other) = generate().unwrap();
    assert_eq!(verify(&other, "audit-receipt", b"entry 1", &s), Err(Error::Decrypt));
    assert_eq!(sign(&[0u8; 5], "x", b""), Err(Error::InvalidKey));
}

#[test]
fn deterministic() {
    let sk = [3u8; 32];
    assert_eq!(sign(&sk, "c", b"m").unwrap(), sign(&sk, "c", b"m").unwrap());
}
