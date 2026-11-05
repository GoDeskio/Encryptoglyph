use encryptoglyph::audit::{verify_chain, AuditLog};
use encryptoglyph::*;
fn ctx() -> RecordContext {
    RecordContext {
        tenant: "t1".into(),
        purpose: "pii".into(),
        table: "users".into(),
        record_id: "42".into(),
        field: "ssn".into(),
        schema_version: 1,
    }
}
#[test]
fn shred_makes_old_records_unrecoverable_and_emits_receipt() {
    let mut kr = Keyring::new("k1", &[1u8; 32]).unwrap();
    let blob = encrypt(&kr, &ctx(), b"secret").unwrap();
    kr.add("k2", &[2u8; 32], true).unwrap();
    let fp = kr.fingerprint("k1").unwrap();
    let r = kr.shred("k1", 1_793_450_000).unwrap();
    assert_eq!(r.fingerprint, fp);
    assert_eq!(r.kid, "k1");
    assert!(kr.fingerprint("k1").is_none());
    assert!(decrypt(&kr, &ctx(), &blob, 1).is_err());
    let mut log = AuditLog::new(&[9u8; 32]).unwrap();
    let rec = log.append(&r.to_bytes()).unwrap();
    assert!(verify_chain(&[9u8; 32], &[rec], None, Some(log.head())).is_ok());
}
#[test]
fn cannot_shred_current_or_unknown() {
    let mut kr = Keyring::new("k1", &[1u8; 32]).unwrap();
    assert_eq!(kr.shred("k1", 0), Err(Error::InvalidArgument));
    assert_eq!(kr.shred("nope", 0), Err(Error::InvalidArgument));
}
#[test]
fn fingerprint_differs_per_key_and_is_not_the_key() {
    let mut kr = Keyring::new("a", &[1u8; 32]).unwrap();
    kr.add("b", &[2u8; 32], false).unwrap();
    let (fa, fb) = (kr.fingerprint("a").unwrap(), kr.fingerprint("b").unwrap());
    assert_ne!(fa, fb);
    assert_eq!(fa.len(), 32);
    assert_ne!(fa, "01".repeat(16));
}
