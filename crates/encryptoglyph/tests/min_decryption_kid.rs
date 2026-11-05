use encryptoglyph::*;

fn ctx() -> RecordContext {
    RecordContext {
        tenant: "t1".into(),
        purpose: "pii".into(),
        table: "users".into(),
        record_id: "1".into(),
        field: "email".into(),
        schema_version: 1,
    }
}

#[test]
fn min_decryption_kid_blocks_older_keys_reversibly() {
    let mut kr = Keyring::new("k1", &[1u8; 32]).unwrap();
    let old = encrypt(&kr, &ctx(), b"old").unwrap();
    kr.add("k2", &[2u8; 32], true).unwrap();
    let new = encrypt(&kr, &ctx(), b"new").unwrap();

    kr.set_min_decryption_kid("k2").unwrap();
    assert_eq!(kr.min_decryption_kid(), Some("k2"));
    assert!(!kr.can_decrypt("k1") && kr.can_decrypt("k2"));
    assert_eq!(
        decrypt(&kr, &ctx(), &old, VERSION_V2).unwrap_err(),
        Error::Downgrade
    );
    assert_eq!(rewrap(&kr, &ctx(), &old).unwrap_err(), Error::Downgrade);
    assert_eq!(&**decrypt(&kr, &ctx(), &new, VERSION_V2).unwrap(), b"new");

    kr.clear_min_decryption_kid();
    assert_eq!(&**decrypt(&kr, &ctx(), &old, VERSION_V2).unwrap(), b"old");
}

#[test]
fn min_decryption_kid_validation() {
    let mut kr = Keyring::new("k1", &[1u8; 32]).unwrap();
    kr.add("k2", &[2u8; 32], false).unwrap();
    assert_eq!(
        kr.set_min_decryption_kid("nope"),
        Err(Error::InvalidArgument)
    );
    // cannot be newer than the current key (would lock out new writes)
    assert_eq!(kr.set_min_decryption_kid("k2"), Err(Error::InvalidArgument));
    kr.set_min_decryption_kid("k1").unwrap();
    // the minimum kid cannot be retired while it is the floor
    kr.add("k3", &[3u8; 32], true).unwrap();
    kr.set_min_decryption_kid("k2").unwrap();
    assert_eq!(kr.retire("k2"), Err(Error::InvalidArgument));
    kr.retire("k1").unwrap();
}
