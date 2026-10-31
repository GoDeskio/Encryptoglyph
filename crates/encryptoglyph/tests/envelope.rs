use encryptoglyph::*;

fn ctx() -> RecordContext {
    RecordContext {
        tenant: "tenant-a".into(),
        purpose: "field-enc".into(),
        table: "users".into(),
        record_id: "42".into(),
        field: "ssn".into(),
        schema_version: 1,
    }
}
fn kr() -> Keyring {
    Keyring::new("k1", &Keyring::generate_key().unwrap()).unwrap()
}

#[test]
fn roundtrip() {
    let k = kr();
    let b = encrypt(&k, &ctx(), b"secret").unwrap();
    assert_eq!(parse_header(&b).unwrap().version, VERSION_V2);
    assert_eq!(&decrypt(&k, &ctx(), &b, 1).unwrap()[..], b"secret");
}
#[test]
fn tamper_every_byte() {
    let k = kr();
    let b = encrypt(&k, &ctx(), b"secret payload").unwrap();
    for i in 0..b.len() {
        let mut t = b.clone();
        t[i] ^= 1;
        assert!(decrypt(&k, &ctx(), &t, 1).is_err(), "byte {i}");
    }
}
#[test]
fn wrong_aad() {
    let k = kr();
    let b = encrypt(&k, &ctx(), b"x").unwrap();
    let mut c = ctx();
    c.record_id = "43".into();
    assert_eq!(decrypt(&k, &c, &b, 1).unwrap_err(), Error::Decrypt);
    let mut c = ctx();
    c.tenant = "b".into();
    assert!(decrypt(&k, &c, &b, 1).is_err());
    let mut c = ctx();
    c.schema_version = 2;
    assert!(decrypt(&k, &c, &b, 1).is_err());
}
#[test]
fn legacy_and_downgrade() {
    let k = kr();
    let old = encrypt_legacy_v1(&k, &ctx(), b"legacy").unwrap();
    assert_eq!(&decrypt(&k, &ctx(), &old, 1).unwrap()[..], b"legacy");
    assert_eq!(
        decrypt(&k, &ctx(), &old, VERSION_V2).unwrap_err(),
        Error::Downgrade
    );
    assert!(needs_rewrap(&k, &old).unwrap());
    let new = rewrap(&k, &ctx(), &old).unwrap();
    assert!(!needs_rewrap(&k, &new).unwrap());
    assert_eq!(
        &decrypt(&k, &ctx(), &new, VERSION_V2).unwrap()[..],
        b"legacy"
    );
}
#[test]
fn rotation() {
    let mut k = kr();
    let old = encrypt(&k, &ctx(), b"r").unwrap();
    k.add("k2", &Keyring::generate_key().unwrap(), true)
        .unwrap();
    let new = rewrap(&k, &ctx(), &old).unwrap();
    k.retire("k1").unwrap();
    assert!(decrypt(&k, &ctx(), &old, 1).is_err());
    assert_eq!(&decrypt(&k, &ctx(), &new, 1).unwrap()[..], b"r");
    assert!(k.retire("k2").is_err());
}
#[test]
fn argon2id() {
    let a = derive_root_key_with_params(b"pw", &[7u8; 16], 8192, 1).unwrap();
    assert_eq!(
        a,
        derive_root_key_with_params(b"pw", &[7u8; 16], 8192, 1).unwrap()
    );
    assert_ne!(
        a,
        derive_root_key_with_params(b"pX", &[7u8; 16], 8192, 1).unwrap()
    );
    assert!(derive_root_key_from_password(b"pw", &[0u8; 3]).is_err());
}
#[test]
fn ct_and_blind_index() {
    assert!(ct_equal(b"a", b"a") && !ct_equal(b"a", b"b"));
    let k = [1u8; 32];
    assert_eq!(
        blind_index(&k, "t", "email", "  Foo@Example.com ", 16),
        blind_index(&k, "t", "email", "foo@example.com", 16)
    );
}
