use encryptoglyph::kek::*;
use encryptoglyph::*;

fn ctx() -> RecordContext {
    RecordContext {
        tenant: "t".into(),
        purpose: "p".into(),
        table: "users".into(),
        record_id: "1".into(),
        field: "f".into(),
        schema_version: 1,
    }
}

#[test]
fn wrap_unwrap_and_build_keyring() {
    let kek = LocalKek::new("kek-1", &[7u8; 32]).unwrap();
    let b1 = new_branch_key(&kek, "b1").unwrap();
    let b2 = new_branch_key(&kek, "b2").unwrap();
    let kr = keyring_from_branch_keys(&kek, &[b1, b2], "b2").unwrap();
    assert_eq!(kr.current(), "b2");
    let blob = encrypt(&kr, &ctx(), b"hi").unwrap();
    assert_eq!(&decrypt(&kr, &ctx(), &blob, 1).unwrap()[..], b"hi");
}

#[test]
fn wrong_kek_or_swapped_kid_rejected() {
    let kek = LocalKek::new("kek-1", &[7u8; 32]).unwrap();
    let other = LocalKek::new("kek-1", &[8u8; 32]).unwrap();
    let b = new_branch_key(&kek, "b1").unwrap();
    assert_eq!(other.unwrap("b1", &b.wrapped).unwrap_err(), Error::Decrypt);
    // Binding to the branch kid: the same blob can't be relabelled as another branch.
    assert_eq!(kek.unwrap("b2", &b.wrapped).unwrap_err(), Error::Decrypt);
    let mut t = b.wrapped.clone();
    *t.last_mut().unwrap() ^= 1;
    assert!(kek.unwrap("b1", &t).is_err());
    assert!(kek.unwrap("b1", &b.wrapped[..10]).is_err());
}

#[test]
fn kek_rotation_keeps_data_readable() {
    let k1 = LocalKek::new("kek-1", &[1u8; 32]).unwrap();
    let k2 = LocalKek::new("kek-2", &[2u8; 32]).unwrap();
    let b = new_branch_key(&k1, "b1").unwrap();
    let kr = keyring_from_branch_keys(&k1, std::slice::from_ref(&b), "b1").unwrap();
    let blob = encrypt(&kr, &ctx(), b"data").unwrap();
    let b2 = rewrap_branch_key(&k1, &k2, &b).unwrap();
    assert!(k1.unwrap("b1", &b2.wrapped).is_err());
    let kr2 = keyring_from_branch_keys(&k2, &[b2], "b1").unwrap();
    assert_eq!(&decrypt(&kr2, &ctx(), &blob, 1).unwrap()[..], b"data");
}

#[test]
fn current_must_exist() {
    let kek = LocalKek::new("k", &[1u8; 32]).unwrap();
    let b = new_branch_key(&kek, "b1").unwrap();
    assert!(keyring_from_branch_keys(&kek, &[b], "nope").is_err());
    assert!(keyring_from_branch_keys(&kek, &[], "b1").is_err());
    assert!(LocalKek::new("k", &[1u8; 16]).is_err());
}
