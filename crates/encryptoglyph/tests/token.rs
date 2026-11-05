use encryptoglyph::ff1::Ff1;
use encryptoglyph::token::{vaultless_digits, vaultless_digits_reveal, MemoryStore, Vault};

#[test]
fn vaulted_roundtrip_and_modes() {
    let mut v = Vault::new(&[5u8; 32], MemoryStore::default()).unwrap();
    let a = v.tokenize(b"4111111111111111", false).unwrap();
    let b = v.tokenize(b"4111111111111111", false).unwrap();
    assert_ne!(a, b);
    assert!(a.starts_with("tok_") && !a.contains("4111"));
    assert_eq!(&v.detokenize(&a).unwrap()[..], b"4111111111111111");
    let d1 = v.tokenize(b"x@y.z", true).unwrap();
    assert_eq!(v.tokenize(b"x@y.z", true).unwrap(), d1);
    assert!(v.revoke(&d1));
    assert!(v.detokenize(&d1).is_err());
    assert_ne!(v.tokenize(b"x@y.z", true).unwrap(), d1);
    assert!(v.detokenize("tok_nope").is_err());
}

#[test]
fn vaultless_keeps_last4() {
    let f = Ff1::new(&[9u8; 32], 10).unwrap();
    let t = vaultless_digits(&f, b"pan", "4111111111111111", 4).unwrap();
    assert_eq!(t.len(), 16);
    assert!(t.ends_with("1111"));
    assert_ne!(&t[..12], "411111111111");
    assert_eq!(vaultless_digits_reveal(&f, b"pan", &t, 4).unwrap(), "4111111111111111");
}
