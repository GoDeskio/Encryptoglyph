use encryptoglyph::policy::{open, peek, seal, Policy};
use encryptoglyph::{Error, Keyring, RecordContext};
use std::collections::BTreeSet;

fn s(v: &[&str]) -> BTreeSet<String> {
    v.iter().map(|x| x.to_string()).collect()
}
fn ctx() -> RecordContext {
    RecordContext { tenant: "t".into(), purpose: "p".into(), table: "docs".into(), record_id: "1".into(), field: "body".into(), schema_version: 1 }
}

#[test]
fn abac_allow_deny_and_tamper() {
    let kr = Keyring::new("k1", &[1u8; 32]).unwrap();
    let pol = Policy { all: s(&["role:hr"]), any: vec![s(&["region:eu", "region:us"])], not_before: Some(100), expires: Some(200) };
    let blob = seal(&kr, &ctx(), &pol, b"salary").unwrap();
    assert_eq!(peek(&blob).unwrap(), pol);
    let ok = s(&["role:hr", "region:eu"]);
    assert_eq!(&open(&kr, &ctx(), &ok, 150, &blob, 2).unwrap()[..], b"salary");
    assert_eq!(open(&kr, &ctx(), &s(&["role:hr"]), 150, &blob, 2).unwrap_err(), Error::InvalidArgument);
    assert_eq!(open(&kr, &ctx(), &ok, 99, &blob, 2).unwrap_err(), Error::InvalidArgument);
    assert_eq!(open(&kr, &ctx(), &ok, 200, &blob, 2).unwrap_err(), Error::InvalidArgument);
    // Loosen the policy text in place: same length, and the AEAD must catch it.
    let mut t = blob.clone();
    let i = t.windows(4).position(|w| w == b"exp:").unwrap();
    t[i + 4] = b'9';
    assert_eq!(open(&kr, &ctx(), &ok, 150, &t, 2).unwrap_err(), Error::Decrypt);
}

#[test]
fn parse_rejects_junk() {
    assert!(Policy::parse(b"root:yes").is_err());
    assert!(Policy::parse(b"exp:soon").is_err());
    assert!(Policy::parse(b"any:a||b").is_err());
}
