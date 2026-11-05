//! Cross-language vectors produced by the Python implementation.
use encryptoglyph::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn field<'a>(j: &'a str, k: &str) -> &'a str {
    let i = j.find(&format!("\"{k}\": \"")).unwrap() + k.len() + 5;
    &j[i..i + j[i..].find('"').unwrap()]
}

#[test]
fn python_vectors_decrypt_in_rust() {
    let j = include_str!("../../../testvectors/envelope.json");
    let kr = Keyring::new(field(j, "kid"), &hex(field(j, "key_hex"))).unwrap();
    let ctx = RecordContext {
        tenant: "tenant-a".into(),
        purpose: "field-enc".into(),
        table: "users".into(),
        record_id: "42".into(),
        field: "ssn".into(),
        schema_version: 1,
    };
    for f in ["v3_hex", "v2_hex", "v1_hex"] {
        assert_eq!(
            &decrypt(&kr, &ctx, &hex(field(j, f)), 1).unwrap()[..],
            field(j, "plaintext").as_bytes()
        );
    }
    assert_eq!(
        blind_index(
            &hex(field(j, "key_hex")),
            "tenant-a",
            "email",
            "Foo@Example.com",
            16
        ),
        hex(field(j, "blind_index_hex"))
    );
}
