//! Published known-answer tests for the primitives the envelope is built on.
//! Expected bytes come from the RFCs, not from a previous run of this crate.
use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn hkdf_sha256_rfc5869_case_1() {
    let ikm = [0x0bu8; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let mut okm = [0u8; 42];
    Hkdf::<Sha256>::new(Some(&salt), &ikm)
        .expand(&info, &mut okm)
        .unwrap();
    assert_eq!(
        okm.as_slice(),
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").as_slice()
    );
}

#[test]
fn hmac_sha256_rfc4231_case_1() {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&[0x0bu8; 20]).unwrap();
    mac.update(b"Hi There");
    let got = mac.finalize().into_bytes();
    assert_eq!(
        got.as_slice(),
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").as_slice()
    );
}

#[test]
fn argon2id_rfc9106_section_5_3() {
    let mut params = ParamsBuilder::new();
    params
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&[0x04u8; 12]).unwrap())
        .output_len(32);
    let argon = Argon2::new_with_secret(
        &[0x03u8; 8],
        Algorithm::Argon2id,
        Version::V0x13,
        params.build().unwrap(),
    )
    .unwrap();
    let mut out = [0u8; 32];
    argon
        .hash_password_into(&[0x01u8; 32], &[0x02u8; 16], &mut out)
        .unwrap();
    assert_eq!(
        out.as_slice(),
        hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659").as_slice()
    );
}

#[test]
fn constant_time_compare_rejects_a_flipped_tag() {
    let a = [1u8; 32];
    let mut b = a;
    b[31] ^= 1;
    assert!(encryptoglyph::ct_equal(&a, &a));
    assert!(!encryptoglyph::ct_equal(&a, &b));
    assert!(!encryptoglyph::ct_equal(&a, &a[..31]));
}
