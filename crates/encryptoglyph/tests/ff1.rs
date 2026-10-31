//! NIST SP 800-38G FF1 sample vectors (published examples).
use encryptoglyph::ff1::Ff1;

fn h(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
const D10: &str = "0123456789";
const B36: &str = "0123456789abcdefghijklmnopqrstuvwxyz";
const K128: &str = "2B7E151628AED2A6ABF7158809CF4F3C";
const K256: &str = "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94";

fn check(key: &str, radix: u32, al: &str, tweak: &str, pt: &str, ct: &str) {
    let f = Ff1::new(&h(key), radix).unwrap();
    assert_eq!(f.encrypt_str(&h(tweak), al, pt).unwrap(), ct);
    assert_eq!(f.decrypt_str(&h(tweak), al, ct).unwrap(), pt);
}

#[test]
fn nist_samples() {
    check(K128, 10, D10, "", "0123456789", "2433477484");
    check(K128, 10, D10, "39383736353433323130", "0123456789", "6124200773");
    check(K128, 36, B36, "3737373770717273373737", "0123456789abcdefghi", "a9tv40mll9kdu509eum");
    check(K256, 10, D10, "", "0123456789", "6657667009");
}

#[test]
fn rejects_bad_input() {
    let f = Ff1::new(&h(K128), 10).unwrap();
    assert!(f.encrypt_str(b"", D10, "12345").is_err()); // domain < 10^6
    assert!(f.encrypt_str(b"", D10, "12a456789").is_err());
    assert!(Ff1::new(&[0u8; 7], 10).is_err());
    assert!(Ff1::new(&h(K128), 1).is_err());
}

#[test]
fn roundtrip_card_like() {
    let f = Ff1::new(&h(K256), 10).unwrap();
    let pan = "4111111111111111";
    let c = f.encrypt_str(b"tenant:a/col:pan", D10, pan).unwrap();
    assert_eq!(c.len(), 16);
    assert_ne!(c, pan);
    assert_eq!(f.decrypt_str(b"tenant:a/col:pan", D10, &c).unwrap(), pan);
    assert_ne!(f.encrypt_str(b"tenant:b/col:pan", D10, pan).unwrap(), c);
}
