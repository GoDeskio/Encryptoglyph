use encryptoglyph::pq::{generate, unwrap, wrap, PUBLIC_LEN, SECRET_LEN};

#[test]
fn hybrid_roundtrip_and_tamper() {
    let kp = generate();
    assert_eq!(kp.public.len(), PUBLIC_LEN);
    assert_eq!(kp.secret.len(), SECRET_LEN);
    let dek = [42u8; 32];
    let w = wrap(&kp.public, &dek).unwrap();
    assert_eq!(&unwrap(&kp.secret, &w).unwrap()[..], &dek);
    assert_ne!(wrap(&kp.public, &dek).unwrap(), w);
    for i in [6usize, 40, 1100, w.len() - 1] {
        let mut t = w.clone();
        t[i] ^= 1;
        assert!(unwrap(&kp.secret, &t).is_err(), "byte {i}");
    }
    let other = generate();
    assert!(unwrap(&other.secret, &w).is_err());
    assert!(wrap(&kp.public[..10], &dek).is_err());
}
