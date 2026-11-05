use encryptoglyph::secrets::{RotationHook, SecretStore};
use encryptoglyph::Keyring;
use std::sync::{Arc, Mutex};

struct Rec(Arc<Mutex<Vec<String>>>);
impl RotationHook for Rec {
    fn rotated(&mut self, t: &str, n: &str, v: u32) {
        self.0.lock().unwrap().push(format!("{t}/{n}@{v}"));
    }
}

#[test]
fn versions_rotation_destroy() {
    let kr = Keyring::new("k1", &[2u8; 32]).unwrap();
    let mut s = SecretStore::new(&kr, "acme");
    let log = Arc::new(Mutex::new(vec![]));
    s.on_rotate(Box::new(Rec(log.clone())));
    assert_eq!(s.put("DB_PASSWORD", b"one", 10).unwrap(), 1);
    assert_eq!(s.put("DB_PASSWORD", b"two", 20).unwrap(), 2);
    assert_eq!(&s.get("DB_PASSWORD", None).unwrap()[..], b"two");
    assert_eq!(&s.get("DB_PASSWORD", Some(1)).unwrap()[..], b"one");
    assert_eq!(*log.lock().unwrap(), vec!["acme/DB_PASSWORD@1", "acme/DB_PASSWORD@2"]);
    assert!(s.destroy("DB_PASSWORD", 2));
    assert!(!s.destroy("DB_PASSWORD", 2));
    assert_eq!(&s.get("DB_PASSWORD", None).unwrap()[..], b"one");
    assert!(s.get("DB_PASSWORD", Some(2)).is_err());
    assert!(s.versions("DB_PASSWORD")[1].destroyed);
    assert!(s.put("bad name", b"x", 0).is_err());
    assert!(s.get("DB_PASSWORD", Some(0)).is_err());
    // Version ciphertexts aren't interchangeable.
    let v1 = s.sealed("DB_PASSWORD", 1).unwrap().to_vec();
    s.put("OTHER", b"z", 30).unwrap();
    let ctx_other = encryptoglyph::RecordContext { tenant: "acme".into(), purpose: "secret".into(), table: "secrets".into(), record_id: "OTHER".into(), field: "v1".into(), schema_version: 1 };
    assert!(encryptoglyph::decrypt(&kr, &ctx_other, &v1, 2).is_err());
}
