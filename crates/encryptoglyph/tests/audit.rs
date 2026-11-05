use encryptoglyph::audit::*;
const K: [u8; 32] = [7u8; 32];
fn chain(n: usize) -> (Vec<AuditRecord>, [u8; 32]) {
    let mut l = AuditLog::new(&K).unwrap();
    let v = (0..n)
        .map(|i| l.append(format!("event-{i}").as_bytes()).unwrap())
        .collect();
    (v, l.head())
}
#[test]
fn valid_chain_verifies() {
    let (v, h) = chain(5);
    assert_eq!(verify_chain(&K, &v, None, Some(h)).unwrap(), h);
}
#[test]
fn edited_payload_detected() {
    let (mut v, _) = chain(5);
    v[2].payload = b"x".to_vec();
    assert_eq!(verify_chain(&K, &v, None, None), Err(AuditError::BadMac(2)));
}
#[test]
fn deletion_detected() {
    let (mut v, _) = chain(5);
    v.remove(2);
    assert_eq!(verify_chain(&K, &v, None, None), Err(AuditError::BadSeq(3)));
}
#[test]
fn reorder_detected() {
    let (mut v, _) = chain(5);
    v.swap(1, 2);
    assert!(verify_chain(&K, &v, None, None).is_err());
}
#[test]
fn truncation_detected_with_anchor() {
    let (mut v, h) = chain(5);
    v.pop();
    assert_eq!(
        verify_chain(&K, &v, None, Some(h)),
        Err(AuditError::HeadMismatch)
    );
}
#[test]
fn wrong_key_rejected() {
    let (v, _) = chain(3);
    assert_eq!(
        verify_chain(&[8u8; 32], &v, None, None),
        Err(AuditError::BadMac(0))
    );
}
#[test]
fn forged_relink_detected() {
    let (mut v, _) = chain(4);
    v[1].prev = [1u8; 32];
    assert_eq!(
        verify_chain(&K, &v, None, None),
        Err(AuditError::BrokenLink(1))
    );
}
#[test]
fn resume_continues_chain() {
    let (mut v, _) = chain(3);
    let mut l = AuditLog::resume(&K, v.last().unwrap()).unwrap();
    v.push(l.append(b"after-restart").unwrap());
    assert_eq!(
        verify_chain(&K, &v, None, Some(l.head())).unwrap(),
        l.head()
    );
}
#[test]
fn rotated_segment_verifies() {
    let (v, h) = chain(6);
    let start = (3, v[2].link());
    assert_eq!(verify_chain(&K, &v[3..], Some(start), Some(h)).unwrap(), h);
}
#[test]
fn short_key_rejected() {
    assert!(AuditLog::new(&[1u8; 16]).is_err());
}
