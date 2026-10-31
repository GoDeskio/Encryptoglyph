use encryptoglyph::stream::{decrypt_stream, encrypt_stream, HEADER_LEN};
use encryptoglyph::Error;

const K: [u8; 32] = [7u8; 32];

fn enc(pt: &[u8], chunk: u32) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt_stream(&K, b"backup:42", chunk, &mut &pt[..], &mut out).unwrap();
    out
}
fn dec(ct: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decrypt_stream(&K, b"backup:42", &mut &ct[..], &mut out).map(|_| out)
}

#[test]
fn roundtrip_sizes() {
    for len in [0usize, 1, 63, 64, 65, 128, 1000] {
        let pt: Vec<u8> = (0..len).map(|i| (i * 31) as u8).collect();
        let ct = enc(&pt, 64);
        let chunks = len.div_ceil(64).max(1); // empty input still gets one (empty, last) chunk
        assert_eq!(ct.len(), HEADER_LEN + len + 16 * chunks, "len {len}");
        assert_eq!(dec(&ct).unwrap(), pt);
    }
}

#[test]
fn random_salt_per_stream() {
    assert_ne!(enc(b"same", 64), enc(b"same", 64));
}

#[test]
fn tamper_truncate_reorder_append_fail() {
    let pt = vec![9u8; 200];
    let ct = enc(&pt, 64); // chunks: 64,64,64,8 -> each +16
    let c = 64 + 16;
    // Truncate at a chunk boundary: the new final chunk wasn't flagged last.
    assert_eq!(dec(&ct[..HEADER_LEN + 3 * c]), Err(Error::Decrypt));
    // Drop the last byte.
    assert_eq!(dec(&ct[..ct.len() - 1]), Err(Error::Decrypt));
    // Swap chunks 0 and 1.
    let mut sw = ct.clone();
    let (a, b) = (HEADER_LEN, HEADER_LEN + c);
    let tmp = sw[a..a + c].to_vec();
    sw.copy_within(b..b + c, a);
    sw[b..b + c].copy_from_slice(&tmp);
    assert_eq!(dec(&sw), Err(Error::Decrypt));
    // Append junk.
    let mut ap = ct.clone();
    ap.extend_from_slice(&[0u8; 24]);
    assert_eq!(dec(&ap), Err(Error::Decrypt));
    // Flip a header bit (chunk size or salt).
    let mut h = ct.clone();
    h[10] ^= 1;
    assert_eq!(dec(&h), Err(Error::Decrypt));
}

#[test]
fn wrong_key_or_aad_fails() {
    let ct = enc(b"hello", 64);
    let mut out = Vec::new();
    assert_eq!(decrypt_stream(&[8u8; 32], b"backup:42", &mut &ct[..], &mut out), Err(Error::Decrypt));
    assert_eq!(decrypt_stream(&K, b"backup:43", &mut &ct[..], &mut out), Err(Error::Decrypt));
    assert_eq!(encrypt_stream(&[1u8; 5], b"", 64, &mut &b""[..], &mut out), Err(Error::InvalidKey));
    assert_eq!(encrypt_stream(&K, b"", 0, &mut &b""[..], &mut out), Err(Error::InvalidArgument));
}
