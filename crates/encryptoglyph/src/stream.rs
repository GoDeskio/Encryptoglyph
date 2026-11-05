//! Streaming AEAD for large files and backups (backlog #10).
//!
//! An independent STREAM-style construction (the Hoang, Reyhanitabar, Rogaway and Vizár online-AE
//! design that age, Tink and libsodium secretstream also use), built on XChaCha20-Poly1305.
//!
//! Header (43 bytes): `b"EGS" | ver=1 | chunk_size u32 BE | salt[16] | nonce_prefix[19]`.
//! Per-stream key = HKDF-SHA256(ikm = key, salt, info = "encryptoglyph/stream/v1").
//! Chunk i nonce = `nonce_prefix | i u32 BE | last u8` and AAD = `header | aad`.
//! The final chunk (possibly empty) is flagged, so truncation, reordering, dropping chunks and
//! appending data all fail to decrypt.
use crate::{Error, KEY_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub const STREAM_MAGIC: &[u8; 3] = b"EGS";
pub const STREAM_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 3 + 1 + 4 + 16 + 19;
pub const DEFAULT_CHUNK: u32 = 64 * 1024;
const TAG: usize = 16;
const MAX_CHUNK: u32 = 16 * 1024 * 1024;

fn cipher(key: &[u8], salt: &[u8]) -> Result<XChaCha20Poly1305, Error> {
    if key.len() != KEY_LEN {
        return Err(Error::InvalidKey);
    }
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), key)
        .expand(b"encryptoglyph/stream/v1", &mut *k)
        .map_err(|_| Error::InvalidKey)?;
    XChaCha20Poly1305::new_from_slice(&*k).map_err(|_| Error::InvalidKey)
}

fn nonce(prefix: &[u8], i: u32, last: bool) -> XNonce {
    let mut n = [0u8; 24];
    n[..19].copy_from_slice(prefix);
    n[19..23].copy_from_slice(&i.to_be_bytes());
    n[23] = last as u8;
    XNonce::from(n)
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize, Error> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::InvalidArgument),
        }
    }
    Ok(n)
}

/// Encrypt everything from `input` to `output`. Returns the number of plaintext bytes.
pub fn encrypt_stream<R: Read, W: Write>(key: &[u8], aad: &[u8], chunk: u32, input: &mut R, output: &mut W) -> Result<u64, Error> {
    if chunk == 0 || chunk > MAX_CHUNK {
        return Err(Error::InvalidArgument);
    }
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(STREAM_MAGIC);
    header.push(STREAM_VERSION);
    header.extend_from_slice(&chunk.to_be_bytes());
    let mut rnd = [0u8; 35];
    getrandom::getrandom(&mut rnd).map_err(|_| Error::InvalidArgument)?;
    header.extend_from_slice(&rnd);
    let c = cipher(key, &header[8..24])?;
    let mut ad = header.clone();
    ad.extend_from_slice(aad);
    output.write_all(&header).map_err(|_| Error::InvalidArgument)?;

    let cs = chunk as usize;
    let mut cur = Zeroizing::new(vec![0u8; cs]);
    let mut next = Zeroizing::new(vec![0u8; cs]);
    let mut n = read_full(input, &mut cur)?;
    let (mut i, mut total) = (0u32, 0u64);
    loop {
        // Look ahead one chunk to know whether this one is last.
        let m = if n == cs { read_full(input, &mut next)? } else { 0 };
        let last = m == 0;
        let ct = c
            .encrypt(&nonce(&header[24..43], i, last), Payload { msg: &cur[..n], aad: &ad })
            .map_err(|_| Error::InvalidArgument)?;
        output.write_all(&ct).map_err(|_| Error::InvalidArgument)?;
        total += n as u64;
        if last {
            return Ok(total);
        }
        i = i.checked_add(1).ok_or(Error::InvalidArgument)?;
        std::mem::swap(&mut cur, &mut next);
        n = m;
    }
}

/// Decrypt a stream. Plaintext is written only after each chunk authenticates. If this returns an
/// error, the caller must discard any output already written.
pub fn decrypt_stream<R: Read, W: Write>(key: &[u8], aad: &[u8], input: &mut R, output: &mut W) -> Result<u64, Error> {
    let mut header = [0u8; HEADER_LEN];
    if read_full(input, &mut header)? != HEADER_LEN || &header[..3] != STREAM_MAGIC || header[3] != STREAM_VERSION {
        return Err(Error::Decrypt);
    }
    let chunk = u32::from_be_bytes(header[4..8].try_into().unwrap());
    if chunk == 0 || chunk > MAX_CHUNK {
        return Err(Error::Decrypt);
    }
    let c = cipher(key, &header[8..24])?;
    let mut ad = header.to_vec();
    ad.extend_from_slice(aad);
    let full = chunk as usize + TAG;
    let mut cur = vec![0u8; full];
    let mut next = vec![0u8; full];
    let mut n = read_full(input, &mut cur)?;
    let (mut i, mut total) = (0u32, 0u64);
    loop {
        if n < TAG {
            return Err(Error::Decrypt);
        }
        let m = if n == full { read_full(input, &mut next)? } else { 0 };
        let last = m == 0;
        let pt = Zeroizing::new(
            c.decrypt(&nonce(&header[24..43], i, last), Payload { msg: &cur[..n], aad: &ad })
                .map_err(|_| Error::Decrypt)?,
        );
        output.write_all(&pt).map_err(|_| Error::InvalidArgument)?;
        total += pt.len() as u64;
        if last {
            return Ok(total);
        }
        i = i.checked_add(1).ok_or(Error::Decrypt)?;
        std::mem::swap(&mut cur, &mut next);
        n = m;
    }
}
