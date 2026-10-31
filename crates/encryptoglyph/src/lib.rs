//! Encryptoglyph shared crypto core. Wire-compatible with `api/eg_crypto` (Python).
//!
//! Envelope: `b"EG" | ver u8 | alg u8 | kid_len u8 | kid | nonce | ct||tag`.
//! v3 = XChaCha20-Poly1305 + 32-byte key commitment (default; body = commitment || ct||tag).
//! v2 = XChaCha20-Poly1305 (24-byte nonce, no commitment; decrypt + upgrade). v1 = AES-256-GCM (legacy decrypt).
//! AAD = full header || canonical record context. Keys: HKDF-SHA256 per kid/purpose/tenant/alg.
//! Zero-knowledge: no escrow or override key exists here.
#![forbid(unsafe_code)]

use aes_gcm::Aes256Gcm;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[cfg(feature = "wasm")]
pub mod wasm;

pub const MAGIC: &[u8; 2] = b"EG";
pub const VERSION_LEGACY: u8 = 1;
pub const VERSION_V2: u8 = 2;
pub const VERSION_V3: u8 = 3;
pub const ALG_AES256GCM: u8 = 1;
pub const ALG_XCHACHA20POLY1305: u8 = 2;
pub const ALG_XCHACHA20POLY1305_COMMIT: u8 = 3;
pub const COMMIT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
const HKDF_SALT: &[u8] = b"encryptoglyph/hkdf-salt/v2";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Authentication failed / malformed. Deliberately non-specific.
    Decrypt,
    Downgrade,
    InvalidKey,
    InvalidArgument,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::Decrypt => "decryption failed",
            Error::Downgrade => "envelope version below minimum",
            Error::InvalidKey => "invalid key",
            Error::InvalidArgument => "invalid argument",
        })
    }
}
impl std::error::Error for Error {}

fn lp(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

#[derive(Clone, Debug)]
pub struct RecordContext {
    pub tenant: String,
    pub purpose: String,
    pub table: String,
    pub record_id: String,
    pub field: String,
    pub schema_version: u32,
}

impl RecordContext {
    pub fn aad(&self) -> Vec<u8> {
        let mut v = b"EGAAD1".to_vec();
        for p in [
            &self.tenant,
            &self.purpose,
            &self.table,
            &self.record_id,
            &self.field,
        ] {
            lp(&mut v, p.as_bytes());
        }
        lp(&mut v, self.schema_version.to_string().as_bytes());
        v
    }
}

pub struct Keyring {
    keys: BTreeMap<String, Zeroizing<[u8; KEY_LEN]>>,
    current: String,
}

impl Keyring {
    pub fn new(kid: &str, key: &[u8]) -> Result<Self, Error> {
        let mut k = Keyring {
            keys: BTreeMap::new(),
            current: String::new(),
        };
        k.add(kid, key, true)?;
        Ok(k)
    }
    pub fn generate_key() -> Result<[u8; KEY_LEN], Error> {
        let mut k = [0u8; KEY_LEN];
        getrandom::getrandom(&mut k).map_err(|_| Error::InvalidArgument)?;
        Ok(k)
    }
    pub fn add(&mut self, kid: &str, key: &[u8], make_current: bool) -> Result<(), Error> {
        if key.len() != KEY_LEN {
            return Err(Error::InvalidKey);
        }
        if kid.is_empty() || kid.len() > 255 {
            return Err(Error::InvalidArgument);
        }
        let mut a = Zeroizing::new([0u8; KEY_LEN]);
        a.copy_from_slice(key);
        self.keys.insert(kid.to_string(), a);
        if make_current {
            self.current = kid.to_string();
        }
        Ok(())
    }
    pub fn retire(&mut self, kid: &str) -> Result<(), Error> {
        if kid == self.current {
            return Err(Error::InvalidArgument);
        }
        self.keys.remove(kid);
        Ok(())
    }
    pub fn current(&self) -> &str {
        &self.current
    }

    pub fn derive(
        &self,
        kid: &str,
        purpose: &str,
        tenant: &str,
        alg: u8,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
        let root = self.keys.get(kid).ok_or(Error::Decrypt)?;
        let mut info = b"encryptoglyph/dek/v2".to_vec();
        lp(&mut info, purpose.as_bytes());
        lp(&mut info, tenant.as_bytes());
        info.push(alg);
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        Hkdf::<Sha256>::new(Some(HKDF_SALT), root.as_ref())
            .expand(&info, out.as_mut())
            .map_err(|_| Error::InvalidKey)?;
        Ok(out)
    }
}

/// Argon2id root key from a password (m=256 MiB, t=3, p=1 == libsodium MODERATE).
pub fn derive_root_key_from_password(
    password: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    derive_root_key_with_params(password, salt, 262_144, 3)
}

pub fn derive_root_key_with_params(
    password: &[u8],
    salt: &[u8],
    m_kib: u32,
    t: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    if salt.len() != 16 {
        return Err(Error::InvalidArgument);
    }
    let params =
        argon2::Params::new(m_kib, t, 1, Some(KEY_LEN)).map_err(|_| Error::InvalidArgument)?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    a.hash_password_into(password, salt, out.as_mut())
        .map_err(|_| Error::InvalidArgument)?;
    Ok(out)
}

pub struct Header<'a> {
    pub version: u8,
    pub alg: u8,
    pub kid: &'a str,
    pub nonce: &'a [u8],
    pub header: &'a [u8],
    pub body: &'a [u8],
}

fn nonce_len(alg: u8) -> Option<usize> {
    match alg {
        ALG_AES256GCM => Some(12),
        ALG_XCHACHA20POLY1305 | ALG_XCHACHA20POLY1305_COMMIT => Some(24),
        _ => None,
    }
}

pub fn parse_header(blob: &[u8]) -> Result<Header<'_>, Error> {
    if blob.len() < 5 || &blob[..2] != MAGIC {
        return Err(Error::Decrypt);
    }
    let (version, alg, klen) = (blob[2], blob[3], blob[4] as usize);
    let ok = matches!(
        (version, alg),
        (VERSION_LEGACY, ALG_AES256GCM)
            | (VERSION_V2, ALG_XCHACHA20POLY1305)
            | (VERSION_V3, ALG_XCHACHA20POLY1305_COMMIT)
    );
    if !ok {
        return Err(Error::Decrypt);
    }
    let n = nonce_len(alg).ok_or(Error::Decrypt)?;
    let off = 5 + klen;
    let extra = if alg == ALG_XCHACHA20POLY1305_COMMIT {
        COMMIT_LEN
    } else {
        0
    };
    if blob.len() < off + n + extra + 16 {
        return Err(Error::Decrypt);
    }
    let kid = std::str::from_utf8(&blob[5..off]).map_err(|_| Error::Decrypt)?;
    Ok(Header {
        version,
        alg,
        kid,
        nonce: &blob[off..off + n],
        header: &blob[..off + n],
        body: &blob[off + n..],
    })
}

fn header(version: u8, alg: u8, kid: &str, nonce: &[u8]) -> Vec<u8> {
    let mut h = MAGIC.to_vec();
    h.extend_from_slice(&[version, alg, kid.len() as u8]);
    h.extend_from_slice(kid.as_bytes());
    h.extend_from_slice(nonce);
    h
}

type KeyPair = (Zeroizing<[u8; KEY_LEN]>, Zeroizing<[u8; KEY_LEN]>);

/// v3: split the DEK into an AEAD key and a commitment key (HKDF-SHA256, salt = nonce).
fn commit_keys(dek: &[u8], nonce: &[u8]) -> Result<KeyPair, Error> {
    let hk = Hkdf::<Sha256>::new(Some(nonce), dek);
    let mut enc = Zeroizing::new([0u8; KEY_LEN]);
    let mut com = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(b"encryptoglyph/v3/enc", enc.as_mut())
        .map_err(|_| Error::InvalidKey)?;
    hk.expand(b"encryptoglyph/v3/commit", com.as_mut())
        .map_err(|_| Error::InvalidKey)?;
    Ok((enc, com))
}

fn commitment(commit_key: &[u8], aad: &[u8]) -> [u8; COMMIT_LEN] {
    let mut m =
        <Hmac<Sha256> as Mac>::new_from_slice(commit_key).expect("hmac accepts any key length");
    m.update(b"EGCMT1");
    m.update(aad);
    m.finalize().into_bytes().into()
}

/// Default writer: v3 key-committing envelope. The commitment binds key, nonce, header and
/// record context, so a ciphertext cannot be crafted to decrypt validly under two keys.
pub fn encrypt(kr: &Keyring, ctx: &RecordContext, pt: &[u8]) -> Result<Vec<u8>, Error> {
    let dek = kr.derive(
        kr.current(),
        &ctx.purpose,
        &ctx.tenant,
        ALG_XCHACHA20POLY1305_COMMIT,
    )?;
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::InvalidArgument)?;
    let mut out = header(
        VERSION_V3,
        ALG_XCHACHA20POLY1305_COMMIT,
        kr.current(),
        &nonce,
    );
    let mut aad = out.clone();
    aad.extend_from_slice(&ctx.aad());
    let (enc, com) = commit_keys(dek.as_ref(), &nonce)?;
    let ct = XChaCha20Poly1305::new(enc.as_ref().into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: pt, aad: &aad })
        .map_err(|_| Error::InvalidArgument)?;
    out.extend_from_slice(&commitment(com.as_ref(), &aad));
    out.extend_from_slice(&ct);
    Ok(out)
}

/// v2 writer (no key commitment), for tests and interop only.
pub fn encrypt_v2(kr: &Keyring, ctx: &RecordContext, pt: &[u8]) -> Result<Vec<u8>, Error> {
    let key = kr.derive(
        kr.current(),
        &ctx.purpose,
        &ctx.tenant,
        ALG_XCHACHA20POLY1305,
    )?;
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::InvalidArgument)?;
    let mut out = header(VERSION_V2, ALG_XCHACHA20POLY1305, kr.current(), &nonce);
    let mut aad = out.clone();
    aad.extend_from_slice(&ctx.aad());
    let ct = XChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: pt, aad: &aad })
        .map_err(|_| Error::InvalidArgument)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Legacy v1 writer, for tests and interop only.
pub fn encrypt_legacy_v1(kr: &Keyring, ctx: &RecordContext, pt: &[u8]) -> Result<Vec<u8>, Error> {
    let key = kr.derive(kr.current(), &ctx.purpose, &ctx.tenant, ALG_AES256GCM)?;
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::InvalidArgument)?;
    let mut out = header(VERSION_LEGACY, ALG_AES256GCM, kr.current(), &nonce);
    let mut aad = out.clone();
    aad.extend_from_slice(&ctx.aad());
    let ct = Aes256Gcm::new(key.as_ref().into())
        .encrypt(
            aes_gcm::Nonce::from_slice(&nonce),
            Payload { msg: pt, aad: &aad },
        )
        .map_err(|_| Error::InvalidArgument)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(
    kr: &Keyring,
    ctx: &RecordContext,
    blob: &[u8],
    min_version: u8,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let h = parse_header(blob)?;
    if h.version < min_version {
        return Err(Error::Downgrade);
    }
    let key = kr.derive(h.kid, &ctx.purpose, &ctx.tenant, h.alg)?;
    let mut aad = h.header.to_vec();
    aad.extend_from_slice(&ctx.aad());
    let p = Payload {
        msg: h.body,
        aad: &aad,
    };
    let r = match h.alg {
        ALG_XCHACHA20POLY1305_COMMIT => {
            let (enc, com) = commit_keys(key.as_ref(), h.nonce)?;
            let (tag, body) = h.body.split_at(COMMIT_LEN);
            if !ct_equal(tag, &commitment(com.as_ref(), &aad)) {
                return Err(Error::Decrypt);
            }
            XChaCha20Poly1305::new(enc.as_ref().into()).decrypt(
                XNonce::from_slice(h.nonce),
                Payload {
                    msg: body,
                    aad: &aad,
                },
            )
        }
        ALG_XCHACHA20POLY1305 => {
            XChaCha20Poly1305::new(key.as_ref().into()).decrypt(XNonce::from_slice(h.nonce), p)
        }
        _ => Aes256Gcm::new(key.as_ref().into()).decrypt(aes_gcm::Nonce::from_slice(h.nonce), p),
    };
    r.map(Zeroizing::new).map_err(|_| Error::Decrypt)
}

pub fn needs_rewrap(kr: &Keyring, blob: &[u8]) -> Result<bool, Error> {
    let h = parse_header(blob)?;
    Ok(h.version < VERSION_V3 || h.kid != kr.current())
}

pub fn rewrap(kr: &Keyring, ctx: &RecordContext, blob: &[u8]) -> Result<Vec<u8>, Error> {
    let pt = decrypt(kr, ctx, blob, VERSION_LEGACY)?;
    encrypt(kr, ctx, &pt)
}

pub fn ct_equal(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

pub fn blind_index(key: &[u8], tenant: &str, field: &str, value: &str, len: usize) -> Vec<u8> {
    let norm = value
        .trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    let mut msg = b"EGBI1".to_vec();
    lp(&mut msg, tenant.as_bytes());
    lp(&mut msg, field.as_bytes());
    msg.extend_from_slice(norm.as_bytes());
    m.update(&msg);
    m.finalize().into_bytes()[..len.min(32)].to_vec()
}
