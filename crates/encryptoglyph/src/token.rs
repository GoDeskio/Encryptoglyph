//! Tokenization (backlog #8): vaulted random tokens and vaultless format-preserving tokens.
//!
//! * Vaulted: `tok_<hex>` tokens are random with no relation to the value. Values are stored
//!   XChaCha20-Poly1305 encrypted, with AAD bound to the token. Optional deterministic mode
//!   reuses a token for equal values via an HMAC fingerprint, so joins still work. A
//!   `TokenStore` backend can swap in a database later.
//! * Vaultless: FF1 over digits that keeps a clear suffix (for example the last 4 of a PAN).
use crate::ff1::Ff1;
use crate::{Error, KEY_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::Zeroizing;

pub trait TokenStore {
    fn put(&mut self, token: &str, sealed: Vec<u8>, fingerprint: Option<[u8; 32]>);
    fn get(&self, token: &str) -> Option<&[u8]>;
    fn by_fingerprint(&self, fp: &[u8; 32]) -> Option<String>;
    fn delete(&mut self, token: &str) -> bool;
}

#[derive(Default)]
pub struct MemoryStore {
    sealed: HashMap<String, Vec<u8>>,
    fps: HashMap<[u8; 32], String>,
}

impl TokenStore for MemoryStore {
    fn put(&mut self, token: &str, sealed: Vec<u8>, fp: Option<[u8; 32]>) {
        self.sealed.insert(token.to_string(), sealed);
        if let Some(f) = fp {
            self.fps.insert(f, token.to_string());
        }
    }
    fn get(&self, token: &str) -> Option<&[u8]> {
        self.sealed.get(token).map(|v| v.as_slice())
    }
    fn by_fingerprint(&self, fp: &[u8; 32]) -> Option<String> {
        self.fps.get(fp).cloned()
    }
    fn delete(&mut self, token: &str) -> bool {
        self.fps.retain(|_, t| t != token);
        self.sealed.remove(token).is_some()
    }
}

pub struct Vault<S: TokenStore> {
    aead: XChaCha20Poly1305,
    fp_key: Zeroizing<[u8; 32]>,
    store: S,
}

impl<S: TokenStore> Vault<S> {
    pub fn new(key: &[u8], store: S) -> Result<Self, Error> {
        if key.len() != KEY_LEN {
            return Err(Error::InvalidKey);
        }
        let hk = Hkdf::<Sha256>::new(Some(b"encryptoglyph/token/v1"), key);
        let mut ek = Zeroizing::new([0u8; 32]);
        let mut fk = Zeroizing::new([0u8; 32]);
        hk.expand(b"seal", &mut *ek).map_err(|_| Error::InvalidKey)?;
        hk.expand(b"fingerprint", &mut *fk).map_err(|_| Error::InvalidKey)?;
        Ok(Vault { aead: XChaCha20Poly1305::new_from_slice(&*ek).map_err(|_| Error::InvalidKey)?, fp_key: fk, store })
    }

    fn fingerprint(&self, value: &[u8]) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&*self.fp_key).expect("hmac key");
        m.update(value);
        m.finalize().into_bytes().into()
    }

    /// Tokenize. With `deterministic`, equal values get the same token.
    pub fn tokenize(&mut self, value: &[u8], deterministic: bool) -> Result<String, Error> {
        let fp = deterministic.then(|| self.fingerprint(value));
        if let Some(t) = fp.as_ref().and_then(|f| self.store.by_fingerprint(f)) {
            return Ok(t);
        }
        let mut r = [0u8; 16 + 24];
        getrandom::getrandom(&mut r).map_err(|_| Error::InvalidArgument)?;
        let token = format!("tok_{}", r[..16].iter().map(|b| format!("{b:02x}")).collect::<String>());
        let mut sealed = r[16..].to_vec();
        let ct = self
            .aead
            .encrypt(XNonce::from_slice(&r[16..]), Payload { msg: value, aad: token.as_bytes() })
            .map_err(|_| Error::InvalidArgument)?;
        sealed.extend(ct);
        self.store.put(&token, sealed, fp);
        Ok(token)
    }

    pub fn detokenize(&self, token: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        let s = self.store.get(token).ok_or(Error::Decrypt)?;
        if s.len() < 24 + 16 {
            return Err(Error::Decrypt);
        }
        self.aead
            .decrypt(XNonce::from_slice(&s[..24]), Payload { msg: &s[24..], aad: token.as_bytes() })
            .map(Zeroizing::new)
            .map_err(|_| Error::Decrypt)
    }

    /// Delete a token mapping (right-to-erasure). Returns whether it existed.
    pub fn revoke(&mut self, token: &str) -> bool {
        self.store.delete(token)
    }
}

const DIGITS: &str = "0123456789";

/// Vaultless digit token: FF1 over everything except the last `keep` digits, which stay clear.
pub fn vaultless_digits(ff1: &Ff1, tweak: &[u8], value: &str, keep: usize) -> Result<String, Error> {
    let (head, tail) = value.split_at(value.len().checked_sub(keep).ok_or(Error::InvalidArgument)?);
    let mut t = tweak.to_vec();
    t.extend_from_slice(tail.as_bytes()); // bind the clear suffix into the tweak
    Ok(ff1.encrypt_str(&t, DIGITS, head)? + tail)
}

pub fn vaultless_digits_reveal(ff1: &Ff1, tweak: &[u8], token: &str, keep: usize) -> Result<String, Error> {
    let (head, tail) = token.split_at(token.len().checked_sub(keep).ok_or(Error::InvalidArgument)?);
    let mut t = tweak.to_vec();
    t.extend_from_slice(tail.as_bytes());
    Ok(ff1.decrypt_str(&t, DIGITS, head)? + tail)
}
