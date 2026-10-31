//! Branch-key hierarchy: a KEK (from KMS/HSM/OpenBao, or local for tests) wraps per-branch
//! root keys. Only wrapped branch keys are stored; a `Keyring` is built by unwrapping them
//! through a `KekProvider`. Rotating a branch key never touches the KEK, and rotating the KEK
//! only rewraps the (small) branch-key records, not the data.
//!
//! Wrapped format: `b"EGBK" | ver=1 | kek_id_len u8 | kek_id | nonce(24) | ct||tag`,
//! AEAD = XChaCha20-Poly1305, AAD = header || len-prefixed branch kid.
use crate::{Error, Keyring, KEY_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"EGBK";
const VER: u8 = 1;

/// Source of key-encryption keys. Implement for KMS / HSM / OpenBao Transit; `LocalKek` is the
/// in-process reference implementation.
pub trait KekProvider {
    fn kek_id(&self) -> &str;
    fn wrap(&self, branch_kid: &str, key: &[u8; KEY_LEN]) -> Result<Vec<u8>, Error>;
    fn unwrap(&self, branch_kid: &str, wrapped: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, Error>;
}

pub struct LocalKek {
    id: String,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl LocalKek {
    pub fn new(id: &str, key: &[u8]) -> Result<Self, Error> {
        if key.len() != KEY_LEN {
            return Err(Error::InvalidKey);
        }
        if id.is_empty() || id.len() > 255 {
            return Err(Error::InvalidArgument);
        }
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        k.copy_from_slice(key);
        Ok(LocalKek {
            id: id.to_string(),
            key: k,
        })
    }
}

fn aad(header: &[u8], branch_kid: &str) -> Vec<u8> {
    let mut a = header.to_vec();
    a.extend_from_slice(&(branch_kid.len() as u32).to_be_bytes());
    a.extend_from_slice(branch_kid.as_bytes());
    a
}

impl KekProvider for LocalKek {
    fn kek_id(&self) -> &str {
        &self.id
    }
    fn wrap(&self, branch_kid: &str, key: &[u8; KEY_LEN]) -> Result<Vec<u8>, Error> {
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::InvalidArgument)?;
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&[VER, self.id.len() as u8]);
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&nonce);
        let a = aad(&out, branch_kid);
        let ct = XChaCha20Poly1305::new(self.key.as_ref().into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: key, aad: &a })
            .map_err(|_| Error::InvalidArgument)?;
        out.extend_from_slice(&ct);
        Ok(out)
    }
    fn unwrap(&self, branch_kid: &str, w: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
        if w.len() < 6 || &w[..4] != MAGIC || w[4] != VER {
            return Err(Error::Decrypt);
        }
        let il = w[5] as usize;
        let off = 6 + il;
        if w.len() != off + 24 + KEY_LEN + 16 || &w[6..off] != self.id.as_bytes() {
            return Err(Error::Decrypt);
        }
        let hdr = &w[..off + 24];
        let a = aad(hdr, branch_kid);
        let pt = Zeroizing::new(
            XChaCha20Poly1305::new(self.key.as_ref().into())
                .decrypt(
                    XNonce::from_slice(&w[off..off + 24]),
                    Payload {
                        msg: &w[off + 24..],
                        aad: &a,
                    },
                )
                .map_err(|_| Error::Decrypt)?,
        );
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        k.copy_from_slice(&pt);
        Ok(k)
    }
}

/// A stored branch key: its kid and the KEK-wrapped key bytes.
pub struct WrappedBranchKey {
    pub kid: String,
    pub wrapped: Vec<u8>,
}

/// Generate a fresh branch key and return only its wrapped form.
pub fn new_branch_key(kek: &dyn KekProvider, kid: &str) -> Result<WrappedBranchKey, Error> {
    let k = Zeroizing::new(Keyring::generate_key()?);
    Ok(WrappedBranchKey {
        kid: kid.to_string(),
        wrapped: kek.wrap(kid, &k)?,
    })
}

/// Build a keyring by unwrapping branch keys (oldest first). `current` must be one of them.
pub fn keyring_from_branch_keys(
    kek: &dyn KekProvider,
    keys: &[WrappedBranchKey],
    current: &str,
) -> Result<Keyring, Error> {
    let mut kr: Option<Keyring> = None;
    for b in keys {
        let k = kek.unwrap(&b.kid, &b.wrapped)?;
        match kr.as_mut() {
            None => kr = Some(Keyring::new(&b.kid, k.as_ref())?),
            Some(r) => r.add(&b.kid, k.as_ref(), false)?,
        }
    }
    let mut kr = kr.ok_or(Error::InvalidArgument)?;
    let cur = keys
        .iter()
        .find(|b| b.kid == current)
        .ok_or(Error::InvalidArgument)?;
    let k = kek.unwrap(&cur.kid, &cur.wrapped)?;
    kr.add(current, k.as_ref(), true)?;
    Ok(kr)
}

/// KEK rotation: rewrap a branch key under a new KEK without exposing it to storage.
pub fn rewrap_branch_key(
    old: &dyn KekProvider,
    new: &dyn KekProvider,
    b: &WrappedBranchKey,
) -> Result<WrappedBranchKey, Error> {
    let k = old.unwrap(&b.kid, &b.wrapped)?;
    Ok(WrappedBranchKey {
        kid: b.kid.clone(),
        wrapped: new.wrap(&b.kid, &k)?,
    })
}
