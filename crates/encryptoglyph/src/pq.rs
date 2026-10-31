//! Hybrid post-quantum key wrap: X25519 + ML-KEM-768 (FIPS 203) (backlog #6).
//! The wrapped key stays safe while either primitive holds, which guards against
//! harvest-now-decrypt-later attacks on long-lived backups.
//!
//! Public key = x25519_pk(32) | mlkem768_ek(1184).
//! Wrap = `b"EGPQ" | ver=1 | eph_pk(32) | kem_ct(1088) | nonce(24) | XChaCha(dek)+tag`.
//! KEK = HKDF-SHA256(ikm = ss_x25519 | ss_mlkem, info = label | eph_pk | x25519_pk | kem_ct).
//! Binding every public value into the KDF follows the usual combiner pattern used by X-Wing.
use crate::Error;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;

const MAGIC: &[u8; 4] = b"EGPQ";
const X: usize = 32;
const EK: usize = 1184;
const DK: usize = 2400;
const KCT: usize = 1088;
pub const PUBLIC_LEN: usize = X + EK;
pub const SECRET_LEN: usize = X + DK;
const HDR: usize = 5 + X + KCT + 24;

pub struct HybridKeypair {
    pub public: Vec<u8>,
    pub secret: Zeroizing<Vec<u8>>,
}

pub fn generate() -> HybridKeypair {
    let xs = StaticSecret::random_from_rng(OsRng);
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    let mut public = PublicKey::from(&xs).to_bytes().to_vec();
    public.extend_from_slice(&ek.as_bytes());
    let mut secret = Zeroizing::new(xs.to_bytes().to_vec());
    secret.extend_from_slice(&dk.as_bytes());
    HybridKeypair { public, secret }
}

fn kek(ss_x: &[u8], ss_k: &[u8], eph: &[u8], xpk: &[u8], kct: &[u8]) -> Result<XChaCha20Poly1305, Error> {
    let mut ikm = Zeroizing::new(ss_x.to_vec());
    ikm.extend_from_slice(ss_k);
    let mut info = b"encryptoglyph/pq-hybrid/v1".to_vec();
    info.extend_from_slice(eph);
    info.extend_from_slice(xpk);
    info.extend_from_slice(kct);
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, &ikm).expand(&info, &mut *k).map_err(|_| Error::InvalidKey)?;
    XChaCha20Poly1305::new_from_slice(&*k).map_err(|_| Error::InvalidKey)
}

pub fn wrap(public: &[u8], dek: &[u8]) -> Result<Vec<u8>, Error> {
    if public.len() != PUBLIC_LEN || dek.is_empty() {
        return Err(Error::InvalidKey);
    }
    let xpk: [u8; 32] = public[..X].try_into().unwrap();
    let ek = Ek::from_bytes(public[X..].try_into().map_err(|_| Error::InvalidKey)?);
    let eph = StaticSecret::random_from_rng(OsRng);
    let eph_pk = PublicKey::from(&eph).to_bytes();
    let ss_x = eph.diffie_hellman(&PublicKey::from(xpk));
    if !ss_x.was_contributory() {
        return Err(Error::InvalidKey);
    }
    let (kct, ss_k) = ek.encapsulate(&mut OsRng).map_err(|_| Error::InvalidKey)?;
    let c = kek(ss_x.as_bytes(), &ss_k, &eph_pk, &xpk, &kct)?;
    let mut out = MAGIC.to_vec();
    out.push(1);
    out.extend_from_slice(&eph_pk);
    out.extend_from_slice(&kct);
    let mut n = [0u8; 24];
    getrandom::getrandom(&mut n).map_err(|_| Error::InvalidArgument)?;
    out.extend_from_slice(&n);
    let ct = c.encrypt(XNonce::from_slice(&n), Payload { msg: dek, aad: &out }).map_err(|_| Error::InvalidArgument)?;
    out.extend(ct);
    Ok(out)
}

pub fn unwrap(secret: &[u8], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if secret.len() != SECRET_LEN {
        return Err(Error::InvalidKey);
    }
    if wrapped.len() < HDR + 16 || &wrapped[..4] != MAGIC || wrapped[4] != 1 {
        return Err(Error::Decrypt);
    }
    let xs = StaticSecret::from(<[u8; 32]>::try_from(&secret[..X]).unwrap());
    let xpk = PublicKey::from(&xs).to_bytes();
    let dk = Dk::from_bytes(secret[X..].try_into().map_err(|_| Error::InvalidKey)?);
    let eph: [u8; 32] = wrapped[5..5 + X].try_into().unwrap();
    let kct_b = &wrapped[5 + X..5 + X + KCT];
    let ss_x = xs.diffie_hellman(&PublicKey::from(eph));
    if !ss_x.was_contributory() {
        return Err(Error::Decrypt);
    }
    let kct = kct_b.try_into().map_err(|_| Error::Decrypt)?;
    let ss_k = dk.decapsulate(&kct).map_err(|_| Error::Decrypt)?;
    let c = kek(ss_x.as_bytes(), &ss_k, &eph, &xpk, kct_b)?;
    c.decrypt(XNonce::from_slice(&wrapped[HDR - 24..HDR]), Payload { msg: &wrapped[HDR..], aad: &wrapped[..HDR] })
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}
