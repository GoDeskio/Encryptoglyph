//! Ed25519 signing for audit receipts, exports and shred receipts (backlog #16).
//! Signatures are domain-separated: the signed message is `"encryptoglyph/sig/v1" | len(context) u32 BE | context | msg`,
//! so a receipt signature can never be replayed as an export signature.
use crate::Error;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

const DOMAIN: &[u8] = b"encryptoglyph/sig/v1";

fn framed(context: &str, msg: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN.len() + 4 + context.len() + msg.len());
    v.extend_from_slice(DOMAIN);
    v.extend_from_slice(&(context.len() as u32).to_be_bytes());
    v.extend_from_slice(context.as_bytes());
    v.extend_from_slice(msg);
    v
}

/// Generate a fresh keypair: (secret seed 32 bytes, public key 32 bytes).
pub fn generate() -> Result<([u8; 32], [u8; 32]), Error> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| Error::InvalidArgument)?;
    let sk = SigningKey::from_bytes(&seed);
    Ok((seed, sk.verifying_key().to_bytes()))
}

pub fn sign(seed: &[u8], context: &str, msg: &[u8]) -> Result<[u8; 64], Error> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| Error::InvalidKey)?;
    Ok(SigningKey::from_bytes(&seed).sign(&framed(context, msg)).to_bytes())
}

/// Strict verification (rejects non-canonical and small-order points).
pub fn verify(public: &[u8], context: &str, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let pk: [u8; 32] = public.try_into().map_err(|_| Error::InvalidKey)?;
    let pk = VerifyingKey::from_bytes(&pk).map_err(|_| Error::InvalidKey)?;
    let sig = Signature::from_slice(sig).map_err(|_| Error::Decrypt)?;
    pk.verify_strict(&framed(context, msg), &sig).map_err(|_| Error::Decrypt)?;
    Ok(())
}
