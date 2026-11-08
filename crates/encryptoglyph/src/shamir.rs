//! Shamir threshold sharing via the `blahaj` crate (GF(256), zeroizing shares).
//! `blahaj` is the maintained fix for the coefficient-bias bug in `sharks` 0.5
//! (RUSTSEC-2024-0398).
//! Use it to split a root or KEK across custodians. Shares exist only where the
//! key owner hands them out. This is not an escrow key and not a backdoor.
//!
//! Share format: `b"EGSS" | ver=1 | threshold u8 | sharks share bytes`.
//! Wrong-but-well-formed shares are rejected by the library when they are
//! duplicate or short. A substituted share can still interpolate to other
//! bytes, so verify a key-check value before trusting the result.
use crate::Error;
use blahaj::{Share, Sharks};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"EGSS";
const VER: u8 = 1;
const HDR: usize = 6;

/// Split `secret` into `n` shares, any `threshold` of which reconstruct it.
pub fn split(secret: &[u8], threshold: u8, n: u8) -> Result<Vec<Vec<u8>>, Error> {
    if secret.is_empty() || threshold < 2 || n < threshold {
        return Err(Error::InvalidArgument);
    }
    let dealer = Sharks(threshold);
    let shares: Vec<Share> = dealer.dealer(secret).take(usize::from(n)).collect();
    if shares.len() != usize::from(n) {
        return Err(Error::InvalidArgument);
    }
    let mut out = Vec::with_capacity(shares.len());
    for share in &shares {
        let body = Vec::from(share);
        let mut framed = Vec::with_capacity(HDR + body.len());
        framed.extend_from_slice(MAGIC);
        framed.extend_from_slice(&[VER, threshold]);
        framed.extend(body);
        out.push(framed);
    }
    Ok(out)
}

/// Recombine shares. Fails closed on a short set, mixed lengths, mixed
/// thresholds, duplicate x values, or a bad header.
pub fn combine(shares: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let first = shares.first().copied().ok_or(Error::InvalidArgument)?;
    if first.len() < HDR + 2 || first[..4] != *MAGIC || first[4] != VER {
        return Err(Error::InvalidArgument);
    }
    let threshold = first[5];
    if threshold < 2 || shares.len() < usize::from(threshold) {
        return Err(Error::InvalidArgument);
    }
    let used = &shares[..usize::from(threshold)];
    let mut parsed = Vec::with_capacity(used.len());
    for share in used {
        if share.len() != first.len() || share[..HDR] != first[..HDR] {
            return Err(Error::InvalidArgument);
        }
        parsed.push(Share::try_from(&share[HDR..]).map_err(|_| Error::InvalidArgument)?);
    }
    let secret = Sharks(threshold)
        .recover(&parsed)
        .map_err(|_| Error::InvalidArgument)?;
    Ok(Zeroizing::new(secret))
}
