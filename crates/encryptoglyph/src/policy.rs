//! Per-object access policy (ABAC), bound into the ciphertext (backlog #12).
//!
//! A sealed object is `b"EGP1" | lp(policy) | envelope`. The policy's SHA-256 is folded into the
//! record context's `field` (`<field>#pol:<hex>`), so editing the policy breaks the AEAD tag.
//! This is a guard rail for honest services. It is not crypto enforcement against a holder of
//! the root key; that is the zero-knowledge model, and no override key exists.
//!
//! Policy text (canonical, one rule per line, sorted):
//!   `all:<attr>` subject must have attr; `any:<a>|<b>` at least one;
//!   `nbf:<unix>` / `exp:<unix>` validity window.
use crate::{decrypt, encrypt, Error, Keyring, RecordContext};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Policy {
    pub all: BTreeSet<String>,
    pub any: Vec<BTreeSet<String>>,
    pub not_before: Option<u64>,
    pub expires: Option<u64>,
}

fn ok_attr(a: &str) -> bool {
    !a.is_empty() && !a.contains(['\n', '|'])
}

impl Policy {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut lines: Vec<String> = self.all.iter().map(|a| format!("all:{a}")).collect();
        lines.extend(self.any.iter().map(|g| format!("any:{}", g.iter().cloned().collect::<Vec<_>>().join("|"))));
        lines.extend(self.not_before.map(|t| format!("nbf:{t}")));
        lines.extend(self.expires.map(|t| format!("exp:{t}")));
        lines.sort();
        lines.join("\n").into_bytes()
    }

    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        let s = std::str::from_utf8(b).map_err(|_| Error::InvalidArgument)?;
        let mut p = Policy::default();
        for line in s.lines().filter(|l| !l.is_empty()) {
            let (k, v) = line.split_once(':').ok_or(Error::InvalidArgument)?;
            match k {
                "all" if ok_attr(v) => {
                    p.all.insert(v.into());
                }
                "any" => {
                    let g: BTreeSet<String> = v.split('|').map(String::from).collect();
                    if g.iter().any(|a| !ok_attr(a)) {
                        return Err(Error::InvalidArgument);
                    }
                    p.any.push(g);
                }
                "nbf" => p.not_before = Some(v.parse().map_err(|_| Error::InvalidArgument)?),
                "exp" => p.expires = Some(v.parse().map_err(|_| Error::InvalidArgument)?),
                _ => return Err(Error::InvalidArgument),
            }
        }
        Ok(p)
    }

    pub fn allows(&self, attrs: &BTreeSet<String>, now: u64) -> bool {
        self.not_before.is_none_or(|t| now >= t)
            && self.expires.is_none_or(|t| now < t)
            && self.all.is_subset(attrs)
            && self.any.iter().all(|g| !g.is_disjoint(attrs))
    }
}

fn bound(ctx: &RecordContext, pol: &[u8]) -> RecordContext {
    let h: String = Sha256::digest(pol).iter().map(|b| format!("{b:02x}")).collect();
    let mut c = ctx.clone();
    c.field = format!("{}#pol:{h}", ctx.field);
    c
}

pub fn seal(kr: &Keyring, ctx: &RecordContext, policy: &Policy, pt: &[u8]) -> Result<Vec<u8>, Error> {
    let pol = policy.to_bytes();
    let mut out = b"EGP1".to_vec();
    out.extend_from_slice(&(pol.len() as u32).to_be_bytes());
    out.extend_from_slice(&pol);
    out.extend(encrypt(kr, &bound(ctx, &pol), pt)?);
    Ok(out)
}

/// Read the policy without decrypting (for UIs and pre-checks). It is only trustworthy after `open`.
pub fn peek(blob: &[u8]) -> Result<Policy, Error> {
    let (pol, _) = split(blob)?;
    Policy::parse(pol)
}

fn split(blob: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if blob.len() < 8 || &blob[..4] != b"EGP1" {
        return Err(Error::Decrypt);
    }
    let n = u32::from_be_bytes(blob[4..8].try_into().unwrap()) as usize;
    if blob.len() < 8 + n {
        return Err(Error::Decrypt);
    }
    Ok((&blob[8..8 + n], &blob[8 + n..]))
}

/// Decrypt only if the subject's attributes satisfy the bound policy at `now` (unix seconds).
/// A denial returns `InvalidArgument`; tampering returns `Decrypt`.
pub fn open(kr: &Keyring, ctx: &RecordContext, attrs: &BTreeSet<String>, now: u64, blob: &[u8], min_version: u8) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (pol, env) = split(blob)?;
    let p = Policy::parse(pol).map_err(|_| Error::Decrypt)?;
    let pt = decrypt(kr, &bound(ctx, pol), env, min_version)?;
    if !p.allows(attrs, now) {
        return Err(Error::InvalidArgument);
    }
    Ok(pt)
}
