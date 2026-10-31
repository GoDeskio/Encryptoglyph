//! Typed searchable indexes over encrypted columns.
//!
//! * Equality: HMAC-SHA256 over a **typed, canonical** encoding, so `"1"` (text) and `1`
//!   (integer) never collide, and integers, dates, and booleans normalise deterministically.
//! * Range: bucketed tokens. A value maps to `floor(v / width)`; a query `[lo, hi]` expands
//!   to the bucket tokens that cover it (capped), and the app filters the decrypted candidates.
//!
//! Leakage (documented, by design): equality tokens reveal equal values within a
//! tenant+field; range tokens reveal bucket membership (not order inside a bucket). Pick
//! `width` per column. Tokens are scoped per tenant+field via the HMAC message.
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum IndexValue<'a> {
    Text(&'a str),
    Int(i64),
    Bool(bool),
    /// Days since 1970-01-01 (UTC).
    Date(i32),
}

fn canon(v: &IndexValue<'_>) -> Vec<u8> {
    match v {
        IndexValue::Text(s) => {
            let n = s
                .trim()
                .to_lowercase()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let mut o = vec![b'T'];
            o.extend_from_slice(n.as_bytes());
            o
        }
        IndexValue::Int(i) => [&b"I"[..], &i.to_be_bytes()].concat(),
        IndexValue::Bool(b) => vec![b'B', *b as u8],
        IndexValue::Date(d) => [&b"D"[..], &d.to_be_bytes()].concat(),
    }
}

fn mac(key: &[u8], label: &[u8], tenant: &str, field: &str, body: &[u8], len: usize) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(label);
    for p in [tenant.as_bytes(), field.as_bytes()] {
        m.update(&(p.len() as u32).to_be_bytes());
        m.update(p);
    }
    m.update(body);
    m.finalize().into_bytes()[..len.clamp(8, 32)].to_vec()
}

/// Typed equality token (8..=32 bytes).
pub fn eq_token(key: &[u8], tenant: &str, field: &str, v: &IndexValue<'_>, len: usize) -> Vec<u8> {
    mac(key, b"EGEQ1", tenant, field, &canon(v), len)
}

fn bucket(v: i64, width: u64) -> Result<i64, Error> {
    if width == 0 || width > i64::MAX as u64 {
        return Err(Error::InvalidArgument);
    }
    Ok(v.div_euclid(width as i64))
}

fn bucket_token(key: &[u8], tenant: &str, field: &str, b: i64, width: u64) -> Vec<u8> {
    let body = [width.to_be_bytes(), b.to_be_bytes()].concat();
    mac(key, b"EGRG1", tenant, field, &body, 16)
}

/// Token stored with a row for range queries on an integer-like value (ints, dates, cents).
pub fn range_token(
    key: &[u8],
    tenant: &str,
    field: &str,
    v: i64,
    width: u64,
) -> Result<Vec<u8>, Error> {
    Ok(bucket_token(key, tenant, field, bucket(v, width)?, width))
}

/// Tokens covering `[lo, hi]`. Errors if the query spans more than `max_buckets`.
pub fn range_query_tokens(
    key: &[u8],
    tenant: &str,
    field: &str,
    lo: i64,
    hi: i64,
    width: u64,
    max_buckets: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    if lo > hi {
        return Err(Error::InvalidArgument);
    }
    let (a, b) = (bucket(lo, width)?, bucket(hi, width)?);
    let n = (b as i128 - a as i128 + 1) as u128;
    if n > max_buckets as u128 {
        return Err(Error::InvalidArgument);
    }
    Ok((a..=b)
        .map(|x| bucket_token(key, tenant, field, x, width))
        .collect())
}
