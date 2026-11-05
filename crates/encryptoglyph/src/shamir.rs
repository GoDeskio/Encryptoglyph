//! Shamir M-of-N secret sharing over GF(2^8) (backlog #15). Use it to split a root or KEK across
//! custodians for break-glass recovery, with no single holder able to decrypt on their own.
//! This is not an escrow or backdoor: shares exist only where the key owner hands them out.
//!
//! Share format: `b"EGSS" | ver=1 | threshold u8 | x u8 | y[len]`.
//! Field arithmetic uses the AES polynomial 0x11b and is branch-free (no lookup tables).
use crate::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"EGSS";
const VER: u8 = 1;
const HDR: usize = 7;

fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & 0u8.wrapping_sub(b & 1);
        let hi = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & hi);
        b >>= 1;
    }
    p
}

fn inv(a: u8) -> u8 {
    // a^254 = a^-1 in GF(2^8). inv(0) = 0, which is never used.
    let mut r = 1u8;
    let mut x = a;
    for bit in 0..8 {
        if (254u8 >> bit) & 1 == 1 {
            r = mul(r, x);
        }
        x = mul(x, x);
    }
    r
}

/// Split `secret` into `n` shares, any `threshold` of which reconstruct it.
pub fn split(secret: &[u8], threshold: u8, n: u8) -> Result<Vec<Vec<u8>>, Error> {
    if secret.is_empty() || threshold < 2 || n < threshold {
        return Err(Error::InvalidArgument);
    }
    let t = threshold as usize;
    let mut coeffs = Zeroizing::new(vec![0u8; secret.len() * (t - 1)]);
    getrandom::getrandom(&mut coeffs).map_err(|_| Error::InvalidArgument)?;
    let mut shares = Vec::with_capacity(n as usize);
    for x in 1..=n {
        let mut s = Vec::with_capacity(HDR + secret.len());
        s.extend_from_slice(MAGIC);
        s.extend_from_slice(&[VER, threshold, x]);
        for (i, &b) in secret.iter().enumerate() {
            let c = &coeffs[i * (t - 1)..(i + 1) * (t - 1)];
            // Horner's method, highest coefficient first.
            let mut y = 0u8;
            for &k in c.iter().rev() {
                y = mul(y, x) ^ k;
            }
            s.push(mul(y, x) ^ b);
        }
        shares.push(s);
    }
    Ok(shares)
}

/// Recombine shares. Fails if there are fewer than the threshold, mixed lengths or thresholds,
/// duplicate x values, or bad headers. Wrong-but-well-formed shares yield wrong bytes, so verify
/// the result (for example, unwrap a key-check value) before trusting it.
pub fn combine(shares: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let first = shares.first().ok_or(Error::InvalidArgument)?;
    if first.len() <= HDR {
        return Err(Error::InvalidArgument);
    }
    let t = first[5] as usize;
    if shares.len() < t {
        return Err(Error::InvalidArgument);
    }
    let use_ = &shares[..t];
    let mut xs = Vec::with_capacity(t);
    for s in use_ {
        if s.len() != first.len() || &s[..4] != MAGIC || s[4] != VER || s[5] as usize != t || s[6] == 0 || xs.contains(&s[6]) {
            return Err(Error::InvalidArgument);
        }
        xs.push(s[6]);
    }
    let mut out = Zeroizing::new(vec![0u8; first.len() - HDR]);
    for (j, s) in use_.iter().enumerate() {
        // Lagrange basis at x = 0: prod x_m / (x_m - x_j), and subtraction is XOR.
        let mut l = 1u8;
        for (m, &xm) in xs.iter().enumerate() {
            if m != j {
                l = mul(l, mul(xm, inv(xm ^ xs[j])));
            }
        }
        for (o, &y) in out.iter_mut().zip(&s[HDR..]) {
            *o ^= mul(l, y);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn field() {
        assert_eq!(mul(0x57, 0x83), 0xc1); // FIPS-197 worked example
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1);
        }
    }
}
