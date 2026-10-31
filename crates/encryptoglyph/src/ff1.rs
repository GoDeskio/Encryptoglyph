//! FF1 format-preserving encryption (NIST SP 800-38G), written from the spec (backlog #9).
//! Encrypts a digit string into another string of the same length and radix, for example a
//! card number or SSN in legacy columns.
//!
//! Limits: radix 2..=65536, length 2..=max, where radix^ceil(len/2) < 2^120 (all arithmetic is
//! u128), and radix^len >= 1_000_000 (the SP 800-38G Rev.1 minimum domain size).
//! FPE leaks length and is deterministic per tweak. Use a distinct tweak per column or tenant.
use crate::Error;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};

enum Aes {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl Aes {
    fn enc(&self, b: &mut [u8; 16]) {
        let g = GenericArray::from_mut_slice(b);
        match self {
            Aes::A128(c) => c.encrypt_block(g),
            Aes::A192(c) => c.encrypt_block(g),
            Aes::A256(c) => c.encrypt_block(g),
        }
    }
}

pub struct Ff1 {
    aes: Aes,
    radix: u32,
}

const LIMIT: u128 = 1u128 << 120;

fn pow(r: u32, e: usize) -> Option<u128> {
    let mut x: u128 = 1;
    for _ in 0..e {
        x = x.checked_mul(r as u128)?;
    }
    Some(x)
}

fn num(x: &[u16], radix: u32) -> u128 {
    x.iter().fold(0u128, |a, &d| a * radix as u128 + d as u128)
}

fn str_m(mut v: u128, radix: u32, m: usize) -> Vec<u16> {
    let mut out = vec![0u16; m];
    for o in out.iter_mut().rev() {
        *o = (v % radix as u128) as u16;
        v /= radix as u128;
    }
    out
}

impl Ff1 {
    pub fn new(key: &[u8], radix: u32) -> Result<Self, Error> {
        if !(2..=65536).contains(&radix) {
            return Err(Error::InvalidArgument);
        }
        let aes = match key.len() {
            16 => Aes::A128(aes::Aes128::new_from_slice(key).map_err(|_| Error::InvalidKey)?),
            24 => Aes::A192(aes::Aes192::new_from_slice(key).map_err(|_| Error::InvalidKey)?),
            32 => Aes::A256(aes::Aes256::new_from_slice(key).map_err(|_| Error::InvalidKey)?),
            _ => return Err(Error::InvalidKey),
        };
        Ok(Ff1 { aes, radix })
    }

    fn prf(&self, data: &[u8]) -> [u8; 16] {
        let mut y = [0u8; 16];
        for blk in data.chunks(16) {
            for (a, b) in y.iter_mut().zip(blk) {
                *a ^= b;
            }
            self.aes.enc(&mut y);
        }
        y
    }

    fn check(&self, x: &[u16]) -> Result<(usize, usize, usize, u128, u128), Error> {
        let n = x.len();
        if n < 2 || x.iter().any(|&d| d as u32 >= self.radix) {
            return Err(Error::InvalidArgument);
        }
        let (u, v) = (n / 2, n - n / 2);
        let mu = pow(self.radix, u).ok_or(Error::InvalidArgument)?;
        let mv = pow(self.radix, v).filter(|&m| m < LIMIT).ok_or(Error::InvalidArgument)?;
        // Domain size check: radix^n >= 10^6.
        if mu.saturating_mul(mv) < 1_000_000 {
            return Err(Error::InvalidArgument);
        }
        // b = ceil(ceil(v * log2 radix) / 8), and ceil(log2(mv)) = bit length of (mv - 1).
        let bits = 128 - (mv - 1).leading_zeros() as usize;
        Ok((u, v, bits.div_ceil(8), mu, mv))
    }

    fn round(&self, p: &[u8], tweak: &[u8], b: usize, i: u8, bval: u128, m_mod: u128) -> u128 {
        let t = tweak.len();
        let pad = (16 - ((t + b + 1) % 16)) % 16;
        let mut q = Vec::with_capacity(p.len() + t + pad + 1 + b);
        q.extend_from_slice(p);
        q.extend_from_slice(tweak);
        q.extend(std::iter::repeat_n(0u8, pad));
        q.push(i);
        let be = bval.to_be_bytes();
        if b > 16 {
            q.extend(std::iter::repeat_n(0u8, b - 16));
            q.extend_from_slice(&be);
        } else {
            q.extend_from_slice(&be[16 - b..]);
        }
        let r = self.prf(&q);
        let d = 4 * b.div_ceil(4) + 4;
        let mut s = r.to_vec();
        let mut j = 1u128;
        while s.len() < d {
            let mut blk = r;
            for (a, c) in blk.iter_mut().zip(j.to_be_bytes()) {
                *a ^= c;
            }
            self.aes.enc(&mut blk);
            s.extend_from_slice(&blk);
            j += 1;
        }
        // y mod radix^m, folded bytewise so it never overflows (m_mod < 2^120).
        s[..d].iter().fold(0u128, |a, &c| (a * 256 + c as u128) % m_mod)
    }

    fn p_block(&self, u: usize, n: usize, t: usize) -> Vec<u8> {
        let mut p = vec![1, 2, 1];
        p.extend_from_slice(&self.radix.to_be_bytes()[1..]);
        p.push(10);
        p.push((u % 256) as u8);
        p.extend_from_slice(&(n as u32).to_be_bytes());
        p.extend_from_slice(&(t as u32).to_be_bytes());
        p
    }

    pub fn encrypt(&self, tweak: &[u8], x: &[u16]) -> Result<Vec<u16>, Error> {
        let (u, v, b, mu, mv) = self.check(x)?;
        let p = self.p_block(u, x.len(), tweak.len());
        let (mut a, mut bb) = (x[..u].to_vec(), x[u..].to_vec());
        for i in 0..10u8 {
            let (m, md) = if i % 2 == 0 { (u, mu) } else { (v, mv) };
            let y = self.round(&p, tweak, b, i, num(&bb, self.radix), md);
            let c = (num(&a, self.radix) % md + y) % md;
            a = std::mem::replace(&mut bb, str_m(c, self.radix, m));
        }
        a.extend(bb);
        Ok(a)
    }

    pub fn decrypt(&self, tweak: &[u8], x: &[u16]) -> Result<Vec<u16>, Error> {
        let (u, v, b, mu, mv) = self.check(x)?;
        let p = self.p_block(u, x.len(), tweak.len());
        let (mut a, mut bb) = (x[..u].to_vec(), x[u..].to_vec());
        for i in (0..10u8).rev() {
            let (m, md) = if i % 2 == 0 { (u, mu) } else { (v, mv) };
            let y = self.round(&p, tweak, b, i, num(&a, self.radix), md);
            let c = (num(&bb, self.radix) % md + md - y) % md;
            bb = std::mem::replace(&mut a, str_m(c, self.radix, m));
        }
        a.extend(bb);
        Ok(a)
    }

    /// Convenience wrapper for alphabet strings such as "0123456789" or base-36.
    pub fn encrypt_str(&self, tweak: &[u8], alphabet: &str, s: &str) -> Result<String, Error> {
        self.map(alphabet, s, |x| self.encrypt(tweak, x))
    }
    pub fn decrypt_str(&self, tweak: &[u8], alphabet: &str, s: &str) -> Result<String, Error> {
        self.map(alphabet, s, |x| self.decrypt(tweak, x))
    }
    fn map(&self, alphabet: &str, s: &str, f: impl Fn(&[u16]) -> Result<Vec<u16>, Error>) -> Result<String, Error> {
        let al: Vec<char> = alphabet.chars().collect();
        if al.len() != self.radix as usize {
            return Err(Error::InvalidArgument);
        }
        let x = s
            .chars()
            .map(|c| al.iter().position(|&a| a == c).map(|p| p as u16).ok_or(Error::InvalidArgument))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(f(&x)?.into_iter().map(|d| al[d as usize]).collect())
    }
}
