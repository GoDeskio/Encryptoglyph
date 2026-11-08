//! FF1 format-preserving encryption (NIST SP 800-38G) via the `fpe` crate
//! (Jack Grigg's reviewed implementation). AES is the block cipher. This module
//! only maps alphabets onto numeral strings.
//!
//! Limits follow SP 800-38G Rev. 1: radix 2..=65536 and a domain of at least
//! one million strings. FPE leaks length and is deterministic for a tweak.
//! Use a distinct tweak per column or tenant.
use crate::Error;
use aes::{Aes128, Aes192, Aes256};
use fpe::ff1::{FlexibleNumeralString, FF1};

enum Inner {
    A128(FF1<Aes128>),
    A192(FF1<Aes192>),
    A256(FF1<Aes256>),
}

pub struct Ff1 {
    inner: Inner,
    radix: u32,
}

impl Ff1 {
    pub fn new(key: &[u8], radix: u32) -> Result<Self, Error> {
        if !(2..=65536).contains(&radix) {
            return Err(Error::InvalidArgument);
        }
        let inner = match key.len() {
            16 => Inner::A128(FF1::<Aes128>::new(key, radix).map_err(|_| Error::InvalidArgument)?),
            24 => Inner::A192(FF1::<Aes192>::new(key, radix).map_err(|_| Error::InvalidArgument)?),
            32 => Inner::A256(FF1::<Aes256>::new(key, radix).map_err(|_| Error::InvalidArgument)?),
            _ => return Err(Error::InvalidKey),
        };
        Ok(Ff1 { inner, radix })
    }

    fn apply(&self, tweak: &[u8], x: &[u16], encrypt: bool) -> Result<Vec<u16>, Error> {
        if x.iter().any(|&d| u32::from(d) >= self.radix) {
            return Err(Error::InvalidArgument);
        }
        let ns = FlexibleNumeralString::from(x.to_vec());
        let out = match &self.inner {
            Inner::A128(ff) if encrypt => ff.encrypt(tweak, &ns).map_err(|_| Error::InvalidArgument)?,
            Inner::A128(ff) => ff.decrypt(tweak, &ns).map_err(|_| Error::InvalidArgument)?,
            Inner::A192(ff) if encrypt => ff.encrypt(tweak, &ns).map_err(|_| Error::InvalidArgument)?,
            Inner::A192(ff) => ff.decrypt(tweak, &ns).map_err(|_| Error::InvalidArgument)?,
            Inner::A256(ff) if encrypt => ff.encrypt(tweak, &ns).map_err(|_| Error::InvalidArgument)?,
            Inner::A256(ff) => ff.decrypt(tweak, &ns).map_err(|_| Error::InvalidArgument)?,
        };
        Ok(Vec::<u16>::from(out))
    }

    pub fn encrypt(&self, tweak: &[u8], x: &[u16]) -> Result<Vec<u16>, Error> {
        self.apply(tweak, x, true)
    }

    pub fn decrypt(&self, tweak: &[u8], x: &[u16]) -> Result<Vec<u16>, Error> {
        self.apply(tweak, x, false)
    }

    /// Convenience wrapper for alphabet strings such as "0123456789" or base-36.
    pub fn encrypt_str(&self, tweak: &[u8], alphabet: &str, s: &str) -> Result<String, Error> {
        self.map(tweak, alphabet, s, true)
    }

    pub fn decrypt_str(&self, tweak: &[u8], alphabet: &str, s: &str) -> Result<String, Error> {
        self.map(tweak, alphabet, s, false)
    }

    fn map(&self, tweak: &[u8], alphabet: &str, s: &str, encrypt: bool) -> Result<String, Error> {
        let al: Vec<char> = alphabet.chars().collect();
        if al.len() != self.radix as usize {
            return Err(Error::InvalidArgument);
        }
        let x = s
            .chars()
            .map(|c| {
                al.iter()
                    .position(|&a| a == c)
                    .map(|p| p as u16)
                    .ok_or(Error::InvalidArgument)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self
            .apply(tweak, &x, encrypt)?
            .into_iter()
            .map(|d| al[d as usize])
            .collect())
    }
}
