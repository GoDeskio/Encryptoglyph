//! Versioned secrets with rotation hooks (backlog #14), the "one console" surface.
//! Each version is a normal v2 envelope whose record context binds tenant, name and version,
//! so versions can't be swapped. Values are never logged or returned by `list`.
use crate::{decrypt, encrypt, Error, Keyring, RecordContext, VERSION_V2};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Called after a new version is stored, for example to push it to an app or bump a deploy.
/// It receives only metadata, never the value.
pub trait RotationHook {
    fn rotated(&mut self, tenant: &str, name: &str, version: u32);
}

#[derive(Debug, Clone, PartialEq)]
pub struct VersionMeta {
    pub version: u32,
    pub created_unix: u64,
    pub destroyed: bool,
}

struct Entry {
    meta: VersionMeta,
    sealed: Option<Vec<u8>>,
}

pub struct SecretStore<'k> {
    kr: &'k Keyring,
    tenant: String,
    items: BTreeMap<String, Vec<Entry>>,
    hooks: Vec<Box<dyn RotationHook>>,
}

fn ctx(tenant: &str, name: &str, v: u32) -> RecordContext {
    RecordContext { tenant: tenant.into(), purpose: "secret".into(), table: "secrets".into(), record_id: name.into(), field: format!("v{v}"), schema_version: 1 }
}

impl<'k> SecretStore<'k> {
    pub fn new(kr: &'k Keyring, tenant: &str) -> Self {
        SecretStore { kr, tenant: tenant.into(), items: BTreeMap::new(), hooks: vec![] }
    }

    pub fn on_rotate(&mut self, h: Box<dyn RotationHook>) {
        self.hooks.push(h);
    }

    /// Store a new version and return its number (starting at 1).
    pub fn put(&mut self, name: &str, value: &[u8], now_unix: u64) -> Result<u32, Error> {
        if name.is_empty() || name.len() > 200 || name.contains(char::is_whitespace) {
            return Err(Error::InvalidArgument);
        }
        let list = self.items.entry(name.into()).or_default();
        let v = list.len() as u32 + 1;
        let sealed = encrypt(self.kr, &ctx(&self.tenant, name, v), value)?;
        list.push(Entry { meta: VersionMeta { version: v, created_unix: now_unix, destroyed: false }, sealed: Some(sealed) });
        for h in self.hooks.iter_mut() {
            h.rotated(&self.tenant, name, v);
        }
        Ok(v)
    }

    /// Fetch a version. `None` means the latest version that hasn't been destroyed.
    pub fn get(&self, name: &str, version: Option<u32>) -> Result<Zeroizing<Vec<u8>>, Error> {
        let list = self.items.get(name).ok_or(Error::Decrypt)?;
        let e = match version {
            Some(v) => list.get((v as usize).checked_sub(1).ok_or(Error::InvalidArgument)?),
            None => list.iter().rev().find(|e| !e.meta.destroyed),
        }
        .ok_or(Error::Decrypt)?;
        let sealed = e.sealed.as_ref().ok_or(Error::Decrypt)?;
        decrypt(self.kr, &ctx(&self.tenant, name, e.meta.version), sealed, VERSION_V2)
    }

    pub fn versions(&self, name: &str) -> Vec<VersionMeta> {
        self.items.get(name).map(|l| l.iter().map(|e| e.meta.clone()).collect()).unwrap_or_default()
    }

    pub fn names(&self) -> Vec<String> {
        self.items.keys().cloned().collect()
    }

    /// Irreversibly drop a version's ciphertext. Its metadata stays for audit.
    pub fn destroy(&mut self, name: &str, version: u32) -> bool {
        match self.items.get_mut(name).and_then(|l| l.get_mut((version as usize).wrapping_sub(1))) {
            Some(e) if !e.meta.destroyed => {
                e.sealed = None;
                e.meta.destroyed = true;
                true
            }
            _ => false,
        }
    }

    /// Export a version's sealed blob (for example to a DB row). Restore with the same ctx.
    pub fn sealed(&self, name: &str, version: u32) -> Option<&[u8]> {
        self.items.get(name)?.get((version as usize).wrapping_sub(1))?.sealed.as_deref()
    }
}
