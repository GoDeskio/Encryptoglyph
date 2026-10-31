//! Multi-tenant namespaces, quotas and per-tenant rate limits (backlog #13, MSP model).
//! Namespaces are hierarchical (`msp/acme/eu`), and a child's limits can never exceed its
//! parent's. Ops are charged to the namespace and all of its ancestors. The clock is injected,
//! so tests are deterministic.
use crate::Error;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub struct Limits {
    pub max_keys: u32,
    /// Token bucket: sustained ops per second and burst capacity.
    pub ops_per_sec: u32,
    pub burst: u32,
}

#[derive(Debug)]
struct Ns {
    limits: Limits,
    keys: u32,
    tokens_milli: u64,
    last_ms: u64,
}

#[derive(Debug, PartialEq)]
pub enum Denied {
    NoNamespace,
    KeyQuota(String),
    RateLimited(String),
}

#[derive(Default)]
pub struct Registry {
    ns: BTreeMap<String, Ns>,
}

fn valid(path: &str) -> bool {
    !path.is_empty() && path.split('/').all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
}

fn chain(path: &str) -> Vec<String> {
    let parts: Vec<&str> = path.split('/').collect();
    (1..=parts.len()).map(|i| parts[..i].join("/")).collect()
}

impl Registry {
    pub fn create(&mut self, path: &str, limits: Limits, now_ms: u64) -> Result<(), Error> {
        if !valid(path) || self.ns.contains_key(path) || limits.burst == 0 {
            return Err(Error::InvalidArgument);
        }
        if let Some((parent, _)) = path.rsplit_once('/') {
            let p = self.ns.get(parent).ok_or(Error::InvalidArgument)?;
            if limits.max_keys > p.limits.max_keys || limits.ops_per_sec > p.limits.ops_per_sec || limits.burst > p.limits.burst {
                return Err(Error::InvalidArgument);
            }
        }
        let tokens_milli = limits.burst as u64 * 1000;
        self.ns.insert(path.into(), Ns { limits, keys: 0, tokens_milli, last_ms: now_ms });
        Ok(())
    }

    fn refill(n: &mut Ns, now: u64) {
        let dt = now.saturating_sub(n.last_ms);
        n.tokens_milli = (n.tokens_milli + dt * n.limits.ops_per_sec as u64).min(n.limits.burst as u64 * 1000);
        n.last_ms = now.max(n.last_ms);
    }

    /// Charge one crypto op to `path` and its ancestors. Either all are charged or none are.
    pub fn charge_op(&mut self, path: &str, now_ms: u64) -> Result<(), Denied> {
        let c = chain(path);
        if c.iter().any(|p| !self.ns.contains_key(p)) {
            return Err(Denied::NoNamespace);
        }
        for p in &c {
            let n = self.ns.get_mut(p).unwrap();
            Self::refill(n, now_ms);
            if n.tokens_milli < 1000 {
                return Err(Denied::RateLimited(p.clone()));
            }
        }
        for p in &c {
            self.ns.get_mut(p).unwrap().tokens_milli -= 1000;
        }
        Ok(())
    }

    /// Reserve a key slot in `path` and its ancestors (each ancestor counts its whole subtree).
    pub fn add_key(&mut self, path: &str) -> Result<(), Denied> {
        let c = chain(path);
        if c.iter().any(|p| !self.ns.contains_key(p)) {
            return Err(Denied::NoNamespace);
        }
        if let Some(p) = c.iter().find(|p| { let n = &self.ns[*p]; n.keys >= n.limits.max_keys }) {
            return Err(Denied::KeyQuota(p.clone()));
        }
        for p in &c {
            self.ns.get_mut(p).unwrap().keys += 1;
        }
        Ok(())
    }

    pub fn remove_key(&mut self, path: &str) {
        for p in chain(path) {
            if let Some(n) = self.ns.get_mut(&p) {
                n.keys = n.keys.saturating_sub(1);
            }
        }
    }

    pub fn usage(&self, path: &str) -> Option<(u32, Limits)> {
        self.ns.get(path).map(|n| (n.keys, n.limits.clone()))
    }
}
