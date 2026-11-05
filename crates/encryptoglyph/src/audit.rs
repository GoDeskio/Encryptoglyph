//! Tamper-evident audit log (backlog #5; learned from Vault audit devices, Keybase sigchain,
//! Keeper/1Password event export). Each record is chained to the previous one and MACed with an
//! audit key (HMAC-SHA256), so edits, reordering, deletion in the middle, or a forged tail are
//! detected. Truncation of the tail is detected by comparing the head against a stored/anchored
//! head (`verify_chain(.., Some(expected_head))`). Payloads are opaque bytes (metadata only).
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
pub const GENESIS: [u8; 32] = [0u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    pub prev: [u8; 32],
    pub payload: Vec<u8>,
    pub mac: [u8; 32],
}

impl AuditRecord {
    /// Link hash that the next record's `prev` must equal.
    pub fn link(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.seq.to_be_bytes());
        h.update(self.prev);
        h.update((self.payload.len() as u64).to_be_bytes());
        h.update(&self.payload);
        h.update(self.mac);
        h.finalize().into()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuditError {
    BadSeq(u64),
    BrokenLink(u64),
    BadMac(u64),
    HeadMismatch,
    BadKey,
}

fn mac(key: &[u8], seq: u64, prev: &[u8; 32], payload: &[u8]) -> Result<[u8; 32], AuditError> {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| AuditError::BadKey)?;
    m.update(b"encryptoglyph/audit/v1");
    m.update(&seq.to_be_bytes());
    m.update(prev);
    m.update(&(payload.len() as u64).to_be_bytes());
    m.update(payload);
    Ok(m.finalize().into_bytes().into())
}

pub struct AuditLog {
    key: Zeroizing<Vec<u8>>,
    next_seq: u64,
    head: [u8; 32],
}

impl AuditLog {
    pub fn new(audit_key: &[u8]) -> Result<Self, AuditError> {
        if audit_key.len() < 32 {
            return Err(AuditError::BadKey);
        }
        Ok(Self {
            key: Zeroizing::new(audit_key.to_vec()),
            next_seq: 0,
            head: GENESIS,
        })
    }
    /// Resume after the last verified record.
    pub fn resume(audit_key: &[u8], last: &AuditRecord) -> Result<Self, AuditError> {
        let mut l = Self::new(audit_key)?;
        l.next_seq = last.seq + 1;
        l.head = last.link();
        Ok(l)
    }
    pub fn head(&self) -> [u8; 32] {
        self.head
    }
    pub fn append(&mut self, payload: &[u8]) -> Result<AuditRecord, AuditError> {
        let r = AuditRecord {
            seq: self.next_seq,
            prev: self.head,
            payload: payload.to_vec(),
            mac: mac(&self.key, self.next_seq, &self.head, payload)?,
        };
        self.head = r.link();
        self.next_seq += 1;
        Ok(r)
    }
}

/// Verify a full chain from genesis (or from `start` = (first seq, prev) for rotated segments).
/// Returns the head link hash.
pub fn verify_chain(
    audit_key: &[u8],
    records: &[AuditRecord],
    start: Option<(u64, [u8; 32])>,
    expected_head: Option<[u8; 32]>,
) -> Result<[u8; 32], AuditError> {
    let (mut seq, mut prev) = start.unwrap_or((0, GENESIS));
    for r in records {
        if r.seq != seq {
            return Err(AuditError::BadSeq(r.seq));
        }
        if r.prev.ct_eq(&prev).unwrap_u8() != 1 {
            return Err(AuditError::BrokenLink(r.seq));
        }
        let m = mac(audit_key, r.seq, &r.prev, &r.payload)?;
        if m.ct_eq(&r.mac).unwrap_u8() != 1 {
            return Err(AuditError::BadMac(r.seq));
        }
        prev = r.link();
        seq += 1;
    }
    if let Some(h) = expected_head {
        if h.ct_eq(&prev).unwrap_u8() != 1 {
            return Err(AuditError::HeadMismatch);
        }
    }
    Ok(prev)
}
