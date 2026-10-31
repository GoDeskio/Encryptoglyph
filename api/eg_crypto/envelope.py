"""Versioned AEAD envelope.

Wire format (all versions)::

    magic  b"EG"            2 bytes
    ver    u8               1 = legacy AES-256-GCM, 2 = XChaCha20-Poly1305 (default)
    alg    u8               1 = AES-256-GCM, 2 = XChaCha20-Poly1305-IETF
    kid_len u8, kid bytes   key id of the root key used (rotation)
    nonce                   12 bytes (v1) / 24 bytes (v2)
    ciphertext || tag(16)

The full header (magic..nonce) is authenticated as AAD together with the canonical
record context (tenant, purpose, table, record id, field, schema version), so a
ciphertext cannot be swapped between records, fields, tenants, or versions, and the
version/alg bytes cannot be altered (downgrade guard).

Per-purpose/tenant data keys are derived with HKDF-SHA256 from the root key; the root
key itself never encrypts data directly.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl import bindings as sodium
from nacl import pwhash
from nacl.exceptions import CryptoError

MAGIC = b"EG"
VERSION_LEGACY = 1
VERSION_V2 = 2
VERSION_V3 = 3
ALG_AES256GCM = 1
ALG_XCHACHA20POLY1305 = 2
ALG_XCHACHA20POLY1305_COMMIT = 3
_COMMIT_LEN = 32
_NONCE_LEN = {ALG_AES256GCM: 12, ALG_XCHACHA20POLY1305: 24, ALG_XCHACHA20POLY1305_COMMIT: 24}
_VERSION_ALG = {
    VERSION_LEGACY: ALG_AES256GCM,
    VERSION_V2: ALG_XCHACHA20POLY1305,
    VERSION_V3: ALG_XCHACHA20POLY1305_COMMIT,
}
KEY_LEN = 32
_HKDF_SALT = b"encryptoglyph/hkdf-salt/v2"


class DecryptError(Exception):
    """Authentication failed or envelope malformed. Deliberately non-specific."""


class DowngradeError(DecryptError):
    """Envelope version below the caller's minimum."""


def ct_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


@dataclass(frozen=True)
class RecordContext:
    tenant: str
    purpose: str
    table: str
    record_id: str
    field: str = ""
    schema_version: int = 1

    def aad(self) -> bytes:
        parts = [self.tenant, self.purpose, self.table, self.record_id, self.field,
                 str(self.schema_version)]
        return b"EGAAD1" + b"".join(_lp(p.encode()) for p in parts)


class Keyring:
    """Root keys by id. The newest (``current``) is used to encrypt; all decrypt."""

    def __init__(self, keys: dict[str, bytes], current: str):
        if current not in keys:
            raise ValueError("current key id not in keyring")
        for kid, k in keys.items():
            if len(k) != KEY_LEN:
                raise ValueError("root keys must be 32 bytes")
            if not 0 < len(kid.encode()) < 256:
                raise ValueError("bad key id")
        self._keys = dict(keys)
        self.current = current

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(KEY_LEN)

    def add(self, kid: str, key: bytes, make_current: bool = True) -> None:
        if len(key) != KEY_LEN:
            raise ValueError("root keys must be 32 bytes")
        self._keys[kid] = key
        if make_current:
            self.current = kid

    def retire(self, kid: str) -> None:
        if kid == self.current:
            raise ValueError("cannot retire current key")
        self._keys.pop(kid, None)

    def has(self, kid: str) -> bool:
        return kid in self._keys

    def derive(self, kid: str, purpose: str, tenant: str, alg: int) -> bytes:
        """HKDF key separation per root key / purpose / tenant / algorithm."""
        root = self._keys.get(kid)
        if root is None:
            raise DecryptError("decryption failed")
        info = b"encryptoglyph/dek/v2" + _lp(purpose.encode()) + _lp(tenant.encode()) + bytes([alg])
        return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=_HKDF_SALT, info=info).derive(root)


def derive_root_key_from_password(password: str, salt: bytes, *,
                                  opslimit: int = pwhash.argon2id.OPSLIMIT_MODERATE,
                                  memlimit: int = pwhash.argon2id.MEMLIMIT_MODERATE) -> bytes:
    """Argon2id (libsodium). ``salt`` must be 16 random bytes stored with the account."""
    if len(salt) != pwhash.argon2id.SALTBYTES:
        raise ValueError("salt must be 16 bytes")
    return pwhash.argon2id.kdf(KEY_LEN, password.encode(), salt, opslimit=opslimit, memlimit=memlimit)


def _header(version: int, alg: int, kid: str, nonce: bytes) -> bytes:
    k = kid.encode()
    return MAGIC + bytes([version, alg, len(k)]) + k + nonce


def parse_header(blob: bytes) -> tuple[int, int, str, bytes, bytes, bytes]:
    """Return (version, alg, kid, nonce, header, body). Raises DecryptError."""
    try:
        if blob[:2] != MAGIC:
            raise ValueError
        version, alg, klen = blob[2], blob[3], blob[4]
        if _VERSION_ALG.get(version) != alg:
            raise ValueError
        kid = blob[5:5 + klen].decode()
        n = _NONCE_LEN[alg]
        off = 5 + klen
        nonce = blob[off:off + n]
        extra = _COMMIT_LEN if alg == ALG_XCHACHA20POLY1305_COMMIT else 0
        if len(nonce) != n or len(blob) < off + n + extra + 16:
            raise ValueError
        return version, alg, kid, nonce, blob[:off + n], blob[off + n:]
    except (ValueError, IndexError, KeyError, UnicodeDecodeError):
        raise DecryptError("decryption failed") from None


def _commit_keys(dek: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """v3 key commitment: split the DEK into an AEAD key and a commitment key (HKDF, salt=nonce)."""
    def h(label: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=nonce, info=label).derive(dek)
    return h(b"encryptoglyph/v3/enc"), h(b"encryptoglyph/v3/commit")


def _commitment(commit_key: bytes, aad: bytes) -> bytes:
    return hmac.new(commit_key, b"EGCMT1" + aad, hashlib.sha256).digest()


def encrypt(keyring: Keyring, ctx: RecordContext, plaintext: bytes) -> bytes:
    """Encrypt with the default v3 envelope: XChaCha20-Poly1305 plus a 32-byte key commitment.

    Body = commitment || ct || tag. The commitment binds the key, nonce, header and context, so
    one ciphertext cannot decrypt validly under two different keys (no partitioning-oracle or
    "invisible salamander" attacks).
    """
    alg = ALG_XCHACHA20POLY1305_COMMIT
    dek = keyring.derive(keyring.current, ctx.purpose, ctx.tenant, alg)
    nonce = os.urandom(24)
    hdr = _header(VERSION_V3, alg, keyring.current, nonce)
    aad = hdr + ctx.aad()
    enc_key, commit_key = _commit_keys(dek, nonce)
    ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, enc_key)
    return hdr + _commitment(commit_key, aad) + ct


def encrypt_v2(keyring: Keyring, ctx: RecordContext, plaintext: bytes) -> bytes:
    """v2 envelope (XChaCha20-Poly1305, no key commitment). For tests/interop; read-compatible."""
    alg = ALG_XCHACHA20POLY1305
    key = keyring.derive(keyring.current, ctx.purpose, ctx.tenant, alg)
    nonce = os.urandom(24)
    hdr = _header(VERSION_V2, alg, keyring.current, nonce)
    ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, hdr + ctx.aad(), nonce, key)
    return hdr + ct


def encrypt_legacy_v1(keyring: Keyring, ctx: RecordContext, plaintext: bytes) -> bytes:
    """Legacy v1 (AES-256-GCM, 96-bit nonce). Kept ONLY for tests/interop; do not use."""
    alg = ALG_AES256GCM
    key = keyring.derive(keyring.current, ctx.purpose, ctx.tenant, alg)
    nonce = os.urandom(12)
    hdr = _header(VERSION_LEGACY, alg, keyring.current, nonce)
    return hdr + AESGCM(key).encrypt(nonce, plaintext, hdr + ctx.aad())


def decrypt(keyring: Keyring, ctx: RecordContext, blob: bytes, *, min_version: int = VERSION_LEGACY) -> bytes:
    version, alg, kid, nonce, hdr, body = parse_header(blob)
    if version < min_version:
        raise DowngradeError("envelope version below minimum")
    key = keyring.derive(kid, ctx.purpose, ctx.tenant, alg)
    aad = hdr + ctx.aad()
    try:
        if alg == ALG_XCHACHA20POLY1305_COMMIT:
            enc_key, commit_key = _commit_keys(key, nonce)
            if not hmac.compare_digest(body[:_COMMIT_LEN], _commitment(commit_key, aad)):
                raise DecryptError("decryption failed")
            return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(body[_COMMIT_LEN:], aad, nonce, enc_key)
        if alg == ALG_XCHACHA20POLY1305:
            return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(body, aad, nonce, key)
        return AESGCM(key).decrypt(nonce, body, aad)
    except (CryptoError, InvalidTag, ValueError):
        raise DecryptError("decryption failed") from None


def needs_rewrap(keyring: Keyring, blob: bytes) -> bool:
    version, _alg, kid, *_ = parse_header(blob)
    return version < VERSION_V3 or kid != keyring.current


def rewrap(keyring: Keyring, ctx: RecordContext, blob: bytes, *, new_ctx: RecordContext | None = None) -> bytes:
    """Decrypt (any supported version/key) and re-encrypt as v3 under the current key.

    Use on unlock/read ("upgrade on unlock") and in bulk rotation jobs. Once every record
    is v3 under the new key, callers should set ``min_version=VERSION_V3`` and retire old keys.
    """
    return encrypt(keyring, new_ctx or ctx, decrypt(keyring, ctx, blob))


def blind_index(key: bytes, tenant: str, field: str, value: str, length: int = 16) -> bytes:
    """Truncated HMAC-SHA256 of the normalised value, separated per tenant/field."""
    norm = " ".join(value.strip().lower().split()).encode()
    mac = hmac.new(key, b"EGBI1" + _lp(tenant.encode()) + _lp(field.encode()) + norm, hashlib.sha256)
    return mac.digest()[:length]


def verify_blind_index(key: bytes, tenant: str, field: str, value: str, expected: bytes) -> bool:
    return ct_equal(blind_index(key, tenant, field, value, len(expected)), expected)
