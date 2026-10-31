"""Encryptoglyph envelope crypto (vetted primitives only: libsodium via PyNaCl, pyca/cryptography).

Zero-knowledge: no escrow/master override key exists in this module. Only holders of a
root key (or the password it is derived from) can decrypt.
"""

from .envelope import (
    ALG_AES256GCM,
    ALG_XCHACHA20POLY1305,
    ALG_XCHACHA20POLY1305_COMMIT,
    VERSION_LEGACY,
    VERSION_V2,
    VERSION_V3,
    DecryptError,
    DowngradeError,
    Keyring,
    RecordContext,
    blind_index,
    ct_equal,
    decrypt,
    derive_root_key_from_password,
    encrypt,
    encrypt_legacy_v1,
    encrypt_v2,
    needs_rewrap,
    parse_header,
    rewrap,
    verify_blind_index,
)

__all__ = [
    "ALG_AES256GCM", "ALG_XCHACHA20POLY1305", "ALG_XCHACHA20POLY1305_COMMIT", "VERSION_V3", "encrypt_v2", "VERSION_LEGACY", "VERSION_V2",
    "DecryptError", "DowngradeError", "Keyring", "RecordContext", "blind_index",
    "ct_equal", "decrypt", "derive_root_key_from_password", "encrypt",
    "encrypt_legacy_v1", "needs_rewrap", "parse_header", "rewrap", "verify_blind_index",
]
