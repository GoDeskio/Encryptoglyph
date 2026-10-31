import os

import pytest
from nacl import pwhash

from eg_crypto import (
    VERSION_LEGACY,
    VERSION_V2,
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
    needs_rewrap,
    parse_header,
    rewrap,
    encrypt_v2,
    VERSION_V3,
    verify_blind_index,
)

CTX = RecordContext("tenant-a", "field-enc", "users", "42", "ssn", 1)


@pytest.fixture
def kr():
    return Keyring({"k1": Keyring.generate_key()}, "k1")


def test_roundtrip_v3_default(kr):
    blob = encrypt(kr, CTX, b"secret")
    assert parse_header(blob)[0] == VERSION_V3
    assert len(parse_header(blob)[3]) == 24
    assert decrypt(kr, CTX, blob) == b"secret"


def test_nonces_unique(kr):
    assert encrypt(kr, CTX, b"x") != encrypt(kr, CTX, b"x")


@pytest.mark.parametrize("pos", [0, 2, 3, 6, 10, -1, -20])
def test_tamper_any_byte(kr, pos):
    blob = bytearray(encrypt(kr, CTX, b"secret payload"))
    blob[pos] ^= 0x01
    with pytest.raises(DecryptError):
        decrypt(kr, CTX, bytes(blob))


def test_truncated(kr):
    with pytest.raises(DecryptError):
        decrypt(kr, CTX, encrypt(kr, CTX, b"abc")[:20])


@pytest.mark.parametrize("field", ["tenant", "purpose", "table", "record_id", "field", "schema_version"])
def test_wrong_aad_blocks_swap(kr, field):
    blob = encrypt(kr, CTX, b"secret")
    other = RecordContext(**{**CTX.__dict__, field: 2 if field == "schema_version" else "zzz"})
    with pytest.raises(DecryptError):
        decrypt(kr, other, blob)


def test_aad_encoding_unambiguous():
    a = RecordContext("ab", "c", "t", "1")
    b = RecordContext("a", "bc", "t", "1")
    assert a.aad() != b.aad()


def test_legacy_decrypt_and_upgrade(kr):
    old = encrypt_legacy_v1(kr, CTX, b"legacy")
    assert parse_header(old)[0] == VERSION_LEGACY
    assert decrypt(kr, CTX, old) == b"legacy"
    assert needs_rewrap(kr, old)
    new = rewrap(kr, CTX, old)
    assert parse_header(new)[0] == VERSION_V3
    assert not needs_rewrap(kr, new)
    assert decrypt(kr, CTX, new, min_version=VERSION_V3) == b"legacy"


def test_downgrade_guard(kr):
    old = encrypt_legacy_v1(kr, CTX, b"legacy")
    with pytest.raises(DowngradeError):
        decrypt(kr, CTX, old, min_version=VERSION_V2)


def test_version_byte_forgery_rejected(kr):
    blob = bytearray(encrypt(kr, CTX, b"x"))
    blob[2] = VERSION_LEGACY  # version/alg mismatch
    with pytest.raises(DecryptError):
        decrypt(kr, CTX, bytes(blob))


def test_rotation(kr):
    old = encrypt(kr, CTX, b"rotate me")
    kr.add("k2", Keyring.generate_key())
    assert needs_rewrap(kr, old)
    assert decrypt(kr, CTX, old) == b"rotate me"
    new = rewrap(kr, CTX, old)
    assert parse_header(new)[2] == "k2"
    kr.retire("k1")
    assert decrypt(kr, CTX, new) == b"rotate me"
    with pytest.raises(DecryptError):
        decrypt(kr, CTX, old)
    with pytest.raises(ValueError):
        kr.retire("k2")


def test_wrong_key(kr):
    blob = encrypt(kr, CTX, b"x")
    other = Keyring({"k1": Keyring.generate_key()}, "k1")
    with pytest.raises(DecryptError):
        decrypt(other, CTX, blob)


def test_hkdf_separation(kr):
    from eg_crypto import ALG_XCHACHA20POLY1305 as A
    keys = {kr.derive("k1", p, t, A) for p in ("a", "b") for t in ("t1", "t2")}
    assert len(keys) == 4


def test_argon2id_password_root():
    salt = os.urandom(16)
    kw = {"opslimit": pwhash.argon2id.OPSLIMIT_MIN, "memlimit": pwhash.argon2id.MEMLIMIT_MIN}
    k1 = derive_root_key_from_password("correct horse", salt, **kw)
    assert k1 == derive_root_key_from_password("correct horse", salt, **kw)
    assert k1 != derive_root_key_from_password("wrong horse", salt, **kw)
    kr = Keyring({"pw": k1}, "pw")
    assert decrypt(kr, CTX, encrypt(kr, CTX, b"z")) == b"z"
    with pytest.raises(ValueError):
        derive_root_key_from_password("x", b"short")


def test_blind_index_constant_time():
    key = os.urandom(32)
    tag = blind_index(key, "t", "email", "  Foo@Example.com ")
    assert verify_blind_index(key, "t", "email", "foo@example.com", tag)
    assert not verify_blind_index(key, "t2", "email", "foo@example.com", tag)
    assert ct_equal(b"a", b"a") and not ct_equal(b"a", b"b")


def test_keyring_validation():
    with pytest.raises(ValueError):
        Keyring({"k": b"short"}, "k")
    with pytest.raises(ValueError):
        Keyring({"k": os.urandom(32)}, "missing")


def test_shared_vectors():
    import json
    from pathlib import Path
    v = json.loads((Path(__file__).parents[2] / "testvectors/envelope.json").read_text())
    kr = Keyring({v["kid"]: bytes.fromhex(v["key_hex"])}, v["kid"])
    ctx = RecordContext(*v["ctx"])
    for f in ("v3_hex", "v2_hex", "v1_hex"):
        assert decrypt(kr, ctx, bytes.fromhex(v[f])) == v["plaintext"].encode()
    assert blind_index(bytes.fromhex(v["key_hex"]), "tenant-a", "email", "Foo@Example.com").hex() == v["blind_index_hex"]


# --- v3 key commitment -------------------------------------------------------

def test_v2_still_decrypts_and_upgrades_to_v3(kr):
    old = encrypt_v2(kr, CTX, b"v2 data")
    assert parse_header(old)[0] == VERSION_V2
    assert decrypt(kr, CTX, old) == b"v2 data"
    assert needs_rewrap(kr, old)
    assert parse_header(rewrap(kr, CTX, old))[0] == VERSION_V3
    with pytest.raises(DowngradeError):
        decrypt(kr, CTX, old, min_version=VERSION_V3)


def test_commitment_tamper_rejected(kr):
    blob = bytearray(encrypt(kr, CTX, b"secret"))
    off = len(parse_header(bytes(blob))[4])
    for i in (off, off + 31):
        b = bytearray(blob)
        b[i] ^= 0x80
        with pytest.raises(DecryptError):
            decrypt(kr, CTX, bytes(b))


def test_commitment_differs_per_key(kr):
    """Same nonce/header/context under two keys -> different commitments (key is bound)."""
    from eg_crypto.envelope import _commit_keys, _commitment
    nonce, aad = b"n" * 24, b"aad"
    c1 = _commitment(_commit_keys(b"a" * 32, nonce)[1], aad)
    c2 = _commitment(_commit_keys(b"b" * 32, nonce)[1], aad)
    assert c1 != c2 and len(c1) == 32


def test_v3_truncated_into_commitment(kr):
    blob = encrypt(kr, CTX, b"x")
    hdr_len = len(parse_header(blob)[4])
    with pytest.raises(DecryptError):
        decrypt(kr, CTX, blob[: hdr_len + 40])
