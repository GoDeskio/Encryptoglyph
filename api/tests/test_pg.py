import pytest

from eg_crypto import DecryptError, Keyring
from eg_crypto.pg import EncryptedTable

T = EncryptedTable("users", "id", ["email", "ssn"], indexed={"email"})
IK = b"\x07" * 32


@pytest.fixture
def kr():
    return Keyring({"k1": Keyring.generate_key()}, "k1")


def test_ddl():
    d = T.ddl()
    assert "ADD COLUMN IF NOT EXISTS email_ct bytea" in d
    assert "email_bi" in d and "ssn_bi" not in d


def test_seal_open_roundtrip_and_no_plaintext(kr):
    row = {"id": 42, "name": "Ann", "email": "Ann@X.io", "ssn": "123-45-6789"}
    s = T.seal_row(kr, IK, "acme", row)
    assert "email" not in s and "ssn" not in s
    assert b"123-45" not in s["ssn_ct"]
    assert T.open_row(kr, "acme", s) == row | {"id": 42}


def test_row_swap_and_tenant_bound(kr):
    a = T.seal_row(kr, IK, "acme", {"id": 1, "email": "a@x", "ssn": "1"})
    b = T.seal_row(kr, IK, "acme", {"id": 2, "email": "b@x", "ssn": "2"})
    a["ssn_ct"] = b["ssn_ct"]
    with pytest.raises(DecryptError):
        T.open_row(kr, "acme", a)
    with pytest.raises(DecryptError):
        T.open_row(kr, "other", b)


def test_lookup_matches_normalized_and_nulls(kr):
    s = T.seal_row(kr, IK, "acme", {"id": 3, "email": "Bob@X.io", "ssn": None})
    sql, (bi,) = T.lookup(IK, "acme", "email", "  bob@x.io ")
    assert bi == s["email_bi"] and "%s" in sql
    assert s["ssn_ct"] is None
    assert T.open_row(kr, "acme", s)["ssn"] is None
    with pytest.raises(ValueError):
        T.lookup(IK, "acme", "ssn", "x")


def test_rejects_unsafe_identifiers():
    with pytest.raises(ValueError):
        EncryptedTable("users; drop", "id", ["a"])
