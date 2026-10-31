import pytest

from eg_crypto import ReauthGate, ReauthRequired

KEY = b"k" * 32


class Clock:
    t = 1_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def gate():
    c = Clock()
    g = ReauthGate(KEY, ttl=60, clock=c)
    g.clock = c
    return g


def test_grant_consume_once(gate):
    tok = gate.grant("u1", "export", "vault", verified=True)
    gate.consume(tok, "u1", "export", "vault")
    with pytest.raises(ReauthRequired):
        gate.consume(tok, "u1", "export", "vault")  # single use


def test_unverified_or_unknown_action(gate):
    with pytest.raises(ReauthRequired):
        gate.grant("u1", "export", "vault", verified=False)
    with pytest.raises(ValueError):
        gate.grant("u1", "admin.reset", "x", verified=True)


@pytest.mark.parametrize("subject,action,target", [
    ("u2", "key.retire", "kv1"), ("u1", "key.shred", "kv1"), ("u1", "key.retire", "kv2"),
])
def test_bound_to_subject_action_target(gate, subject, action, target):
    tok = gate.grant("u1", "key.retire", "kv1", verified=True)
    with pytest.raises(ReauthRequired):
        gate.consume(tok, subject, action, target)


def test_expiry(gate):
    tok = gate.grant("u1", "tenant.shred", "t1", verified=True)
    gate.clock.t += 61
    with pytest.raises(ReauthRequired):
        gate.consume(tok, "u1", "tenant.shred", "t1")


@pytest.mark.parametrize("bad", [None, "", "a.b", "a.b.c", "x.1.y"])
def test_malformed(gate, bad):
    with pytest.raises(ReauthRequired):
        gate.consume(bad, "u1", "export", "vault")


def test_tampered_and_other_key(gate):
    tok = gate.grant("u1", "export", "vault", verified=True)
    g, e, t = tok.split(".")
    with pytest.raises(ReauthRequired):
        gate.consume(f"{g}.{int(e) + 100}.{t}", "u1", "export", "vault")
    other = ReauthGate(b"z" * 32, clock=gate.clock)
    with pytest.raises(ReauthRequired):
        other.consume(tok, "u1", "export", "vault")


def test_config_validation():
    with pytest.raises(ValueError):
        ReauthGate(b"short")
    with pytest.raises(ValueError):
        ReauthGate(KEY, ttl=5)
