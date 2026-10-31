"""Re-authentication gate for destructive or exfiltrating actions.

Export, key deletion (retire), and crypto-shred must not run on a session alone. The
caller re-proves the secret (password, or a WebAuthn assertion verified elsewhere), and the
gate mints a short-lived, **single-use** grant bound to (subject, action, target). The
sensitive operation then consumes the grant.

Grants are HMAC-SHA256 tokens under a server-held gate key. Nothing here can decrypt data,
so it does not affect zero-knowledge. Used grant ids are kept in memory until they expire;
multi-process deployments should pass a shared ``used_store`` (e.g. Redis SETNX).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from collections.abc import Callable, MutableMapping

ACTIONS = frozenset({"export", "key.retire", "key.shred", "tenant.shred"})
DEFAULT_TTL = 120  # seconds


class ReauthRequired(PermissionError):
    """The action needs a fresh, matching, unused re-auth grant."""


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class ReauthGate:
    def __init__(self, gate_key: bytes, *, ttl: int = DEFAULT_TTL,
                 clock: Callable[[], float] = time.time,
                 used_store: MutableMapping[str, float] | None = None):
        if len(gate_key) < 32:
            raise ValueError("gate key must be at least 32 bytes")
        if not 10 <= ttl <= 900:
            raise ValueError("ttl must be 10..900 seconds")
        self._k, self._ttl, self._now = gate_key, ttl, clock
        self._used = used_store if used_store is not None else {}

    def _mac(self, msg: bytes) -> bytes:
        return hmac.new(self._k, b"EGRA1" + msg, hashlib.sha256).digest()

    @staticmethod
    def _msg(gid: bytes, exp: int, subject: str, action: str, target: str) -> bytes:
        out = gid + exp.to_bytes(8, "big")
        for p in (subject, action, target):
            e = p.encode()
            out += len(e).to_bytes(4, "big") + e
        return out

    def grant(self, subject: str, action: str, target: str, *, verified: bool) -> str:
        """Mint a grant. ``verified`` must be the result of a fresh secret check by the caller."""
        if action not in ACTIONS:
            raise ValueError(f"unknown action {action!r}")
        if not verified:
            raise ReauthRequired("re-authentication failed")
        gid, exp = os.urandom(16), int(self._now()) + self._ttl
        tag = self._mac(self._msg(gid, exp, subject, action, target))
        return ".".join((_b64(gid), str(exp), _b64(tag)))

    def consume(self, token: str | None, subject: str, action: str, target: str) -> None:
        """Validate and burn a grant. Raises ReauthRequired on any mismatch."""
        try:
            g, e, t = (token or "").split(".")
            gid, exp, tag = _unb64(g), int(e), _unb64(t)
        except (ValueError, TypeError):
            raise ReauthRequired("re-authentication required") from None
        now = self._now()
        expected = self._mac(self._msg(gid, exp, subject, action, target))
        if not hmac.compare_digest(tag, expected) or exp < now:
            raise ReauthRequired("re-authentication required")
        for k, v in list(self._used.items()):
            if v < now:
                self._used.pop(k, None)
        if g in self._used:
            raise ReauthRequired("re-authentication required")
        self._used[g] = exp
