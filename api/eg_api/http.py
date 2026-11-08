"""Versioned HTTP surface and the Encryptoglyph console."""

from __future__ import annotations

import base64
import hmac
import json
import os
import re
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from eg_crypto import (
    DecryptError,
    DowngradeError,
    RecordContext,
    decrypt,
    encrypt,
    needs_rewrap,
    rewrap,
)
from eg_crypto.envelope import blind_index, fingerprint
from eg_crypto.reauth import ReauthGate, ReauthRequired

from .agent import answer
from .store import Store
from .updater import check_release, github_fetch, read_version

_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
_FORBIDDEN = {
    "plaintext",
    "plaintext_b64",
    "key",
    "key_hex",
    "password",
    "secret",
    "dek",
    "seed",
    "share",
    "private_key",
}
_SECURITY = {
    "content-security-policy": (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
}


def _here() -> Path:
    return Path(__file__).resolve()


def locate_version() -> Path:
    here = _here()
    for path in (here.parents[1] / "VERSION", here.parents[2] / "VERSION"):
        if path.is_file():
            return path
    return here.parents[2] / "VERSION"


def locate_console() -> Path:
    here = _here()
    for path in (here.parents[1] / "console", here.parents[2] / "console"):
        if (path / "index.html").is_file():
            return path
    return here.parents[2] / "console"


def _fail(status: int, error: str) -> JSONResponse:
    return JSONResponse({"error": error}, status_code=status)


def _b64(value: object, limit: int) -> bytes | None:
    if not isinstance(value, str) or not value or len(value) > limit:
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return None
    if len(raw) > 65536:
        return None
    return raw


def _context(body: dict) -> RecordContext | None:
    values: dict[str, str] = {}
    for name in ("tenant", "purpose", "table", "record_id", "field"):
        value = body.get(name, "")
        if not isinstance(value, str) or not _ID.fullmatch(value):
            return None
        values[name] = value
    schema = body.get("schema_version", 1)
    if isinstance(schema, bool) or not isinstance(schema, int) or not 1 <= schema <= 1000:
        return None
    return RecordContext(
        values["tenant"],
        values["purpose"],
        values["table"],
        values["record_id"],
        values["field"],
        schema,
    )


class _Headers(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.update(_SECURITY)
        response.headers["x-encryptoglyph-api"] = "1"
        return response


def create_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(_Headers)
    app.state.store = Store()
    app.state.gate = ReauthGate(os.urandom(32))
    app.state.version = read_version(locate_version())
    console = locate_console()
    app.mount("/static", StaticFiles(directory=console), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(console / "index.html")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        build = os.environ.get("BUILD_SHA", "")[:12]
        return {"status": "ok", "build": build}

    @app.get("/v1/status")
    def status() -> dict[str, object]:
        return {
            "product": "Encryptoglyph",
            "version": app.state.version,
            "api": "v1",
            "aead": "XChaCha20-Poly1305",
            "kdf": "HKDF-SHA256",
            "password_kdf": "Argon2id",
            "custody": "process-memory",
            "openbao": "not-connected",
            "restic": "not-configured",
            "agent": "deterministic",
            "ollama": bool(os.environ.get("OLLAMA_BASE_URL")),
        }

    @app.get("/v1/integration")
    def integration() -> dict[str, str]:
        return {
            "version": app.state.version,
            "api": "v1",
            "python": (
                "from eg_crypto import Keyring, RecordContext, encrypt, decrypt\n"
                "kr = Keyring({kid: key}, kid)\n"
                "blob = encrypt(kr, RecordContext(tenant, purpose, table, record_id, field), plaintext)"
            ),
            "http": (
                "eg = Encryptoglyph(os.environ['EG_URL'])\n"
                "eg.session()\n"
                "sealed = eg.seal(ctx, plaintext)"
            ),
        }

    @app.get("/v1/update")
    def update_check() -> dict[str, object]:
        return check_release(app.state.version, github_fetch)

    @app.post("/v1/sessions")
    def open_session() -> JSONResponse:
        try:
            sid, session = app.state.store.create()
        except RuntimeError:
            return _fail(503, "busy")
        return JSONResponse({"session_id": sid, "expires_unix": int(session.expires)})

    def _session(request: Request):
        token = request.headers.get("x-eg-session", "")
        session = app.state.store.get(token)
        if session is None:
            return None, None
        return token, session

    @app.post("/v1/keys")
    def create_key(request: Request) -> JSONResponse:
        _token, session = _session(request)
        if session is None:
            return _fail(401, "session required")
        try:
            kid, fp = session.add_key()
        except ValueError:
            return _fail(400, "too many keys")
        return JSONResponse({"kid": kid, "fingerprint": fp, "current": True})

    @app.get("/v1/keys")
    def list_keys(request: Request) -> JSONResponse:
        _token, session = _session(request)
        if session is None:
            return _fail(401, "session required")
        return JSONResponse({"keys": session.public_keys()})

    @app.post("/v1/seal")
    def seal(request: Request, body: dict) -> JSONResponse:
        _token, session = _session(request)
        if session is None:
            return _fail(401, "session required")
        ctx = _context(body)
        raw = _b64(body.get("plaintext_b64"), 90_000)
        if ctx is None or raw is None:
            return _fail(400, "invalid payload")
        if not session.current:
            try:
                session.add_key()
            except ValueError:
                return _fail(400, "too many keys")
        try:
            blob = encrypt(session.keyring(), ctx, raw)
        except (LookupError, ValueError):
            return _fail(400, "invalid payload")
        kid = session.current or ""
        material = session.keys.get(kid, bytearray())
        return JSONResponse(
            {
                "blob_b64": base64.b64encode(blob).decode(),
                "kid": kid,
                "fingerprint": fingerprint(bytes(material)) if material else "",
                "version": 3,
                "plaintext_bytes": len(raw),
            }
        )

    @app.post("/v1/open")
    def open_blob(request: Request, body: dict) -> JSONResponse:
        _token, session = _session(request)
        if session is None:
            return _fail(401, "session required")
        ctx = _context(body)
        blob = _b64(body.get("blob_b64"), 180_000)
        if ctx is None or blob is None:
            return _fail(400, "invalid payload")
        try:
            plain = decrypt(session.keyring(), ctx, blob)
        except DowngradeError:
            return _fail(400, "envelope version below minimum")
        except (DecryptError, LookupError, ValueError):
            return _fail(400, "decryption failed")
        return JSONResponse(
            {"plaintext_b64": base64.b64encode(bytes(plain)).decode(), "bytes": len(plain)}
        )

    @app.post("/v1/rewrap")
    def rewrap_blob(request: Request, body: dict) -> JSONResponse:
        _token, session = _session(request)
        if session is None:
            return _fail(401, "session required")
        ctx = _context(body)
        blob = _b64(body.get("blob_b64"), 180_000)
        if ctx is None or blob is None:
            return _fail(400, "invalid payload")
        try:
            ring = session.keyring()
            upgraded = needs_rewrap(ring, blob)
            fresh = rewrap(ring, ctx, blob) if upgraded else blob
        except (DecryptError, DowngradeError, LookupError, ValueError):
            return _fail(400, "decryption failed")
        return JSONResponse(
            {
                "blob_b64": base64.b64encode(fresh).decode(),
                "rewrapped": bool(upgraded),
                "kid": session.current,
            }
        )

    @app.post("/v1/blind-index")
    def blind(request: Request, body: dict) -> JSONResponse:
        _token, session = _session(request)
        if session is None:
            return _fail(401, "session required")
        tenant = body.get("tenant", "")
        field = body.get("field", "")
        value = body.get("value", "")
        if (
            not isinstance(tenant, str)
            or not isinstance(field, str)
            or not isinstance(value, str)
            or not _ID.fullmatch(tenant)
            or not _ID.fullmatch(field)
            or not value
            or len(value) > 500
        ):
            return _fail(400, "invalid payload")
        if not session.current:
            return _fail(400, "create a key first")
        try:
            key = session.keyring().derive(session.current, "blind-index", tenant, 2)
        except (LookupError, ValueError, DecryptError):
            return _fail(400, "invalid payload")
        digest = blind_index(key, tenant, field, value)
        return JSONResponse({"index_b64": base64.b64encode(digest).decode(), "bytes": len(value)})

    @app.post("/v1/backup")
    def backup(request: Request) -> JSONResponse:
        _token, session = _session(request)
        if session is None:
            return _fail(401, "session required")
        if not session.current:
            return _fail(400, "create a key first")
        manifest = json.dumps(
            {"product": "Encryptoglyph", "version": app.state.version, "keys": session.public_keys()},
            separators=(",", ":"),
        ).encode()
        ctx = RecordContext("local", "backup", "inventory", "manifest", "json", 1)
        try:
            blob = encrypt(session.keyring(), ctx, manifest)
        except (LookupError, ValueError):
            return _fail(400, "invalid payload")
        return JSONResponse(
            {
                "blob_b64": base64.b64encode(blob).decode(),
                "filename": "encryptoglyph-inventory.eg",
                "note": "Sealed inventory of fingerprints. Key material is not in this file.",
            }
        )

    @app.post("/v1/reauth")
    def reauth(request: Request, body: dict) -> JSONResponse:
        token, session = _session(request)
        if session is None or token is None:
            return _fail(401, "session required")
        kid = body.get("kid", "")
        confirm = body.get("confirm_fingerprint", "")
        if not isinstance(kid, str) or not isinstance(confirm, str) or kid not in session.keys:
            return _fail(400, "invalid payload")
        expected = fingerprint(bytes(session.keys[kid]))
        if not hmac.compare_digest(confirm.encode(), expected.encode()):
            return _fail(403, "confirmation did not match")
        try:
            grant = app.state.gate.grant(token, "key.shred", kid, verified=True)
        except ReauthRequired:
            return _fail(403, "confirmation did not match")
        return JSONResponse({"grant": grant})

    @app.post("/v1/shred")
    def shred(request: Request, body: dict) -> JSONResponse:
        token, session = _session(request)
        if session is None or token is None:
            return _fail(401, "session required")
        kid = body.get("kid", "")
        grant = body.get("grant", "")
        if not isinstance(kid, str) or not isinstance(grant, str):
            return _fail(400, "invalid payload")
        try:
            app.state.gate.consume(grant, token, "key.shred", kid)
            fp = session.shred(kid)
        except ReauthRequired:
            return _fail(403, "re-authentication required")
        except ValueError:
            return _fail(400, "cannot shred the current key")
        return JSONResponse({"shredded": kid, "fingerprint": fp})

    @app.post("/v1/agent")
    def agent(body: dict) -> JSONResponse:
        if not isinstance(body, dict) or _FORBIDDEN.intersection(body):
            return _fail(400, "redacted")
        message = body.get("message", "")
        if not isinstance(message, str) or len(message) > 2000:
            return _fail(400, "invalid request")
        result = answer(message)
        result.pop("safe", None)
        return JSONResponse(result)

    return app
