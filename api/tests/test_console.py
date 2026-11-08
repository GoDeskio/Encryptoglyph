import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from main import app


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("BUILD_SHA", "0123456789abcdef")
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
    app.state.store.reset()
    return TestClient(app)


def _session(client: TestClient) -> dict[str, str]:
    opened = client.post("/v1/sessions")
    assert opened.status_code == 200
    return {"x-eg-session": opened.json()["session_id"]}


def test_home_is_branded_and_health_stays_narrow(client: TestClient) -> None:
    page = client.get("/")
    assert page.status_code == 200
    assert "Seal the field" in page.text
    assert 'data-testid="hero"' in page.text
    health = client.get("/healthz")
    assert health.json() == {"status": "ok", "build": "0123456789ab"}
    for path in ("/docs", "/redoc", "/openapi.json", "/swagger"):
        assert client.get(path).status_code == 404


def test_seal_open_rewrap_and_shred_roundtrip(client: TestClient) -> None:
    headers = _session(client)
    created = client.post("/v1/keys", headers=headers)
    assert created.status_code == 200
    body = created.json()
    assert set(body) == {"kid", "fingerprint", "current"}
    assert len(body["fingerprint"]) == 32

    ctx = {
        "tenant": "acme",
        "purpose": "field",
        "table": "customers",
        "record_id": "42",
        "field": "email",
        "schema_version": 1,
    }
    secret = "ada@example.com"
    sealed = client.post(
        "/v1/seal",
        headers=headers,
        json={**ctx, "plaintext_b64": base64.b64encode(secret.encode()).decode()},
    )
    assert sealed.status_code == 200
    payload = sealed.json()
    assert secret not in json.dumps(payload)
    assert "key" not in payload

    opened = client.post("/v1/open", headers=headers, json={**ctx, "blob_b64": payload["blob_b64"]})
    assert base64.b64decode(opened.json()["plaintext_b64"]) == secret.encode()

    rotated = client.post("/v1/keys", headers=headers)
    assert rotated.json()["kid"] != body["kid"]
    rewrapped = client.post(
        "/v1/rewrap", headers=headers, json={**ctx, "blob_b64": payload["blob_b64"]}
    )
    assert rewrapped.status_code == 200
    assert rewrapped.json()["rewrapped"] is True
    assert rewrapped.json()["blob_b64"] != payload["blob_b64"]

    denied = client.post(
        "/v1/reauth",
        headers=headers,
        json={"kid": body["kid"], "confirm_fingerprint": "0" * 32},
    )
    assert denied.status_code == 403
    listed = client.get("/v1/keys", headers=headers).json()["keys"]
    old = next(row for row in listed if row["kid"] == body["kid"])
    grant = client.post(
        "/v1/reauth",
        headers=headers,
        json={"kid": body["kid"], "confirm_fingerprint": old["fingerprint"]},
    )
    assert grant.status_code == 200
    shredded = client.post(
        "/v1/shred", headers=headers, json={"kid": body["kid"], "grant": grant.json()["grant"]}
    )
    assert shredded.status_code == 200
    assert client.post(
        "/v1/open", headers=headers, json={**ctx, "blob_b64": payload["blob_b64"]}
    ).status_code == 400


def test_agent_never_echoes_secrets_and_runs_without_a_model(client: TestClient) -> None:
    planted = "hunter2-plaintext"
    rejected = client.post("/v1/agent", json={"message": "health", "password": planted})
    assert rejected.status_code == 400
    assert planted not in rejected.text

    leaked = client.post("/v1/agent", json={"message": f"password={planted}"})
    assert leaked.status_code == 200
    assert planted not in leaked.text
    assert leaked.json()["redacted"] is True

    health = client.post("/v1/agent", json={"message": "health"})
    assert health.json()["actions"] == [{"op": "health"}]
    moved = client.post("/v1/agent", json={"message": "go to keys"})
    assert moved.json()["actions"] == [{"op": "navigate", "view": "keys"}]


def test_ollama_receives_only_sanitized_text(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            raw = self.rfile.read(length).decode()
            seen["body"] = raw
            reply = json.dumps({"message": {"content": "health"}}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("OLLAMA_BASE_URL", f"http://127.0.0.1:{server.server_port}")
    try:
        response = client.post("/v1/agent", json={"message": "how does rotation work"})
    finally:
        server.shutdown()
    assert response.status_code == 200
    assert response.json()["actions"] == [{"op": "health"}]
    assert "hunter2" not in seen["body"]
    assert "how does rotation work" in seen["body"]


def test_backup_has_fingerprints_not_key_bytes(client: TestClient) -> None:
    headers = _session(client)
    client.post("/v1/keys", headers=headers)
    saved = client.post("/v1/backup", headers=headers)
    assert saved.status_code == 200
    assert "Key material is not" in saved.json()["note"]
    blob = base64.b64decode(saved.json()["blob_b64"])
    assert b"k1" not in blob or blob[:2] == b"EG"


def test_status_is_honest(client: TestClient) -> None:
    status = client.get("/v1/status").json()
    assert status["openbao"] == "not-connected"
    assert status["restic"] == "not-configured"
    assert status["aead"] == "XChaCha20-Poly1305"
    assert status["version"] == "0.2.0"
