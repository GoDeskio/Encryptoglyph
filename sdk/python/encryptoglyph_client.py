"""Small client for the Encryptoglyph sidecar. No extra dependencies."""

from __future__ import annotations

import base64
import json
import urllib.request


class Encryptoglyph:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.session_id = ""

    def session(self) -> str:
        opened = self._json("POST", "/v1/sessions", {})
        self.session_id = str(opened["session_id"])
        return self.session_id

    def seal(self, ctx: dict, plaintext: bytes) -> dict:
        body = dict(ctx)
        body["plaintext_b64"] = base64.b64encode(plaintext).decode()
        return self._json("POST", "/v1/seal", body)

    def open(self, ctx: dict, blob_b64: str) -> bytes:
        body = dict(ctx)
        body["blob_b64"] = blob_b64
        opened = self._json("POST", "/v1/open", body)
        return base64.b64decode(opened["plaintext_b64"])

    def _json(self, method: str, path: str, body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body).encode()
        headers = {"content-type": "application/json"}
        if self.session_id:
            headers["x-eg-session"] = self.session_id
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode())
