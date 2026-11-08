"""Deterministic assistant. An optional Ollama hop may only pick an action id.

The model is never shown plaintext, keys, or the raw user text when that text
looks like a secret. Replies are canned strings from this module.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

HELP = (
    "I can check health, create a key, open Seal, Keys, Custody, or Adopt, "
    "and check for updates. Plaintext and keys stay out of this chat. "
    "Use the Seal form for values."
)
SHRED = (
    "Shred a retired key from the Keys panel and confirm with its fingerprint. "
    "That fingerprint never belongs in chat."
)

_SECRET = re.compile(
    r"(?i)\b(password|secret|api[_ -]?key|token|seed|private key|plaintext)\b\s*[:=]"
)
_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_NAV = {
    "home": "home",
    "overview": "home",
    "seal": "seal",
    "keys": "keys",
    "custody": "custody",
    "agent": "agent",
    "adopt": "adopt",
    "integrate": "adopt",
    "integration": "adopt",
}
_ACTIONS = {
    "help",
    "health",
    "new-key",
    "update",
    "navigate:home",
    "navigate:seal",
    "navigate:keys",
    "navigate:custody",
    "navigate:agent",
    "navigate:adopt",
}


def _looks_secret(text: str) -> bool:
    if _SECRET.search(text) or _BLOB.search(text):
        return True
    return any(len(word) > 32 for word in text.split())


def sanitize(text: str) -> str | None:
    compact = " ".join(text.split())
    if not compact or len(compact) > 180 or _looks_secret(compact):
        return None
    return compact


def _reply(action: str) -> dict[str, object]:
    if action == "health":
        return {"reply": "Checking service health.", "actions": [{"op": "health"}], "redacted": False}
    if action == "new-key":
        return {
            "reply": "Creating a key. Only the fingerprint comes back.",
            "actions": [{"op": "new-key"}],
            "redacted": False,
        }
    if action == "update":
        return {
            "reply": "Checking the public release feed.",
            "actions": [{"op": "update"}],
            "redacted": False,
        }
    if action.startswith("navigate:"):
        view = action.split(":", 1)[1]
        return {
            "reply": f"Opening {view}.",
            "actions": [{"op": "navigate", "view": view}],
            "redacted": False,
        }
    return {"reply": HELP, "actions": [], "redacted": False}


def decide(message: str) -> dict[str, object]:
    """Map a chat line to a canned reply. `recognized` is false when Ollama may choose."""
    if _looks_secret(message or ""):
        return {"reply": HELP, "actions": [], "redacted": True, "recognized": True}
    text = sanitize(message or "")
    if text is None:
        return {"reply": HELP, "actions": [], "redacted": True, "recognized": True}
    low = text.lower().strip(" ?.!")
    if low in {"help", "what can you do", "what do you do"}:
        result = _reply("help")
    elif low in {"health", "status"}:
        result = _reply("health")
    elif low in {"new key", "create key", "create a key", "rotate", "rotate key"}:
        result = _reply("new-key")
    elif low in {"check updates", "check for updates", "updates", "update"}:
        result = _reply("update")
    elif low in {"shred", "shred key", "delete key"}:
        result = {"reply": SHRED, "actions": [], "redacted": False}
    elif low.startswith(("go to ", "open ", "show ")):
        target = low.split(" ", 2)[-1].strip()
        view = _NAV.get(target)
        result = _reply(f"navigate:{view}") if view else _reply("help")
        if view is None:
            result["recognized"] = False
            return result
    else:
        return {"reply": HELP, "actions": [], "redacted": False, "recognized": False, "safe": text}
    result["recognized"] = True
    return result


def ollama_action(base_url: str, safe_text: str, timeout: float = 2.0) -> str | None:
    """Ask Ollama for one action id. The prompt contains only sanitized text."""
    payload = {
        "model": os.environ.get("OLLAMA_MODEL", "llama3.2"),
        "stream": False,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are the Encryptoglyph assistant. You never see or request keys, "
                    "passwords, or plaintext. Reply with exactly one of: help, health, "
                    "new-key, update, navigate:home, navigate:seal, navigate:keys, "
                    "navigate:custody, navigate:agent, navigate:adopt."
                ),
            },
            {"role": "user", "content": safe_text},
        ],
    }
    request = urllib.request.Request(
        base_url.rstrip("/") + "/api/chat",
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode())
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return None
    content = str(body.get("message", {}).get("content", "")).strip().lower()
    first = content.split()[0] if content else ""
    if first in _ACTIONS:
        return first
    return None


def answer(message: str, ollama_base: str | None = None) -> dict[str, object]:
    chosen = decide(message)
    if chosen.get("recognized"):
        chosen.pop("safe", None)
        return chosen
    safe = str(chosen.get("safe") or "")
    base = ollama_base if ollama_base is not None else os.environ.get("OLLAMA_BASE_URL", "")
    if base and safe:
        action = ollama_action(base, safe)
        if action:
            resolved = _reply(action)
            resolved["recognized"] = True
            resolved["provider"] = "ollama"
            return resolved
    chosen.pop("safe", None)
    return chosen
