"""Version check and tarball fetch for GoDeskio/Encryptoglyph releases.

The updater talks only to the GitHub API for this repository. It refuses any
other host, does not run downloaded code, and rejects archive members that
leave the destination directory.
"""

from __future__ import annotations

import io
import json
import tarfile
from collections.abc import Callable
from pathlib import Path
from urllib.request import Request, urlopen

REPO = "GoDeskio/Encryptoglyph"
RELEASES = f"https://api.github.com/repos/{REPO}/releases/latest"
_TARBALL_PREFIX = f"https://api.github.com/repos/{REPO}/tarball/"


def parse_version(value: str) -> tuple[int, int, int]:
    text = value.strip().lstrip("v")
    parts = text.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise ValueError("bad version")
    return int(parts[0]), int(parts[1]), int(parts[2])


def read_version(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def allowed_tarball(url: str) -> bool:
    if not url.startswith(_TARBALL_PREFIX):
        return False
    rest = url[len(_TARBALL_PREFIX) :]
    return bool(rest) and ".." not in rest and "/" not in rest and " " not in rest


def check_release(current: str, fetch: Callable[[str], tuple[int, dict]]) -> dict[str, object]:
    unknown = {
        "current": current,
        "latest": None,
        "update_available": False,
        "state": "unknown",
        "url": None,
    }
    try:
        status, payload = fetch(RELEASES)
    except (OSError, ValueError, TimeoutError):
        return unknown
    if status != 200 or not isinstance(payload, dict):
        return unknown
    latest = str(payload.get("tag_name") or "").lstrip("v")
    try:
        newer = parse_version(latest) > parse_version(current)
    except ValueError:
        return unknown
    url = payload.get("tarball_url") if isinstance(payload.get("tarball_url"), str) else ""
    safe = url if isinstance(url, str) and allowed_tarball(url) else None
    return {
        "current": current,
        "latest": latest,
        "update_available": newer,
        "state": "available" if newer else "current",
        "url": safe,
    }


def github_fetch(url: str, timeout: float = 5.0) -> tuple[int, dict]:
    if url != RELEASES and not allowed_tarball(url):
        raise ValueError("refusing url")
    request = Request(url, headers={"accept": "application/vnd.github+json", "user-agent": "encryptoglyph-updater"})
    with urlopen(request, timeout=timeout) as response:
        return response.status, json.loads(response.read().decode())


def download_tarball(url: str, timeout: float = 20.0) -> bytes:
    if not allowed_tarball(url):
        raise ValueError("refusing url")
    request = Request(url, headers={"user-agent": "encryptoglyph-updater", "accept": "application/vnd.github+json"})
    with urlopen(request, timeout=timeout) as response:
        blob = response.read()
    if blob[:2] != b"\x1f\x8b":
        raise ValueError("not a gzip tarball")
    return blob


def extract_tarball(blob: bytes, dest: Path) -> None:
    """Extract a release tree into a new directory. No links, no parent paths."""
    if blob[:2] != b"\x1f\x8b":
        raise ValueError("not a gzip tarball")
    if dest.exists():
        raise ValueError("destination exists")
    dest.mkdir()
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            parts = Path(member.name).parts
            if member.islnk() or member.issym() or member.name.startswith("/") or ".." in parts:
                raise ValueError("unsafe path")
        archive.extractall(dest, members=members, filter="data")
