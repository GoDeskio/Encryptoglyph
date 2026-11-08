import io
import tarfile
from pathlib import Path

import pytest

from eg_api.updater import allowed_tarball, check_release, extract_tarball, parse_version


def test_release_check_ignores_foreign_urls() -> None:
    def fetch(_url: str) -> tuple[int, dict]:
        return 200, {
            "tag_name": "v0.3.0",
            "tarball_url": "https://evil.example/tarball/v0.3.0",
        }

    report = check_release("0.2.0", fetch)
    assert report["update_available"] is True
    assert report["url"] is None
    assert allowed_tarball("https://api.github.com/repos/GoDeskio/Encryptoglyph/tarball/v0.3.0")
    assert not allowed_tarball("https://api.github.com/repos/GoDeskio/Encryptoglyph/tarball/v0.3.0/../../etc")


def test_extract_rejects_parent_paths(tmp_path: Path) -> None:
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as archive:
        payload = b"nope"
        info = tarfile.TarInfo("../evil.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    with pytest.raises(ValueError):
        extract_tarball(blob.getvalue(), tmp_path / "out")
    assert not (tmp_path / "evil.txt").exists()


def test_extract_writes_a_safe_member(tmp_path: Path) -> None:
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as archive:
        payload = b"encryptoglyph"
        info = tarfile.TarInfo("encryptoglyph-0.2.0/VERSION")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    dest = tmp_path / "out"
    extract_tarball(blob.getvalue(), dest)
    assert (dest / "encryptoglyph-0.2.0" / "VERSION").read_bytes() == b"encryptoglyph"


def test_parse_version() -> None:
    assert parse_version("v0.2.0") == (0, 2, 0)
    with pytest.raises(ValueError):
        parse_version("latest")
