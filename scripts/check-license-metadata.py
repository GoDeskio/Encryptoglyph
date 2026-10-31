#!/usr/bin/env python3
"""Fail unless license fields and Cargo package metadata say Apache-2.0."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

EXPECTED = "Apache-2.0"
SKIP_DIRS = {
    ".git",
    ".venv",
    "dist",
    "node_modules",
    "pkg",
    "target",
    "venv",
    "__pycache__",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def iter_files(root: Path, name: str) -> list[Path]:
    found: list[Path] = []
    for path in root.rglob(name):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        found.append(path)
    return sorted(found)


def license_text(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        text = value.get("text")
        if isinstance(text, str):
            return text
    return None


def check_cargo_toml(path: Path, root: Path, errors: list[str]) -> bool:
    data = tomllib.loads(path.read_text())
    package = data.get("package")
    if not isinstance(package, dict):
        return False
    rel = path.relative_to(root)
    lic = package.get("license")
    if lic != EXPECTED:
        errors.append(f"{rel}: [package].license is {lic!r}, expected {EXPECTED!r}")
    return True


def check_package_json(path: Path, root: Path, errors: list[str]) -> None:
    data = json.loads(path.read_text())
    rel = path.relative_to(root)
    lic = data.get("license")
    if lic != EXPECTED:
        errors.append(f"{rel}: license is {lic!r}, expected {EXPECTED!r}")


def check_pyproject(path: Path, root: Path, errors: list[str]) -> None:
    data = tomllib.loads(path.read_text())
    project = data.get("project")
    if not isinstance(project, dict):
        return
    rel = path.relative_to(root)
    lic = license_text(project.get("license"))
    if lic != EXPECTED:
        errors.append(
            f"{rel}: [project].license is {project.get('license')!r}, expected {EXPECTED!r}"
        )


def check_cargo_metadata(manifest: Path, root: Path, errors: list[str]) -> None:
    proc = subprocess.run(
        [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
            str(manifest),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    rel = manifest.relative_to(root)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout).strip().splitlines()
        detail = err[-1] if err else f"exit {proc.returncode}"
        errors.append(f"{rel}: cargo metadata failed: {detail}")
        return
    meta = json.loads(proc.stdout)
    manifest_resolved = manifest.resolve()
    matches = [
        pkg
        for pkg in meta.get("packages", [])
        if Path(pkg.get("manifest_path", "")).resolve() == manifest_resolved
    ]
    if len(matches) != 1:
        errors.append(f"{rel}: cargo metadata returned {len(matches)} packages for this manifest")
        return
    lic = matches[0].get("license")
    if lic != EXPECTED:
        errors.append(f"{rel}: cargo metadata license is {lic!r}, expected {EXPECTED!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-cargo-metadata",
        action="store_true",
        help="also require `cargo metadata` to report Apache-2.0",
    )
    args = parser.parse_args()
    root = repo_root()
    errors: list[str] = []

    cargo_manifests = [
        path
        for path in iter_files(root, "Cargo.toml")
        if check_cargo_toml(path, root, errors)
    ]
    package_jsons = iter_files(root, "package.json")
    pyprojects = iter_files(root, "pyproject.toml")
    if not cargo_manifests:
        errors.append("no Cargo.toml package manifests found")
    if not package_jsons:
        errors.append("no package.json files found")
    if not pyprojects:
        errors.append("no pyproject.toml files found")
    for path in package_jsons:
        check_package_json(path, root, errors)
    for path in pyprojects:
        check_pyproject(path, root, errors)

    if args.require_cargo_metadata:
        if shutil.which("cargo") is None:
            errors.append("cargo is not on PATH; cannot read package metadata")
        else:
            for manifest in cargo_manifests:
                check_cargo_metadata(manifest, root, errors)

    if errors:
        print("license metadata check failed:", file=sys.stderr)
        for err in errors:
            print(f"- {err}", file=sys.stderr)
        return 1

    checked = [str(path.relative_to(root)) for path in cargo_manifests + package_jsons + pyprojects]
    print(f"license metadata is {EXPECTED}: {', '.join(checked)}")
    if args.require_cargo_metadata:
        print("cargo metadata license is Apache-2.0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
