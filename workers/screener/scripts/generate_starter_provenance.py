#!/usr/bin/env python3
"""Generate the pinned starter-kit file provenance index.

Commit any ``miners/dittobench-starter-kit`` change, then run
``REGENERATE_COMMAND`` from the repository root with the next manifest number.
``tests/test_starter_provenance_current.py`` fails until the newest manifest
matches the kit again. Keep older manifests so older honest derivatives match.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import subprocess
from pathlib import Path, PurePosixPath

ORIGIN = "ditto-assistant/ditto-subnet/miners/dittobench-starter-kit"
REGENERATE_COMMAND = (
    "python workers/screener/scripts/generate_starter_provenance.py "
    "--starter-dir miners/dittobench-starter-kit "
    "--output workers/screener/ditto_screener/data/"
    "starter-kit-provenance-v{version}.json"
)
# Mirror the starter `submit` tar excludes so the manifest never trusts local
# state or development skills that an honest submission never contains.
_EXCLUDED_PARTS = frozenset({".agents", ".claude", ".git", "target"})
_EXCLUDED_NAMES = (".env", ".env.*", "*.db", "*.db-*", "*.tgz", "*.tar")
_COMMITTED_TEMPLATES = frozenset({".env.example"})


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--starter-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _excluded(relative: str) -> bool:
    for part in PurePosixPath(relative).parts:
        if part in _EXCLUDED_PARTS:
            return True
        if part not in _COMMITTED_TEMPLATES and any(
            fnmatch.fnmatchcase(part, pattern) for pattern in _EXCLUDED_NAMES
        ):
            return True
    return False


def tracked_starter_files(root: Path) -> dict[str, str]:
    """Map each Git-tracked, submittable regular starter file to its sha256."""
    raw = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    files: dict[str, str] = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        relative = item.decode("utf-8")
        path = root / relative
        if path.is_file() and not path.is_symlink() and not _excluded(relative):
            files[relative] = _sha256(path)
    return files


def starter_revision(root: Path) -> str:
    """Return the last commit that touched the kit, so reruns are byte-stable."""
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no", "--", "."],
        cwd=root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout
    if dirty:
        raise ValueError("commit starter-kit changes before generating provenance")
    revision = subprocess.run(
        ["git", "log", "-1", "--format=%H", "--", "."],
        cwd=root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    if len(revision) != 40:
        raise ValueError("starter revision is not a full Git SHA")
    return revision


def main() -> int:
    args = _arguments()
    root = args.starter_dir.resolve()
    payload = {
        "files": tracked_starter_files(root),
        "origin": ORIGIN,
        "revision": starter_revision(root),
        "version": 1,
    }
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
