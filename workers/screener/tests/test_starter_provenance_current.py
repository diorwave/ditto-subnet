"""Keep the newest trusted starter manifest equal to the monorepo starter kit."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.generate_starter_provenance import (
    REGENERATE_COMMAND,
    tracked_starter_files,
)

SCREENER_ROOT = Path(__file__).resolve().parents[1]
STARTER_KIT = SCREENER_ROOT.parents[1] / "miners/dittobench-starter-kit"
MANIFESTS = SCREENER_ROOT / "ditto_screener/data"
GENERATOR = SCREENER_ROOT / "scripts/generate_starter_provenance.py"


def _manifest_number(path: Path) -> int:
    match = re.fullmatch(r"starter-kit-provenance-v(\d+)\.json", path.name)
    assert match is not None, path.name
    return int(match.group(1))


def newest_manifest(directory: Path = MANIFESTS) -> Path:
    return max(directory.glob("starter-kit-provenance-*.json"), key=_manifest_number)


def assert_manifest_current(kit: Path, manifest: Path) -> None:
    expected = json.loads(manifest.read_text())["files"]
    actual = tracked_starter_files(kit)
    if actual == expected:
        return
    modified = sorted(
        path
        for path in actual.keys() & expected.keys()
        if actual[path] != expected[path]
    )
    pytest.fail(
        f"{manifest.name} no longer matches {kit.name}: "
        f"modified={modified} added={sorted(actual.keys() - expected.keys())} "
        f"removed={sorted(expected.keys() - actual.keys())}. Screener reviewers "
        "would attribute these first-party files to the miner. Commit the "
        "starter-kit change, then run from the repository root:\n"
        + REGENERATE_COMMAND.format(version=_manifest_number(manifest) + 1),
        pytrace=False,
    )


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=root,
        check=True,
        stdout=subprocess.DEVNULL,
    )


def _starter_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    kit = repo / "kit"
    for relative, content in {
        "src/lib.rs": "fn tracked() {}\n",
        ".env.example": "OPENROUTER_API_KEY=\n",
        ".env": "OPENROUTER_API_KEY=secret\n",
        ".env.local": "OPENROUTER_API_KEY=secret\n",
        ".agents/skills/mine/SKILL.md": "skill\n",
        "target/debug/artifact": "build\n",
        "local.db": "db\n",
        "submission.tgz": "archive\n",
    }.items():
        path = kit / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    (kit / ".claude").mkdir()
    (kit / ".claude/skills").symlink_to("../.agents/skills")
    _git(repo, "init", "-q")
    _git(repo, "add", "-f", "kit")
    _git(repo, "commit", "-q", "-m", "kit")
    (kit / "untracked.rs").write_text("fn untracked() {}\n")
    return kit


def _generate(kit: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            "--starter-dir",
            str(kit),
            "--output",
            str(output),
        ],
        text=True,
        capture_output=True,
    )


def test_newest_manifest_covers_current_starter_kit() -> None:
    if not STARTER_KIT.is_dir():
        pytest.skip("the monorepo starter kit is not part of this checkout")
    assert_manifest_current(STARTER_KIT, newest_manifest())


def test_drift_guard_fails_with_regenerate_command(tmp_path: Path) -> None:
    kit = _starter_repo(tmp_path)
    manifest = tmp_path / "starter-kit-provenance-v6.json"
    manifest.write_text(json.dumps({"files": tracked_starter_files(kit)}))
    assert_manifest_current(kit, manifest)
    (kit / "src/lib.rs").write_text("fn tracked() {} \n")

    with pytest.raises(pytest.fail.Exception) as failure:
        assert_manifest_current(kit, manifest)

    message = str(failure.value)
    assert "modified=['src/lib.rs']" in message
    assert "generate_starter_provenance.py" in message
    assert "starter-kit-provenance-v7.json" in message


def test_generator_excludes_dev_skills_and_env(tmp_path: Path) -> None:
    kit = _starter_repo(tmp_path)

    assert sorted(tracked_starter_files(kit)) == [".env.example", "src/lib.rs"]


def test_generator_is_reproducible_and_pins_last_kit_commit(tmp_path: Path) -> None:
    kit = _starter_repo(tmp_path)
    kit_revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=kit,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    (kit.parent / "unrelated.txt").write_text("outside the kit\n")
    _git(kit.parent, "add", "unrelated.txt")
    _git(kit.parent, "commit", "-q", "-m", "unrelated")
    outputs = [tmp_path / "first.json", tmp_path / "second.json"]

    for output in outputs:
        assert _generate(kit, output).returncode == 0

    assert outputs[0].read_bytes() == outputs[1].read_bytes()
    payload = json.loads(outputs[0].read_text())
    assert payload["revision"] == kit_revision
    assert payload["version"] == 1
    assert (
        payload["origin"]
        == "ditto-assistant/ditto-subnet/miners/dittobench-starter-kit"
    )

    (kit / "src/lib.rs").write_text("fn uncommitted() {}\n")
    dirty = _generate(kit, outputs[0])
    assert dirty.returncode != 0
    assert "commit starter-kit changes" in dirty.stderr
