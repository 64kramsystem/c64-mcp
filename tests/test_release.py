"""Tests for tools/release.

Every refusal test satisfies all *other* preconditions, so no test can pass for
the wrong reason.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools import release  # noqa: E402

PYPROJECT = """[project]
name = "ghidra-mcp-c64"
version = "{version}"
"""

CHANGELOG = """# Changelog

## Unreleased

- A thing worth releasing.

## 0.98.0

- Older news.
"""


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", release.DEFAULT_BRANCH)
    git(root, "config", "user.email", "test@example.com")
    git(root, "config", "user.name", "Test")
    (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        PYPROJECT.format(version="0.99.0"), encoding="utf-8"
    )
    (root / "CHANGELOG.md").write_text(CHANGELOG, encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "initial")
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", str(remote))
    git(root, "remote", "add", "origin", str(remote))
    git(root, "push", "-q", "origin", release.DEFAULT_BRANCH)
    return root


def make_artifacts(
    repo: Path, version: str, *, metadata_version: str | None = None
) -> None:
    (repo / "dist").mkdir(exist_ok=True)
    wheel = repo / "dist" / f"ghidra_mcp_c64-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            f"ghidra_mcp_c64-{version}.dist-info/METADATA",
            "Metadata-Version: 2.4\n"
            "Name: ghidra-mcp-c64\n"
            f"Version: {metadata_version or version}\n",
        )
    (repo / "dist" / f"ghidra_mcp_c64-{version}.tar.gz").write_bytes(b"sdist")


def recording_runner(repo: Path, *, fail: str | None = None, build: bool = True):
    def runner(command, cwd):
        # Normalised: GATES/BUILD entries are tuples, and a tuple slice never
        # equals a list, so comparisons must not depend on the sequence type.
        parts = [str(part) for part in command]
        joined = " ".join(parts)
        if fail and fail in joined:
            raise release.ReleaseError(f"injected failure: {joined}")
        if parts[0] == "git":
            return release.run(command, cwd)
        if build and parts[:2] == ["uv", "build"]:
            make_artifacts(repo, release.read_version(repo))
            return ""
        return ""

    return runner


# ------------------------------------------------------------------- version


def test_version_comes_from_pyproject(repo: Path):
    assert release.read_version(repo) == "0.99.0"


def test_next_version_from_ninety_nine():
    assert release.next_version("0.99.0", "minor") == "0.100.0"
    assert release.next_version("0.99.0", "patch") == "0.99.1"


def test_write_version_updates_pyproject(repo: Path):
    written = release.write_version(repo, "0.100.0")

    assert release.read_version(repo) == "0.100.0"
    assert repo / "pyproject.toml" in written


def test_relock_is_skipped_without_a_lock_file(repo: Path):
    """The fixture has no uv.lock; write_version must not fail on that."""
    release.write_version(repo, "0.100.0")

    assert not (repo / "uv.lock").exists()


def test_write_version_regenerates_the_lock(
    repo: Path, monkeypatch: pytest.MonkeyPatch
):
    """uv.lock records this package's own version, so it must be refreshed.

    Testing relock() alone is not enough: it leaves the call site untested, so
    dropping relock() from write_version would go unnoticed.
    """
    calls: list[Path] = []
    monkeypatch.setattr(release, "relock", calls.append)

    release.write_version(repo, "0.100.0")

    assert calls == [repo]


def test_relock_runs_when_a_lock_exists(repo: Path, monkeypatch: pytest.MonkeyPatch):
    (repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(command, cwd, capture_output, text, check):
        calls.append(list(command))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(release.subprocess, "run", fake_run)
    release.relock(repo)

    assert calls == [["uv", "lock"]]


def test_relock_failure_is_a_release_error(repo: Path, monkeypatch: pytest.MonkeyPatch):
    (repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")

    def fake_run(command, cwd, capture_output, text, check):
        return subprocess.CompletedProcess(command, 1, "", "resolution failed")

    monkeypatch.setattr(release.subprocess, "run", fake_run)

    with pytest.raises(release.ReleaseError, match="uv lock failed"):
        release.relock(repo)


# ------------------------------------------------------------------ refusals


def test_refuses_a_dirty_tree(repo: Path):
    (repo / "CHANGELOG.md").write_text(CHANGELOG + "\n", encoding="utf-8")

    with pytest.raises(release.ReleaseError, match="not clean"):
        release.prepare(repo, "minor", recording_runner(repo))


def test_refuses_a_non_default_branch(repo: Path):
    git(repo, "checkout", "-qb", "feature")

    with pytest.raises(release.ReleaseError, match="releases run on"):
        release.prepare(repo, "minor", recording_runner(repo))


def test_refuses_an_empty_unreleased_section(repo: Path):
    (repo / "CHANGELOG.md").write_text(
        "# Changelog\n\n## Unreleased\n\n## 0.98.0\n\n- Older.\n", encoding="utf-8"
    )
    git(repo, "commit", "-aqm", "empty")

    with pytest.raises(release.ReleaseError, match="nothing to release"):
        release.prepare(repo, "minor", recording_runner(repo))


def test_refuses_a_tag_already_on_origin(repo: Path):
    git(repo, "tag", "v0.100.0")
    git(repo, "push", "-q", "origin", "v0.100.0")
    git(repo, "tag", "-d", "v0.100.0")

    with pytest.raises(release.ReleaseError, match="already exists on origin"):
        release.prepare(repo, "minor", recording_runner(repo))


# ------------------------------------------------------------- gate ordering


def test_gates_run_after_the_version_is_written(repo: Path):
    observed: list[str] = []

    def runner(command, cwd):
        if "pytest" in " ".join(str(part) for part in command):
            observed.append(release.read_version(repo))
            return ""
        return recording_runner(repo)(command, cwd)

    release.prepare(repo, "minor", runner)

    assert observed == ["0.100.0"]


def test_gates_run_through_uv_run_locked():
    """Dev tools live in a dependency group; bare commands would use PATH."""
    for gate in release.GATES:
        assert gate[0] == "uv"
        if gate[1] == "run":
            assert gate[2] == "--locked"


def test_a_failing_gate_leaves_the_repository_untouched(repo: Path):
    before_head = release.head_sha(repo)
    before = (repo / "pyproject.toml").read_text(encoding="utf-8")

    with pytest.raises(release.ReleaseError, match="injected failure"):
        release.prepare(repo, "minor", recording_runner(repo, fail="pytest"))

    assert release.head_sha(repo) == before_head
    assert (repo / "pyproject.toml").read_text(encoding="utf-8") == before
    assert git(repo, "status", "--porcelain").strip() == ""
    assert git(repo, "tag", "--list").strip() == ""


def test_a_failing_tag_resets_the_branch(repo: Path):
    before_head = release.head_sha(repo)

    with pytest.raises(release.ReleaseError, match="injected failure"):
        release.prepare(repo, "minor", recording_runner(repo, fail="git tag -a"))

    assert release.head_sha(repo) == before_head
    assert git(repo, "status", "--porcelain").strip() == ""


# ------------------------------------------------------------------ artifacts


def test_a_missing_artifact_fails_before_committing(repo: Path):
    before_head = release.head_sha(repo)

    with pytest.raises(release.ReleaseError, match="build did not produce"):
        release.prepare(repo, "minor", recording_runner(repo, build=False))

    assert release.head_sha(repo) == before_head


def test_wheel_metadata_is_checked_not_just_the_filename(repo: Path):
    """A correctly named wheel recording the wrong version must fail."""

    def runner(command, cwd):
        if [str(part) for part in command][:2] == ["uv", "build"]:
            make_artifacts(repo, "0.100.0", metadata_version="0.99.0")
            return ""
        return recording_runner(repo, build=False)(command, cwd)

    with pytest.raises(release.ReleaseError, match="does not record 0.100.0"):
        release.prepare(repo, "minor", runner)


# ------------------------------------------------------------------ changelog


def test_roll_inserts_the_new_unreleased_above_the_release(repo: Path):
    release.prepare(repo, "minor", recording_runner(repo))
    text = (repo / "CHANGELOG.md").read_text(encoding="utf-8")

    assert text.index("## Unreleased") < text.index("## 0.100.0")
    assert release.unreleased_section(repo / "CHANGELOG.md") == ""


def test_a_successful_run_commits_and_tags(repo: Path):
    version = release.prepare(repo, "minor", recording_runner(repo))

    assert version == "0.100.0"
    assert git(repo, "tag", "--list", "v0.100.0").strip() == "v0.100.0"
    assert git(repo, "log", "-1", "--format=%s").strip() == "Release 0.100.0"
    assert git(repo, "status", "--porcelain").strip() == ""


def test_there_is_no_publish_command():
    """Nothing consumes a c64 release; compatibility is a runtime handshake."""
    assert not hasattr(release, "publish")
    assert not hasattr(release, "write_manifest")
