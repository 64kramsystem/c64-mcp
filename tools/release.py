"""Version preparation for ghidra-mcp-c64.

`prepare` only: there is no `publish`. Nothing consumes a c64 release -- it runs
from a local venv path, and its compatibility with the connector rests on the
`c64.vice/1` runtime handshake rather than on matching versions. If a PyPI channel
ever appears, publishing can follow.

    tools/release prepare --minor    # gates, build, commit and tag
    git push origin HEAD && git push origin v<version>

The version is written before the gates run, so they see the mutation they exist
to catch. On failure the working tree, the index and the branch ref are restored,
so a failed run is a no-op.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

PRODUCT = "ghidra-mcp-c64"
DEFAULT_BRANCH = "main"

_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_PYPROJECT_VERSION_RE = re.compile(r'(?m)^(version = ")(\d+\.\d+\.\d+)(")$')
_UNRELEASED_RE = re.compile(r"(?m)^## Unreleased[ \t]*$")
_LEVEL_TWO_RE = re.compile(r"(?m)^## .+$")

Runner = Callable[[Sequence[str], Path], str]


class ReleaseError(RuntimeError):
    """A release was refused or failed; the repository is unchanged."""


# --------------------------------------------------------------------------- shell


def run(command: Sequence[str], cwd: Path) -> str:
    completed = subprocess.run(
        list(command), cwd=cwd, capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        raise ReleaseError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout}{completed.stderr}".rstrip()
        )
    return completed.stdout


# ------------------------------------------------------------------------- version


def next_version(current: str, bump: str) -> str:
    """Return the next semantic version.

    Note `0.99.0` + minor is `0.100.0`, not `1.0.0`: semver places no limit on a
    component's magnitude, and both Maven and PEP 440 compare them numerically.
    """
    match = _SEMVER_RE.fullmatch(current)
    if match is None:
        raise ReleaseError(f"current version is not semantic: {current!r}")
    major, minor, patch = (int(part) for part in match.groups())

    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    if bump == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ReleaseError(f"unknown bump: {bump!r}")


def read_version(repo_root: Path) -> str:
    """Read the version from `pyproject.toml`, the single source of truth.

    `__version__` derives from installed metadata, so it needs no writing here.
    """
    match = _PYPROJECT_VERSION_RE.search(
        (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    )
    if match is None:
        raise ReleaseError("pyproject.toml has no version")
    return match.group(2)


def write_version(repo_root: Path, version: str) -> list[Path]:
    """Write the version and refresh the lock, which pins this package too."""
    path = repo_root / "pyproject.toml"
    text = path.read_text(encoding="utf-8")
    updated, count = _PYPROJECT_VERSION_RE.subn(rf"\g<1>{version}\g<3>", text, count=1)
    if count != 1:
        raise ReleaseError("pyproject.toml has no version")
    path.write_text(updated, encoding="utf-8")

    relock(repo_root)
    written = [path]
    # Only report the lock as written when there is one: relock skips a checkout
    # that has never been locked, and staging a nonexistent path fails.
    lock = repo_root / "uv.lock"
    if lock.is_file():
        written.append(lock)
    return written


def relock(repo_root: Path) -> None:
    """Regenerate `uv.lock`, which records this package's own version.

    Skipped when there is no lock file, so the function stays usable in tests
    and in a checkout that has not been locked.
    """
    if not (repo_root / "uv.lock").is_file():
        return
    completed = subprocess.run(
        ["uv", "lock"], cwd=repo_root, capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        raise ReleaseError(f"uv lock failed:\n{completed.stderr.rstrip()}")


# ----------------------------------------------------------------------- changelog


def unreleased_section(changelog_path: Path) -> str:
    text = changelog_path.read_text(encoding="utf-8")
    headings = list(_UNRELEASED_RE.finditer(text))
    if len(headings) != 1:
        raise ReleaseError(
            "CHANGELOG.md must have exactly one ## Unreleased heading; "
            f"found {len(headings)}"
        )
    heading = headings[0]
    following = _LEVEL_TWO_RE.search(text, heading.end())
    end = following.start() if following else len(text)
    return text[heading.end() : end].strip()


def roll_changelog(changelog_path: Path, version: str) -> None:
    """Retitle `## Unreleased` as the version, with a fresh empty one above it.

    Above, not below: the retired CI job inserted the version heading directly
    beneath `## Unreleased`, and a later merge then filed a new entry underneath
    it — inside a release that did not contain it.
    """
    text = changelog_path.read_text(encoding="utf-8")
    section = unreleased_section(changelog_path)
    if not section:
        raise ReleaseError("## Unreleased is empty; nothing to release")

    heading = _UNRELEASED_RE.search(text)
    assert heading is not None
    updated = (
        text[: heading.start()]
        + "## Unreleased\n\n"
        + f"## {version}\n"
        + text[heading.end() :].lstrip("\n")
    )
    changelog_path.write_text(updated, encoding="utf-8")


# ----------------------------------------------------------------------------- git


def git_status_porcelain(repo_root: Path, runner: Runner = run) -> str:
    return runner(["git", "status", "--porcelain"], repo_root).strip()


def ensure_clean(repo_root: Path, runner: Runner = run) -> None:
    if git_status_porcelain(repo_root, runner):
        raise ReleaseError("working tree is not clean; commit or stash first")


def ensure_default_branch(repo_root: Path, runner: Runner = run) -> None:
    branch = runner(["git", "branch", "--show-current"], repo_root).strip()
    if branch != DEFAULT_BRANCH:
        raise ReleaseError(f"releases run on {DEFAULT_BRANCH}, not {branch!r}")


def head_sha(repo_root: Path, runner: Runner = run) -> str:
    return runner(["git", "rev-parse", "HEAD"], repo_root).strip()


def ensure_tag_absent(repo_root: Path, tag: str, runner: Runner = run) -> None:
    local = runner(["git", "tag", "--list", tag], repo_root).strip()
    if local:
        raise ReleaseError(f"tag {tag} already exists locally")
    remote = runner(["git", "ls-remote", "--tags", "origin", tag], repo_root).strip()
    if remote:
        raise ReleaseError(f"tag {tag} already exists on origin")


# ------------------------------------------------------------------------ manifest


@dataclass(frozen=True)
class Artifact:
    path: Path
    sha256: str

    def as_json(self) -> dict[str, str]:
        return {"name": self.path.name, "path": str(self.path), "sha256": self.sha256}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ------------------------------------------------------------------------- gates


# Run through `uv run --locked`: the dev tools are declared in a dependency
# group, so bare invocations would take whatever happens to be on PATH.
GATES: tuple[tuple[str, ...], ...] = (
    ("uv", "run", "--locked", "pytest"),
    ("uv", "run", "--locked", "ruff", "check"),
    ("uv", "run", "--locked", "mypy"),
    ("uv", "lock", "--check"),
)

BUILD: tuple[tuple[str, ...], ...] = (
    ("uv", "build"),
)


def expected_artifacts(repo_root: Path, version: str) -> list[Path]:
    return [
        repo_root / "dist" / f"ghidra_mcp_c64-{version}-py3-none-any.whl",
        repo_root / "dist" / f"ghidra_mcp_c64-{version}.tar.gz",
    ]


def verify_artifact_contents(repo_root: Path, version: str) -> list[Artifact]:
    """Check the wheel's recorded metadata, not just its filename."""
    artifacts = []
    for path in expected_artifacts(repo_root, version):
        if not path.is_file():
            raise ReleaseError(f"build did not produce {path}")
        artifacts.append(Artifact(path, sha256(path)))

    wheel = artifacts[0].path
    with zipfile.ZipFile(wheel) as archive:
        metadata = next(
            (
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            ),
            None,
        )
        if metadata is None:
            raise ReleaseError(f"{wheel.name} has no dist-info METADATA")
        recorded = archive.read(metadata).decode("utf-8")
    if f"Version: {version}" not in recorded:
        raise ReleaseError(f"{wheel.name} metadata does not record {version}")
    return artifacts


# ------------------------------------------------------------------------ prepare


def prepare(repo_root: Path, bump: str, runner: Runner = run) -> str:
    changelog = repo_root / "CHANGELOG.md"
    ensure_clean(repo_root, runner)
    ensure_default_branch(repo_root, runner)
    if not unreleased_section(changelog):
        raise ReleaseError("## Unreleased is empty; nothing to release")

    original_head = head_sha(repo_root, runner)
    current = read_version(repo_root)
    version = next_version(current, bump)
    tag = f"v{version}"
    ensure_tag_absent(repo_root, tag, runner)

    print(f"{current} -> {version}")
    committed = False
    try:
        written = [*write_version(repo_root, version), changelog]
        roll_changelog(changelog, version)

        for gate in GATES:
            print(f"gate: {' '.join(gate)}")
            runner(gate, repo_root)
        for step in BUILD:
            print(f"build: {' '.join(step)}")
            runner(step, repo_root)

        artifacts = verify_artifact_contents(repo_root, version)

        # Explicit paths, not `add -A`: the latter would stage build output and
        # anything else untracked into the release commit.
        staged = [str(path.relative_to(repo_root)) for path in written]
        runner(["git", "add", *staged], repo_root)
        runner(["git", "commit", "-m", f"Release {version}"], repo_root)
        committed = True
        del artifacts
        runner(
            ["git", "tag", "-a", tag, "-m", unreleased_or_version(changelog, version)],
            repo_root,
        )
    except BaseException:
        _rollback(repo_root, original_head, committed, runner)
        raise

    print(
        f"\nprepared {tag}. Now:\n  git push origin HEAD\n  git push origin {tag}\n"
        "\nThere is no publish step: nothing consumes a c64 release."
    )
    return version


def unreleased_or_version(changelog: Path, version: str) -> str:
    """Tag message: the released section, falling back to the bare version."""
    text = changelog.read_text(encoding="utf-8")
    match = re.search(rf"(?m)^## {re.escape(version)}[ \t]*$", text)
    if match is None:
        return version
    following = _LEVEL_TWO_RE.search(text, match.end())
    end = following.start() if following else len(text)
    return f"{version}\n\n{text[match.end():end].strip()}"


def _rollback(
    repo_root: Path,
    original_head: str,
    committed: bool,
    runner: Runner,
) -> None:
    """Restore worktree, index and refs. A failed release must be a no-op."""
    if committed:
        # Only move the branch if HEAD is still the commit this run created.
        current = head_sha(repo_root, runner)
        if current != original_head:
            runner(["git", "reset", "--hard", original_head], repo_root)
    else:
        # Unstage anything the failed commit left in the index, then restore the
        # tracked files. `reset --hard` is confined to tracked content, so build
        # output stays where it is.
        runner(["git", "reset", "-q", "HEAD"], repo_root)
        runner(["git", "checkout", "--", "."], repo_root)


# ---------------------------------------------------------------------------- cli


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"{PRODUCT} release")
    sub = parser.add_subparsers(dest="command", required=True)

    prepare_parser = sub.add_parser(
        "prepare", help="gate, build, commit and tag a release"
    )
    group = prepare_parser.add_mutually_exclusive_group(required=True)
    for bump in ("major", "minor", "patch"):
        group.add_argument(f"--{bump}", action="store_const", const=bump, dest="bump")

    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        prepare(repo_root, args.bump)
    except ReleaseError as error:
        print(f"release refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
