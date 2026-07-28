"""Scripted releases for c64-mcp.

One command:

    tools/release minor        # or major / patch

A release tags its own commit `v<version>`, so a HEAD already carrying such a tag
has nothing to release: the run says so and exits 0 without touching anything.
Only `v<semver>` counts; a tag in any other scheme is not a release.

Otherwise it refuses unless the checkout is on the default branch, clean, and
exactly in sync with origin. Then it writes the version, regenerates the lock,
rolls the changelog, runs the runtime tests, builds the release candidate,
commits, tags, and pushes the branch and the tag.

The final step publishes versioned artifacts to PyPI. Compatibility with the
connector rests on the `c64.vice/1` runtime handshake rather than matching versions.

Everything fallible happens *before* the push, because the push is a one-way
door. Until then a failure restores the working tree, the index and the branch
ref, so a failed release is a no-op.
"""


from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

PRODUCT = "c64-mcp"
DEFAULT_BRANCH = "main"
PUBLISH_TOKEN_ENV = "UV_PUBLISH_TOKEN"
# Skips files already on the index, so re-running after a partial upload
# does not fail on duplicates.
PUBLISH_CHECK_URL = "https://pypi.org/simple/c64-mcp/"

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


def ensure_in_sync_with_origin(repo_root: Path, runner: Runner = run) -> None:
    """Refuse unless the branch matches origin exactly.

    Releasing something the remote does not have, or missing something it does,
    produces a tag whose contents nobody else can reproduce.
    """
    runner(["git", "fetch", "--quiet", "origin", DEFAULT_BRANCH], repo_root)
    ahead_behind = runner(
        ["git", "rev-list", "--left-right", "--count",
         f"origin/{DEFAULT_BRANCH}...HEAD"],
        repo_root,
    ).split()
    if len(ahead_behind) != 2:
        raise ReleaseError("cannot compare HEAD with origin")
    behind, ahead = (int(value) for value in ahead_behind)
    if behind or ahead:
        raise ReleaseError(
            f"HEAD is {ahead} ahead and {behind} behind origin/{DEFAULT_BRANCH}; "
            "push or pull first"
        )


def head_release_tag(repo_root: Path, runner: Runner = run) -> str | None:
    """The version already released at HEAD, if any.

    A release tags its own commit, so a tagged HEAD has nothing left to release.
    Only `v<semver>` counts: a tag in any other scheme is not a release of this
    line.
    """
    for tag in runner(
        ["git", "tag", "--points-at", "HEAD", "--list", "v*"], repo_root
    ).split():
        if _SEMVER_RE.fullmatch(tag[1:]):
            return tag[1:]
    return None


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


GATES: tuple[tuple[str, ...], ...] = (
    # Resolve pytest from the declared development dependencies, not ambient PATH.
    ("uv", "run", "--locked", "pytest"),
)

BUILD: tuple[tuple[str, ...], ...] = (
    ("uv", "build"),
)


def expected_artifacts(repo_root: Path, version: str) -> list[Path]:
    return [
        repo_root / "dist" / f"c64_mcp-{version}-py3-none-any.whl",
        repo_root / "dist" / f"c64_mcp-{version}.tar.gz",
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


def ensure_publish_token() -> None:
    """Refuse before anything irreversible if the PyPI token is absent.

    Checked up front, not at publish time: the push and the tag come earlier and
    cannot be retracted, so discovering a missing token afterwards would leave a
    released tag with nothing on PyPI. It sits just below the already-released
    check, which needs no token because it publishes nothing.
    """
    if not os.environ.get(PUBLISH_TOKEN_ENV):
        raise ReleaseError(
            f"{PUBLISH_TOKEN_ENV} is not set; a release publishes to PyPI. "
            f"Export a token scoped to {PRODUCT} and re-run."
        )


def release(repo_root: Path, bump: str, runner: Runner = run) -> str:
    """Cut a release: test, build, commit, tag, push, and publish."""
    ensure_default_branch(repo_root, runner)
    ensure_clean(repo_root, runner)

    released = head_release_tag(repo_root, runner)
    if released is not None:
        print(f"HEAD is already tagged v{released}; nothing to release")
        return released

    # After the skip: a run with nothing to release needs no PyPI token. Still
    # before everything irreversible, which is what the check is for.
    ensure_publish_token()
    ensure_in_sync_with_origin(repo_root, runner)

    version = prepare(repo_root, bump, runner)
    tag = f"v{version}"

    # The one-way door. Everything that can fail locally has already run.
    print(f"push: origin HEAD and {tag}")
    runner(["git", "push", "origin", "HEAD"], repo_root)
    runner(["git", "push", "origin", tag], repo_root)

    # Explicit paths, not the whole of dist/: `uv publish` would otherwise upload
    # stale artifacts left there by earlier builds.
    artifacts = [str(path) for path in expected_artifacts(repo_root, version)]
    print(f"publish: {PRODUCT} {version} to PyPI")
    runner(["uv", "publish", "--check-url", PUBLISH_CHECK_URL, *artifacts], repo_root)

    print(f"released {tag} and published {PRODUCT} {version}")
    return version


def prepare(repo_root: Path, bump: str, runner: Runner = run) -> str:
    changelog = repo_root / "CHANGELOG.md"
    if not unreleased_section(changelog):
        raise ReleaseError("## Unreleased is empty; nothing to release")

    original_head = head_sha(repo_root, runner)
    current = read_version(repo_root)
    version = next_version(current, bump)
    tag = f"v{version}"
    ensure_tag_absent(repo_root, tag, runner)

    print(f"{current} -> {version}")
    release_commit: str | None = None
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
        release_commit = head_sha(repo_root, runner)
        del artifacts
        runner(
            ["git", "tag", "-a", tag, "-m", unreleased_or_version(changelog, version)],
            repo_root,
        )
    except BaseException:
        _rollback(repo_root, original_head, release_commit, runner)
        raise

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
    release_commit: str | None,
    runner: Runner,
) -> None:
    """Restore worktree, index and refs. A failed release must be a no-op."""
    if release_commit is not None:
        current = head_sha(repo_root, runner)
        if current == release_commit:
            runner(["git", "reset", "--hard", original_head], repo_root)
        else:
            # Something else advanced HEAD; resetting would destroy that work.
            raise ReleaseError(
                f"HEAD moved to {current[:12]} after the release commit "
                f"{release_commit[:12]}; not resetting. Undo manually."
            )
    else:
        # Unstage anything the failed commit left in the index, then restore the
        # tracked files. `reset --hard` is confined to tracked content, so build
        # output stays where it is.
        runner(["git", "reset", "-q", "HEAD"], repo_root)
        runner(["git", "checkout", "--", "."], repo_root)


# ---------------------------------------------------------------------------- cli


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=f"Cut a {PRODUCT} release",
        epilog="Runs runtime tests, builds, commits, tags, pushes, and publishes.",
    )
    parser.add_argument(
        "bump", choices=("major", "minor", "patch"), help="which component to raise"
    )

    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        release(repo_root, args.bump)
    except ReleaseError as error:
        print(f"release refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
