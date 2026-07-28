# AGENTS.md

- No conventional-commit prefixes (`feat/`, etc.) in commit titles or branch names.
- Review every change except `AGENTS.md` with an agent skill: Claude Code uses
  `/codex review`; Codex uses `$claude review`.

## Ghidra

- `$GHIDRA_PROGRAM_PATH` identifies the program; consult `$GHIDRA_SOURCE_PATH` when
  Ghidra source can replace guesswork.

## Scope

- Scope by usefulness and correctness, never release cost.
- Prefer a better public contract over compatibility. Change names, arguments, groups,
  or results directly; add no legacy response, shim, flag, or versioned duplicate.
  Record the change in `CHANGELOG.md`; breaking changes use `tools/release minor`.

## Tests

- Retain tests only for shipped runtime behavior: execute production runtime code and
  assert observable results.
- Retain no tests, fixtures, snapshots, mutation checks, or CI assertions for
  non-runtime infrastructure: repository content, documentation, metadata, generated
  artifacts, build/CI, installation/setup, configuration patching, deployment,
  packaging, release, migrations, or maintenance scripts.
- Verify infrastructure work only with temporary manual checks; remove their artifacts.
