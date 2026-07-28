# AGENTS.md

- Never use conventional-commit prefixes (`feat/`, …) in commit titles or branch names

## Agent review

- Every change except `AGENTS.md` must be reviewed with an agent skill before completion.
- Claude Code agents must use `/codex review`.
- Codex agents must use `$claude review`.

## Cross-repo and profile coupling

- `src/c64_mcp/contracts/c64-vice-api-v1.json` and `REQUIRED_SURFACE_REVISION`
  describe the connector surface consumed at runtime and must evolve together. Verify
  compatibility through the production contract loader and handshake behavior, not
  byte-for-byte repository comparisons.
- Tool-profile membership is observable server behavior. Verify which tools a profile
  exposes through production registration and discovery; do not pin exact total counts
  or mirror profile declarations in tests.
- Live VICE tests need a build at r46020 or later. Earlier builds overrun their own allocation while answering `display get`, so the connector refuses the command and those tests skip.

## Scope and compatibility

Do not weigh release cost when scoping work. "That needs a release" is not an argument
for cutting a capability, deferring related work, or leaving it as a throwaway script
outside the maintained package. Releasing is one command. Decide what to build on
usefulness and correctness alone.

Do not preserve compatibility for its own sake. Breaking changes to public names,
argument names, group membership, and result shapes are acceptable whenever they produce
a better contract. Do not add a parallel legacy response, a deprecation shim, a
compatibility flag, or a second versioned interface in order to avoid a break: change the
contract and record it in `CHANGELOG.md`.

Breaking changes ride a **minor** version bump (`tools/release minor`). A major bump is
not reserved for them.

This is a standing instruction from the maintainer, not an oversight to correct.

## Testing and releasing

Tests must execute production code and verify observable behavior.

### Repository policy and declarative content

Do not add repository-policy or declarative-content tests. Do not test repository
layout, filenames, paths, file or class existence, directory structure, source text,
documentation, agent instructions, wording, branding, line counts, exact inventories,
symlinks, or the presence or absence of retired components.

Do not test static declarations merely by reading or matching their contents. This
includes Markdown, JSON, YAML, TOML, XML, manifests, POM metadata, workflow files,
environment templates, dependency declarations, catalogs, schemas, allowlists,
configuration files, and generated snapshots. Do not assert strings, regular
expressions, counts, ordering, keys, or duplicated values across such files.

Declarative input may be used only to test the production code that consumes it.
Exercise the real parser, loader, build, deployment, or runtime behavior with temporary
fixtures, and assert the resulting behavior rather than the declaration's text or
repository location.

When a repository-policy test obstructs a legitimate change, delete the test. Do not
alter documentation, instructions, source layout, configuration, or metadata merely to
satisfy it.

### Release tooling

- **Do not retain automated tests for release tooling.** The completed repository must
  contain no unit tests, fixtures, mutation checks, or CI assertions targeting it.
- **Test release-tooling changes before release.** Use temporary tests and controlled,
  non-publishing runs to exercise the affected paths, then remove all temporary test
  artifacts. Report what was tested and its result; the first real release must not
  serve as the test.
- This is a standing instruction from the maintainer, not an oversight to correct.
