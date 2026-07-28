# AGENTS.md

- No conventional-commit prefixes (`feat/`, etc.) in commit titles or branch names.
- Review every change except `AGENTS.md` with an agent skill: Claude Code uses
  `/codex review`; Codex uses `$claude review`.

## C64 coupling

- Evolve `src/c64_mcp/contracts/c64-vice-api-v1.json` with
  `REQUIRED_SURFACE_REVISION`; test compatibility through the production loader and
  handshake, never byte comparison.
- Test profile membership through production registration/discovery, never exact totals
  or mirrored declarations.
- Live VICE display tests require r46020+; older builds overrun their allocation and the
  connector therefore skips them.

## Scope

- Scope by usefulness and correctness, never release cost.
- Prefer a better public contract over compatibility. Change names, arguments, groups,
  or results directly; add no legacy response, shim, flag, or versioned duplicate.
  Record the change in `CHANGELOG.md`; breaking changes use `tools/release minor`.

## Tests and releases

- Tests must execute production code and assert observable behavior.
- No repository-policy or declarative-content tests: do not assert repository layout,
  paths, existence, source/docs/instruction text, branding, counts, inventories,
  symlinks, retired artifacts, or static contents of configuration, metadata,
  workflows, manifests, catalogs, schemas, allowlists, or snapshots.
- Declarative fixtures are allowed only through the real parser, loader, build,
  deployment, or runtime; assert behavior, not text or location.
- Delete obstructive policy tests; never alter docs, instructions, layout,
  configuration, or metadata to satisfy them.
- Retain no tests, fixtures, mutation checks, or CI assertions for release tooling.
  Verify release-tool changes with temporary non-publishing runs, remove the artifacts,
  and report the result; the first real release must not be the test.
