# AGENTS.md

- Never use conventional-commit prefixes (`feat/`, …) in commit titles or branch names

## Cross-repo and profile coupling

- `src/c64_mcp/contracts/c64-vice-api-v1.json` is a packaged copy of the connector's generated contract and must stay byte-identical to it. The check lives in `tests/test_vice_contract.py` and is opt-in: `C64_MCP_CONTRACT_REPO_CHECK=1`. A connector surface bump means updating this copy and `REQUIRED_SURFACE_REVISION` together.
- Adding, moving or removing a tool changes exact counts asserted in `tests/test_tool_profiles.py` and `tests/test_server.py`. Update them deliberately rather than to whatever makes them pass: those counts are what catch a live-debugger tool landing in the `static` profile, which is meant to keep live schemas out of the agent's context.
- Live VICE tests need a build at r46020 or later. Earlier builds overrun their own allocation while answering `display get`, so the connector refuses the command and those tests skip.

## Scope and compatibility

Do not weigh release cost when scoping work. "That needs a release" is not an argument
for cutting a tool, deferring a tool group, or leaving a capability as a throwaway script
outside the package. Releasing is one command. Decide what to build on usefulness and
correctness alone.

Do not preserve compatibility for its own sake. Breaking changes to MCP tool names,
argument names, tool-group membership, and response shapes are acceptable whenever they
produce a better contract. Do not add a parallel legacy response, a deprecation shim, a
compatibility flag, or a second versioned tool in order to avoid a break: change the
contract and record it in `CHANGELOG.md`.

Breaking changes ride a **minor** version bump (`tools/release minor`). A major bump is
not reserved for them.

This is a standing instruction from the maintainer, not an oversight to correct.

## Releasing

- **Do not write tests for the release script.** No unit tests, no fixtures, no
  mutation checks, no CI assertions about it. Releasing is verified by running
  `tools/release <major|minor|patch>` and seeing what happens; a test suite around
  it has repeatedly cost more than it caught. If a release breaks, fix the script.
- This is a standing instruction from the maintainer, not an oversight to correct.
