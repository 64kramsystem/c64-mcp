# AGENTS.md

- Never use conventional-commit prefixes (`feat/`, …) in commit titles or branch names

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
