# AGENTS.md

- Never use conventional-commit prefixes (`feat/`, …) in commit titles or branch names

## Releasing

- **Do not write tests for the release script.** No unit tests, no fixtures, no
  mutation checks, no CI assertions about it. Releasing is verified by running
  `tools/release <major|minor|patch>` and seeing what happens; a test suite around
  it has repeatedly cost more than it caught. If a release breaks, fix the script.
- This is a standing instruction from the maintainer, not an oversight to correct.
