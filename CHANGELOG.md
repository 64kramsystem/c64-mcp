# Changelog

## Unreleased

### Changed

- `tools/release` now publishes to PyPI as its final step, the package being
  `c64-mcp` there. It refuses up front when `UV_PUBLISH_TOKEN` is unset, before
  touching git: the push and the tag come earlier and cannot be retracted, so
  discovering a missing token afterwards would leave a released tag with nothing
  published. Only the two artifacts built for that version are uploaded, not
  whatever `dist/` happens to hold.
- Renamed the `GHIDRA_MCP_C64_*` environment variables to `C64_MCP_*`, including
  the runtime `C64_MCP_TOOL_PROFILE`. `GHIDRA_MCP_URL` and
  `GHIDRA_VICE_CONNECTOR_REPO` keep their names, naming things that are still
  called that.

- Renamed the project from `ghidra-mcp-c64` to `c64-mcp`, and the Python package
  from `ghidra_mcp_c64` to `c64_mcp`. The old name implied a sibling of
  `ghidra-mcp-next`; this is not a Ghidra extension and contains no Java. It is an
  MCP server that reaches Ghidra over HTTP and VICE through the connector's
  TraceRMI contract, and roughly half of it — the PETSCII and screen-code tables,
  the C64 symbol profile, the tool-visibility profiles — needs neither.
  **The console script is now `c64-mcp`**: update the `command` in any `.mcp.json`
  and re-sync the virtualenv, which otherwise keeps the old script.

### Added

- Added `tools/release <major|minor|patch>`, a single command that refuses unless
  the checkout is on the default branch, clean and exactly in sync with origin,
  then writes the version to `pyproject.toml`, regenerates `uv.lock`, rolls the
  changelog, runs the gates through `uv run --locked` against that candidate,
  builds, commits, tags and pushes. There is deliberately no publishing step:
  nothing consumes a c64 release, and its compatibility with the connector rests
  on the `c64.vice/1` runtime handshake rather than on matching versions.
  Everything that can fail runs before the push, since the push cannot be undone;
  until then a failure restores the working tree, the index and the branch ref.

### Changed

- Version moves to `0.99.0`. `__version__` is now derived from installed package
  metadata rather than duplicated as a literal, so it cannot drift from
  `pyproject.toml`.
- Dropped `connector.version` from the packaged `c64-vice-api-v1.json`, matching
  the connector: it is release metadata rather than part of the `c64.vice/1`
  compatibility surface, and keeping it required a coordinated commit here on
  every connector release. The runtime `connector_version` from `status` is
  unaffected.

### Added

- `minimal`, `static`, `vice`, and `full` tool-visibility profiles with
  runtime group listing, search, load, and unload tools.
- Initial standalone package scaffold.
- Immutable, source-cited 256-entry PETSCII and C64 screen-code tables for
  both C64 character-set modes.
- Lossless bounded PETSCII/screen-code decoding with fixed, terminated, and
  length-prefixed sources, high-bit policies, control rendering, and
  caller-owned token expansion.
- `decode_c64_text`, `search_c64_text`, and dry-run-first
  `define_c64_text` MCP tools over the public Ghidra HTTP boundary.
- A versioned, source-attributed C64 profile covering VIC-II, SID, CIA,
  KERNAL, vectors, workspace, control-bit equates, and opt-in memory
  templates.
- `get_c64_symbol_profile` and dry-run-first
  `apply_c64_symbol_profile` MCP tools.
- A strict packaged `c64.vice/1` connector contract and race-safe local
  binding keyed by the Ghidra target token and connector instance ID.
- Complete `vice_*` tools for connector-owned registers, banks, memory,
  checkpoints, execution, stop waits, reset, and cached session status.
- Dry-run-first `copy_vice_memory_to_ghidra`, with one complete VICE read,
  SHA-256 verification, exactly one generic program write, and no payload
  echo.
- Distinct connector, generic TraceRMI, and HTTP timeout reporting with
  operation-specific uncertainty flags and no automatic retries.
