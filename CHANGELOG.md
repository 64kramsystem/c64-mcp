# Changelog

## Unreleased

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
