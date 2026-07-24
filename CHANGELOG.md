# Changelog

## Unreleased

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
