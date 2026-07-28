# AGENTS.md

- See AGENTS.ghidra-mcps.md

## C64 coupling

- Evolve `src/c64_mcp/contracts/c64-vice-api-v1.json` with
  `REQUIRED_SURFACE_REVISION`; test compatibility through the production loader and
  handshake, never byte comparison.
- Test profile membership through production registration/discovery, never exact totals
  or mirrored declarations.
- Live VICE display tests require r46020+; older builds overrun their allocation and the
  connector therefore skips them.

