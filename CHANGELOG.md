# Changelog

## Unreleased

### Added

- `tools/release` now accepts an exact `X.Y.Z` release version as well as `major`, `minor`, or `patch`, and no longer runs test suites before building and publishing a release.
- `vice_capture_screen`, in the **`vice`** group rather than `graphics`, because
  the default `static` profile deliberately keeps live-debugger schemas out of
  context. It asks the connector for one composited frame plus the palette VICE
  returned with it, crops to the inner screen rectangle by default (`crop=false`
  returns the whole debug buffer, border included), and encodes an indexed PNG
  through the same writer the static decoders use — mapped through the
  emulator's own palette, not the static Pepto default. The summary carries
  `mode`, `width`, `height`, `cropped`, `inner`, `palette_size`,
  `used_indices`, `distinct_index_count`, and `output_path`; `output_path` is
  written atomically and refuses an existing file unless `overwrite=true`.
  Capture needs a stopped emulator, which the connector enforces:
  `vice_interrupt`, capture, then `vice_resume`.
- The connector envelope is validated completely before anything renders —
  `bits_per_pixel == 8`, `buffer_length == width * height`, the decoded base64
  length, the inner rectangle fitting inside the debug buffer, and a palette
  covering every index present. A violation is one
  `vice_connector_incompatible` error naming the offending field rather than a
  half-invented image. Unmapped indices cannot occur on this path, because the
  connector refuses a buffer whose highest index its palette does not cover, so
  capture reports no `unmapped_indices`.

- A `graphics` tool group, in the `static` and `full` profiles, decoding C64
  graphics memory to an indexed PNG: `decode_c64_hires_bitmap`,
  `decode_c64_multicolor_bitmap`, `decode_c64_charset`,
  `decode_c64_char_screen`, and `decode_c64_sprites`. Each encodes conventions
  that are otherwise re-derived from memory every time — bitmap cell
  interleaving, the multicolor bit-pair to colour-source mapping, per-cell
  hires/multicolor selection through colour-RAM bit 3, the 64-byte sprite
  stride, sprite transparency — and returns one image plus a JSON summary of
  what was read and what was drawn. Colours are Pepto PAL by default; a
  `palette` argument overrides it, and indices beyond a short palette extend
  `PLTE` with black and are reported rather than silently dropped.
- Every graphics byte input takes one discriminated source: `{"kind":
  "inline", "bytes": "…"}`, `{"kind": "ghidra", "program": …, "start": …}`, or
  `{"kind": "vice", "bank_id": …, "start": …}`. `bank_id` is mandatory, because
  the same address holds different bytes in different banks, and a VICE read is
  refused rather than wrapped past `$FFFF`. A source shorter than the geometry
  requires is an error before anything is read or rendered, rather than an
  image with invented pixels. Naming more than one VICE source while the
  emulator runs fails unless `allow_non_atomic_vice_reads=true`, which then
  reports a `non_atomic_vice_reads` warning in both summaries. `output_path`
  writes the PNG atomically and refuses an existing file unless
  `overwrite=true`.

### Changed

- `tools/release` retains the shipped-runtime pytest gate but no longer treats
  Ruff, mypy, or lockfile consistency as release test gates.
- `tools/release` now exits successfully when HEAD already carries its release
  tag, reporting that there is nothing to release rather than refusing at
  `ensure_tag_absent`. A release tags its own commit, so a tagged HEAD is the
  record that this commit was released, and a repository with nothing new
  becomes a no-op instead of an error — which is what lets
  `~/code/scripts/release_ghidra_tools`, running this script alongside the
  connector's and GhidraMCP-next's, be re-run after any one of them fails. Only
  `v<semver>` tags count. The `UV_PUBLISH_TOKEN` check moved below the skip, so
  a run with nothing to release no longer demands a token it will not use; it
  still precedes everything irreversible, which is the point of the check.
- The bundled C64 symbol profile is now version 1.1.0 and qualifies all
  platform-symbol addresses with the default `RAM` space. Applying the profile
  remains deterministic and idempotent after ROM and I/O overlays exist,
  instead of failing on an ambiguous unqualified address.
- The packaged `c64-vice-api-v1.json` is now the connector's **surface revision
  2** contract, adding the `display.capture` capability and the
  `c64_vice_v1_capture_display` method. `vice_connect` refuses an older
  connector during the handshake, naming the revision it requires, instead of
  failing later on a missing method.
- `tools/release` now publishes to PyPI as its final step, the package being
  `c64-mcp` there. It refuses up front when `UV_PUBLISH_TOKEN` is unset, before
  touching git: the push and the tag come earlier and cannot be retracted, so
  discovering a missing token afterwards would leave a released tag with nothing
  published. Only the two artifacts built for that version are uploaded, not
  whatever `dist/` happens to hold.
- Renamed the `GHIDRA_MCP_C64_*` environment variables to `C64_MCP_*`, including
  the runtime `C64_MCP_TOOL_PROFILE`. `GHIDRA_MCP_URL` keeps its name because it
  addresses the generic Ghidra MCP.

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
  changelog, runs the runtime pytest gate through `uv run --locked`, builds,
  commits, tags, pushes, and publishes the artifacts to PyPI. Compatibility with
  the connector rests on the `c64.vice/1` runtime handshake rather than matching
  versions.
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
