# ghidra-mcp-c64

C64-specific MCP tools layered over the public `ghidra-mcp` HTTP API and the
separately installed Ghidra VICE connector.

The server uses stdio transport by default. It does not open a VICE binary
monitor socket; the connector remains the sole owner of that connection.

## C64 symbol profile

`get_c64_symbol_profile` returns the bundled, versioned C64 platform profile.
`apply_c64_symbol_profile` applies that exact profile to an explicitly named
Ghidra program through the generic `apply_symbol_profile` endpoint. It
defaults to `dry_run=true`, `conflict_policy=error`, and memory-block creation
disabled. Re-applying an unchanged profile is idempotent.

The profile covers the 6510 processor port, all VIC-II and SID registers,
both CIA devices, color RAM, the 39 standard KERNAL jump-table entry points,
processor vectors, and common KERNAL workspace addresses. Value-only equates
name documented VIC-II, SID, and CIA control bits. Optional RAM, ROM, I/O,
and color-RAM block templates are only considered when
`create_memory_blocks=true`; the generic endpoint preflights the complete
request before mutation and refuses ordinary-block overlap.

The checked-in profile is generated deterministically by
`tools/generate_c64_profile.py`. Every symbol group cites its authoritative
Commodore manual or chip data sheet in the package data.

## C64 text tools

The server includes immutable 256-entry mappings for upper/graphics and
lower/upper PETSCII and C64 screen codes:

- `decode_c64_text` decodes inline hex/byte arrays or an exact bounded read
  from a named Ghidra program.
- `search_c64_text` searches an inclusive program range by exact raw bytes or
  exact decoded Unicode code points.
- `define_c64_text` decodes first, then sends one flat contiguous region to
  Ghidra with byte typing, an optional label/namespace, and a complete plate
  comment. It defaults to `dry_run=true`.

Every decode uses exactly one of a positive fixed `length`, a one-byte
`terminator`, or a one/two-byte little-endian `prefix_size`. Terminators are
consumed but excluded from text. Prefixes are consumed and excluded from
text, and may either describe payload length or include themselves.

`high_bit` accepts `exact`, `strip`, or `annotate_reverse`; the latter is
screen-code-only. `controls` accepts `names`, `escaped`, or `unicode`.
Lossless payload output retains every original text byte as a stable fragment
such as `{A:$41}`, `{CLR:$93}`, or `{REV A:$81}`. Prefix and terminator bytes
remain available in `consumed_bytes` and the per-byte records even though
framing bytes are excluded from both decoded text renderings.

Caller token maps use unprefixed decimal keys (`"129"`) or explicitly
hexadecimal keys (`"0x81"`). Expansion is single-pass by default. Recursive
mode recognizes two-digit hexadecimal references such as `{81}`, enforces a
caller-selected depth, detects cycles, and fails rather than truncating when
the aggregate rendering cap is exceeded.

All reads and inline inputs have a 1 MiB hard cap. Search defaults to 64 KiB
and 100 results, with hard caps of 1 MiB and 1,000 results. Ghidra reads must
be complete; partial or unmapped reads are errors.

The normative mapping source is Appendices B and C of the official
*Commodore 64 Programmer's Reference Guide*. The generated package data
records the source URL and printed page references.

## Configuration

- `GHIDRA_MCP_URL` defaults to `http://127.0.0.1:8089`.
- `GHIDRA_MCP_AUTH_TOKEN` optionally supplies a bearer token.
- `GHIDRA_MCP_TIMEOUT` defaults to 30 seconds.
