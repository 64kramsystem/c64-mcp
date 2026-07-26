# c64-mcp

C64-specific MCP tools layered over the public `ghidra-mcp` HTTP API and the
separately installed Ghidra VICE connector.

The server uses stdio transport by default. It does not open a VICE binary
monitor socket; the connector remains the sole owner of that connection.

## Tool visibility

The default `static` profile exposes the symbol and text groups plus four
small catalog-management tools. This keeps live-debugger schemas out of the
agent context until they are needed. `minimal` starts with management tools
only, `vice` starts with the live-debugger group, and `full` exposes every
tool.

Use `list_c64_tool_groups`, `search_c64_tools`, and
`load_c64_tool_group` to discover and expose hidden tools at runtime.
`unload_c64_tool_group` removes only groups loaded after startup; profile
baseline groups remain visible. Thus `static` followed by loading `all`
still permits unloading the transient VICE group, while the `full` profile
does not permit partial unloading.

## VICE debugger tools

The `vice_*` tools bind to the active **VICE C64 Debugger** TraceRMI target
through the generic Ghidra MCP HTTP API. Install and launch the separately
released `ghidra-vice-connector` first, then call `vice_connect`. The handshake
checks the complete versioned `c64.vice/1` method schema, capability set,
machine, limits, and immutable connector instance ID. Compatibility is based
on that runtime contract rather than an assumed package-version pairing.

The tool set covers cached status, dynamic registers and banks, bank-aware
memory, checkpoints, execution control, stop-event waits, and reset.
`vice_disconnect` releases only this MCP process's local binding; it never
closes the connector socket, trace, or VICE process. `vice_status` is cached
and performs no discovery or network operation.

`copy_vice_memory_to_ghidra` is the only implicit bridge from live VICE memory
to a static program. It performs one complete connector read, verifies the
exact byte count, computes SHA-256, and calls the generic
`write_memory_bytes` endpoint exactly once. It defaults to `dry_run=true` and
never returns the complete payload. It does not create memory blocks or
disassemble.

Connector, generic target-method, and HTTP timeouts remain distinguishable.
Mutating timeout responses explicitly say which VICE or Ghidra state may have
changed, and no timed-out operation is retried automatically. The C64 MCP
contains no VICE monitor host, port, socket, or binary protocol fallback.

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
- `C64_MCP_TOOL_PROFILE` accepts `minimal`, `static`, `vice`, or
  `full`; the default is `static`.

The `--tool-profile` command-line option overrides the environment setting.

VICE method calls accept a caller-visible `timeout_ms` from 1 through 55,000.
The wrapper reserves an additional five seconds for generic TraceRMI
invocation and another five seconds for HTTP transport.
