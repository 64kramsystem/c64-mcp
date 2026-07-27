# c64-mcp

C64-specific MCP tools layered over the public `ghidra-mcp` HTTP API and the
separately installed Ghidra VICE connector.

The server uses stdio transport by default. It does not open a VICE binary
monitor socket; the connector remains the sole owner of that connection.

## Tool visibility

The default `static` profile exposes the symbol, text, and graphics groups
plus four small catalog-management tools. This keeps live-debugger schemas out of the
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

The handshake also requires connector **surface revision 2**, which adds the
`display.capture` capability; an older connector is refused there, naming the
revision it needs, rather than failing later on a missing method.

The tool set covers cached status, dynamic registers and banks, bank-aware
memory, checkpoints, execution control, stop-event waits, reset, and screen
capture. `vice_disconnect` releases only this MCP process's local binding; it
never closes the connector socket, trace, or VICE process. `vice_status` is
cached and performs no discovery or network operation.

`vice_capture_screen` returns the composited frame as an indexed PNG. It lives
in the `vice` group rather than `graphics`, because it needs the live debugger.
The connector returns the debug frame — border and blanking included — as one
palette index per byte, together with the palette VICE is using; the capture is
mapped through that palette rather than the static Pepto default, and the
default `crop=true` keeps only the inner screen rectangle the connector
reports, while `crop=false` returns the whole debug buffer. The summary carries
`width`, `height`, `cropped`, `inner`, `palette_size`, `used_indices`,
`distinct_index_count`, and `output_path`, which is written atomically and
refuses an existing file unless `overwrite=true`. The envelope is validated
before anything renders, and a mismatch is one `vice_connector_incompatible`
error naming the field.

Capture requires a stopped emulator, because any binary-monitor command traps
VICE into the monitor: call `vice_interrupt`, capture, then `vice_resume`, so
the stop stays visible instead of hiding inside a read-only-looking call. It
also requires a VICE at r46020 or later; earlier builds, including the 3.10
release, overrun their allocation while answering `display get`, and the
connector refuses them by design.

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

Every platform-symbol address explicitly targets the default `RAM` address
space. This keeps CPU-visible register and ROM references unambiguous after
ROM, I/O, or color-RAM overlays have been added. The bundled profile supports
`6502:LE:16:default` programs whose default CPU space is named `RAM`; an
overlay must not reuse that name.

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

## C64 graphics tools

Five per-mode decoders turn C64 graphics memory into an indexed PNG:

- `decode_c64_hires_bitmap` takes `bitmap` and `screen`; a set bit uses the
  screen byte's high nybble and a clear bit its low nybble.
- `decode_c64_multicolor_bitmap` adds `color`; the bit pairs select
  `background`, the screen high nybble, the screen low nybble, and the
  colour-RAM low nybble.
- `decode_c64_charset` renders a character set as a sheet `sheet_columns`
  glyphs wide, optionally in multicolor.
- `decode_c64_char_screen` renders text mode from `screen` and `charset`. With
  `multicolor=true`, `color` is required because colour-RAM bit 3 selects each
  cell's mode; only glyphs up to the highest screen code present must be
  supplied.
- `decode_c64_sprites` renders 24x21 hires or 12x21 multicolor definitions onto
  a sheet. `sprite_stride` defaults to 64, the padded definition-block size;
  63 is accepted for packed records. Transparent pixels composite onto
  `background`.

Every byte input takes one discriminated source:

```json
{"kind": "inline", "bytes": "00ff"}
{"kind": "ghidra", "program": "name", "start": "ram:2000"}
{"kind": "vice", "bank_id": 1, "start": 8192}
```

`bank_id` is mandatory for a VICE source: the same address holds different
bytes in different banks. A VICE read that would run past `$FFFF` is refused
rather than wrapped. Naming more than one VICE source while the emulator is
running is refused unless `allow_non_atomic_vice_reads=true`, which then
reports a `non_atomic_vice_reads` warning.

A source shorter than the geometry requires is an error before any rendering
and before any remote read; extra inline bytes are ignored and counted in the
summary. Colours are Pepto PAL unless a `palette` of `#rrggbb` strings or
`[r, g, b]` triples is supplied; indices past a short palette extend `PLTE`
with black and are reported as `unmapped_indices`. `output_path` writes the
PNG atomically and refuses an existing file unless `overwrite=true`.

Cell geometry is capped at 64 columns, 64 rows, and 2,048 cells; glyph and
sprite counts at 256; sheet width at 64. These tools are read-only: nothing is
written into a program or into VICE.

These decoders render bytes, wherever they came from; `vice_capture_screen`,
in the VICE group above, renders what the emulator is actually showing. Use the
decoders for an off-screen buffer or a program's data, and capture for the
composited result.

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
