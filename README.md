# c64-mcp

Small C64-specific MCP tools layered over GhidraMCP-next and the separately installed Ghidra VICE connector. The server uses stdio and never opens VICE's binary-monitor socket.

## Tools

`vice_start_trace` records load (1), store (2), and execute (4) operations for inclusive `{"start": ..., "end": ...}` ranges to a new absolute output filename. Combine operation bits as needed. `vice_stop_trace` takes the returned trace ID, flushes the log, and removes its checkpoints. VICE monitor output and other checkpoint messages may also appear in the log.

### Static analysis

- `apply_c64_symbols` creates the bundled C64 hardware and KERNAL labels in one idempotent Ghidra batch. Symbols use nested `C64::...` namespaces, and the result reports `labels_created`, `labels_skipped`, and `labels_failed`.
- `decode_c64_text` decodes inline bytes or a bounded Ghidra read as upper or lower PETSCII or screen codes. Input may use a fixed length, a terminator, or a one/two-byte little-endian length prefix. Token keys are decimal unless prefixed with `0x`.
- `decode_c64_hires_bitmap` and `decode_c64_multicolor_bitmap` render bitmap memory.
- `decode_c64_charset`, `decode_c64_char_screen`, and `decode_c64_sprites` render character and sprite data.

Graphics inputs explicitly name their source:

```json
{"kind": "inline", "bytes": "00ff"}
{"kind": "ghidra", "program": "game", "start": "RAM:2000"}
```

Renderers return an indexed PNG and a compact summary. `output_path` is optional; an existing file is replaced only when `overwrite=true`. Static rendering uses the Pepto PAL palette.

### Live VICE

Call `vice_connect` after the VICE connector has established its TraceRMI session. The remaining `vice_*` tools cover:

- status, registers, banks, and bank-aware memory;
- checkpoints with optional native VICE conditions, step/next/finish, resume, interrupt, and stop waits;
- resource reads/writes and autostart of VICE-local files;
- deterministic keyboard and joystick input;
- reset and snapshot save/load;
- capture of VICE's composited display;
- copying one verified VICE memory range into Ghidra.

`vice_get_resource` and `vice_set_resource` require stopped VICE. Set values as text, for example `WarpMode="1"`. Autostart also requires stopped VICE and resumes it when scheduled; `run` controls BASIC RUN, and the response does not mean loading is complete. `file_index=0` selects the default; positive indexes are directory positions starting at 1. Use a checkpoint or stop wait for readiness.

`vice_disconnect` drops only this process's binding. It does not close VICE, the connector, or the trace.

`vice_advance_frames(frame_count, timeout_ms=10000)` and `vice_run_until(address, max_frames, timeout_ms=10000)` start stopped. A frame is the first observed CPU instruction boundary on raster line 0 after a nonzero line; long REU DMA can skip an observation. Counts must be positive, addresses are 0–65535, and timeouts are 1–55000 ms. Results include `reason` and `frames_completed`: advance reasons are `frames`, `checkpoint`, `stopped`, and `timeout`; run-until reasons are `target`, `checkpoint`, `frame_limit`, `stopped`, and `timeout`. If stops coincide, target takes precedence over another checkpoint, which takes precedence over the frame limit. An already-current target returns immediately with zero frames and no new stop. Other operations publish one final stop after removing their helper checkpoints. Timeout recovery can take up to two additional seconds; recovery or cleanup failure returns an error and may leave checkpoint state uncertain.

`vice_cpu_history(count=64)` reads up to 4096 recent main-CPU entries while stopped. Each entry has pre-instruction registers, a fetch-start cycle and three saved instruction-prefix bytes; unused operand slots may be zero or neighboring bytes. Entries are oldest to newest, but cycles can decrease after reset or snapshot restore. VICE must be built with `--enable-cpuhistory`.

Binary-monitor reads require VICE to be stopped. A normal sequence is `vice_interrupt`, read or capture, then `vice_resume`. Display capture is optional: other VICE tools remain usable when the connector lacks it. Capture requires the display methods and a VICE build with the safe display-command fix.

`copy_vice_memory_to_ghidra` reads the complete range once, verifies its length and SHA-256, then makes one Ghidra write request. It defaults to `dry_run=true`.

`vice_set_joyport` injects one raw active-low joystick-line byte on public port 1 or 2. The value remains in effect until another input, reset, or emulator shutdown changes it.

`vice_set_keyboard_matrix` presses or releases one physical matrix position (row and column 0–7). A press remains held until explicitly released or the keyboard is cleared. It requires a VICE build containing binary-monitor command `0xa3` from the companion patch; stock builds reject it cleanly.

## Limits and behavior

- Text and graphics sources are capped at 64 KiB.
- VICE memory calls transfer at most 16 KiB; a verified copy into Ghidra may span 64 KiB.
- Keyboard input is capped at 255 bytes.
- Graphics geometry is bounded before remote reads.
- Requests are never retried automatically. A timed-out mutation may already have changed VICE or Ghidra, so inspect state before repeating it.
- The Ghidra and connector boundaries are local and unauthenticated.

## Configuration

- By default, the first Ghidra operation discovers local GhidraMCP-next Unix sockets and selects the sole reachable instance. No instance or multiple instances produces an error listing candidates.
- Set `GHIDRA_MCP_SOCKET` to select a Unix socket explicitly. TCP endpoints are not supported.
- A selected socket stays fixed for the server lifetime. Failed operations are never retried or replayed automatically; restart the client to discover another instance.
- `GHIDRA_MCP_TIMEOUT` defaults to 30 seconds.

Run with:

```sh
uv run c64-mcp
```

The package contains the immutable text tables and C64 symbol data used by the tools.

## Ghidra integration baseline

The companion extensions target Ghidra 12.2 and JDK 25. Older Ghidra releases and
older trace databases are not supported. c64-mcp remains a separate MCP process.

With sibling checkouts, run the disposable integration test using
`python ../ghidra-mcp-next/tools/test_debugger_stacks.py --stack vice --ghidra "$GHIDRA_INSTALL_DIR"`.

### Execution map assessment

VICE maintains cumulative per-address access bits beyond history overwrite. The map starts empty and `memmapzap` clears it; reset and snapshot restore do not clear it, so separate runs require explicit capture and clear boundaries. The binary monitor currently offers no map read or clear command; the text-monitor orchestration in `codemap.py` can execute the CPU just to query or clear it. A future explicit capture/read operation and read-only Ghidra comparison could identify observed opcode starts and possible indirect-target candidates missed by static analysis, not sequenced edges. Adjacent history entries can supply evidence with interrupt and capture-boundary caveats.

The map has no versioned bytes, timestamps, or bank identity; VICE’s main-CPU ROM/RAM/IO classification has a FIXME and cartridge banks merge. Current $00/$01 values cannot resolve earlier mappings. Current-memory decoding infers operand spans under self-modifying code; only the marked start is directly observed. An observed start in defined DATA should be reported separately from an uncertain inferred operand span or undefined bytes; explicit undefined 1–8 byte units remain undefined in `analyze_coverage`.
