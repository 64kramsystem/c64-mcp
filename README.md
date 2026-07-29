# c64-mcp

Small C64-specific MCP tools layered over GhidraMCP-next and the separately installed Ghidra VICE connector. The server uses stdio and never opens VICE's binary-monitor socket.

## Tools

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
- checkpoints, step/next/finish, resume, interrupt, and stop waits;
- deterministic keyboard and joystick input;
- reset and snapshot save/load;
- capture of VICE's composited display;
- copying one verified VICE memory range into Ghidra.

`vice_disconnect` drops only this process's binding. It does not close VICE, the connector, or the trace.

Binary-monitor reads require VICE to be stopped. A normal sequence is `vice_interrupt`, read or capture, then `vice_resume`. Display capture is optional: other VICE tools remain usable when the connector lacks it. Capture requires the display methods and a VICE build with the safe display-command fix.

`copy_vice_memory_to_ghidra` reads the complete range once, verifies its length and SHA-256, then makes one Ghidra write request. It defaults to `dry_run=true`.

`vice_set_joyport` injects one raw active-low joystick-line byte on public port 1 or 2. The value remains in effect until another input, reset, or emulator shutdown changes it.

## Limits and behavior

- Text and graphics sources are capped at 64 KiB.
- VICE memory calls transfer at most 16 KiB; a verified copy into Ghidra may span 64 KiB.
- Keyboard input is capped at 255 bytes.
- Graphics geometry is bounded before remote reads.
- Requests are never retried automatically. A timed-out mutation may already have changed VICE or Ghidra, so inspect state before repeating it.
- The Ghidra and connector boundaries are local and unauthenticated.

## Configuration

- `GHIDRA_MCP_URL` defaults to `http://127.0.0.1:8089`.
- `GHIDRA_MCP_TIMEOUT` defaults to 30 seconds.

Run with:

```sh
uv run c64-mcp
```

The package contains the immutable text tables and C64 symbol data used by the tools.
