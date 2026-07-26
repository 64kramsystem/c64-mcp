# Graphics decoding and screen capture

Date: 2026-07-26
Status: proposed (revised 2026-07-27, rounds 1 and 2 of review)

## Motivation

`text/` exists because decoding C64 text is knowledge, not code: PETSCII versus screen codes,
charset variants, high-bit conventions, length prefixes, token expansion. Any agent can write a
decoder loop; getting those conventions right from memory every time is what the package
prevents.

C64 graphics has the same shape and no equivalent. Bitmap cell interleaving, the multicolor
bit-pair to colour-source mapping, per-cell hires/multicolor selection in text mode, sprite
stride and transparency — all knowledge that gets re-derived and misremembered.

The immediate driver: a real target holds ~21 KB of illustration data reached through
fixed-stride records, drawn by a blitter that touches bitmap, screen codes and colour RAM.
Classifying it means rendering it.

Evidence that this is the right knowledge to encode, gathered while writing this spec: a
throwaway renderer built from these conventions rendered all 57 of that target's records, and
the 21 belonging to the resident part came out as recognisable illustrations while the other 36
came out as noise — which is how the per-part buffer structure was discovered. That renderer is
the prototype for `modes.py` and `png.py`; it is not the test (see [Testing](#testing)).

## Tool surface

`src/c64_mcp/graphics/` — `png.py`, `modes.py`, `palette.py`, `sources.py`, `tools.py`.

**Five per-mode decoder tools**, in a new `graphics` group:
`decode_c64_hires_bitmap`, `decode_c64_multicolor_bitmap`, `decode_c64_charset`,
`decode_c64_char_screen`, `decode_c64_sprites`.

One polymorphic `decode_c64_graphics` was rejected: a single flat signature carrying four
conditionally relevant sources plus mode-specific geometry and colours invites callers to supply
incomplete combinations, and FastMCP cannot express those conditions in a flat schema.

**`vice_capture_screen` joins the existing `vice` group**, not `graphics`. The default `static`
profile is `{symbols, text}` and deliberately keeps live-debugger schemas out of context.
`graphics` is added to `static` and `full`.

### ByteSource

Every byte input takes one discriminated source:

```json
{"kind": "inline", "bytes": "00ff…"}
{"kind": "ghidra", "program": "name", "start": "ram:2000"}
{"kind": "vice", "bank_id": 1, "start": 8192}
```

`bank_id` is **mandatory** for the VICE source: the same address returns different bytes in
different banks. A correction to the first draft, which claimed this mirrors the text tools:
`text/tools.py` accepts **inline or Ghidra only**; the VICE source is new here.

A VICE read that would run past `$FFFF` fails with the required and available lengths; it does
not wrap.

### Live-read atomicity

`allow_non_atomic_vice_reads`, default `false`. When a call names **more than one** VICE source
and the emulator is running, it fails **before any reads** unless the flag is `true`. With the
flag set, the reads proceed and a stable warning string `non_atomic_vice_reads` appears in both
the textual and structured summaries. A single VICE source, or a stopped emulator, needs no
flag.

## `vice_capture_screen`

| argument | default | notes |
| --- | --- | --- |
| `crop` | `true` | inner screen only, using the connector's `inner` offsets |
| `use_vic` | `true` | passed through to the connector |
| `timeout_ms` | `10000` | passed through |
| `output_path` | — | optional; written atomically |
| `overwrite` | `false` | required to replace an existing `output_path` |

Returns a `CallToolResult` (see [Output](#output)) whose summary carries `mode:
"vice_capture"`, `width`, `height`, `cropped`, `inner`, `palette_size`, `used_indices`,
`distinct_index_count`, and `output_path`.

Validation of the connector envelope before rendering: `bits_per_pixel == 8`,
`buffer_length == width * height`, decoded base64 length equal to `buffer_length`, crop bounds
within the debug buffer, and a palette covering every index present. A failure surfaces as
`vice_connector_incompatible` naming the field.

**Requires connector surface revision 2.** The packaged
`src/c64_mcp/contracts/c64-vice-api-v1.json` is revision 1 today and carries neither the
`display.capture` capability nor the `c64_vice_v1_capture_display` method; it must be updated
in step with the connector, and the handshake must reject an older connector with a clear
message rather than failing on a missing method.

**Unmapped indices cannot occur on this path**, because the connector rejects a buffer whose
maximum index is not covered by its palette. This resolves a contradiction in the previous
revision of these two specs. PLTE extension (below) therefore applies only to static decodes
with a caller-supplied palette, and to the encoder itself.

## Per-mode contracts

Cell dimensions default to the C64 screen: `columns` 40, `rows` 25.

| tool | sources (all required) | geometry | colours |
| --- | --- | --- | --- |
| `decode_c64_hires_bitmap` | `bitmap`, `screen` | `columns`, `rows` | — |
| `decode_c64_multicolor_bitmap` | `bitmap`, `screen`, `color` | `columns`, `rows` | `background` (default `0`) |
| `decode_c64_charset` | `charset` | `glyph_count` (default `256`), `sheet_columns` (default `16`) | `foreground` (default `1`), `background` (default `0`), `multicolor` (default `false`), `background_1`, `background_2` (required when `multicolor`) |
| `decode_c64_char_screen` | `screen`, `charset`, `color` (see below) | `columns`, `rows` | `background` (default `0`), `foreground` (default `1`), `multicolor` (default `false`), `background_1`, `background_2` (required when `multicolor`) |
| `decode_c64_sprites` | `sprites` | `sprite_count`, `sprite_stride` (default `64`, `63` accepted), `sheet_columns` (default `8`) | `sprite_colors`, `multicolor` (default `false`), `multicolor_0`, `multicolor_1` (required when `multicolor`), `background` (default `0`) |

- `decode_c64_char_screen`: `color` is **optional only when `multicolor` is `false`**, in which
  case every cell uses `foreground`. With `multicolor` true, `color` is **required**, because
  colour-RAM bit 3 selects each cell's mode.
- `decode_c64_sprites`: `sprite_colors` is a list of exactly `sprite_count` colour indices.
  `background` is the colour transparent pixels composite onto. Sprites are laid out on a sheet
  `sheet_columns` wide, row-major, padded with `background`.
- `decode_c64_charset`: with `multicolor` true, glyph bit pairs map as in `char_screen`
  multicolor cells, with `11` taking `foreground`'s low three bits.

### Mode semantics

**`hires_bitmap`** — 8 bytes per 8×8 cell, cells row-major: the byte for pixel row `r` of cell
column `c` in cell row `R` is at `R*columns*8 + c*8 + (r % 8)`. Per cell, a set bit takes the
screen byte's high nybble, a clear bit its low nybble.

**`multicolor_bitmap`** — same cell layout, two bits per pixel, 4×8 pixels per cell doubled
horizontally: `00` background, `01` screen high nybble, `10` screen low nybble, `11` colour-RAM
low nybble.

**`char_screen`** — screen codes index `charset`, 8 bytes per glyph.

- `multicolor=false`: every cell is hires, one bit per pixel, foreground from the cell's colour
  (colour RAM when supplied, else `foreground`), background from `background`.
- `multicolor=true`: **multicolor is per cell**, selected by colour-RAM **bit 3**. Bit 3 clear
  means a hires cell whose foreground is colour-RAM bits 0–2. Bit 3 set means a multicolor cell:
  `00` → `background`, `01` → `background_1` (`$D022`), `10` → `background_2` (`$D023`), `11` →
  **the low three bits** of the colour-RAM nybble.

**`charset`** — 8 bytes per glyph, rendered as a sheet `sheet_columns` glyphs wide; glyph
indices reported in the summary, not drawn.

**`sprites`** — 24×21 hires, or 12×21 multicolor doubled horizontally; 63 visible bytes per
sprite. `sprite_stride` defaults to **64**, because sprite definitions normally occupy 64-byte
blocks and consuming packed 63-byte records misaligns every sprite after the first. Multicolor
mapping: `00` transparent, `01` `multicolor_0` (`$D025`), `10` the per-sprite colour, `11`
`multicolor_1` (`$D026`).

## Lengths, ranges and caps

Required source lengths, all exact minimums:

| tool | source | required bytes |
| --- | --- | --- |
| `hires_bitmap` | `bitmap` / `screen` | `columns*rows*8` / `columns*rows` |
| `multicolor_bitmap` | `bitmap` / `screen` / `color` | `columns*rows*8` / `columns*rows` / `columns*rows` |
| `charset` | `charset` | `glyph_count*8` |
| `char_screen` | `screen` / `color` | `columns*rows` each |
| `char_screen` | `charset` | `(highest screen code present + 1) * 8` |
| `sprites` | `sprites` | `(sprite_count-1)*sprite_stride + 63` |

`char_screen` derives its charset requirement from the highest screen code actually present
rather than demanding a full 2,048 bytes, so a caller pointing at a partial glyph set is not
forced to over-supply. The rule is stated because it is otherwise ambiguous.

Ranges and caps, contractual:

| argument | range |
| --- | --- |
| `columns` | `1`–`64` |
| `rows` | `1`–`64` |
| `columns * rows` | `≤ 2048` |
| `glyph_count` | `1`–`256` |
| `sprite_count` | `1`–`256` |
| `sheet_columns` | `1`–`64` |
| colour indices (`background`, `foreground`, `background_1`, `background_2`, `multicolor_0`, `multicolor_1`, `sprite_colors[]`) | `0`–`15` |
| output pixels | `≤ 4,194,304` |
| encoded PNG | `≤ 8 MiB` |

Output dimensions: bitmap and char modes are `columns*8` × `rows*8`; charset is
`sheet_columns*8` × `ceil(glyph_count/sheet_columns)*8`; sprites are `sheet_columns*24` ×
`ceil(sprite_count/sheet_columns)*21`. A partly filled final sheet row is padded with
`background`.

### Short sources fail

A source shorter than required is an **error before any rendering**, naming required and
supplied lengths. Reporting a shortfall while returning a full-size image is unsafe: the image
invents pixels and an agent can accept it without reading the summary. Extra inline bytes are
ignored, with supplied, consumed and trailing counts in the summary. If partial rendering ever
has a real caller it arrives as explicit `allow_partial=true` with a conspicuous sentinel fill,
never implicit zeroes.

## Output

Each tool returns an explicit `CallToolResult` containing one `ImageContent`, one textual JSON
summary, and `structuredContent` holding **only** the summary. MCP 1.28.1 has a trap here: some
typed `Image` annotations fail schema construction or serialization, and a bare content block
can duplicate the base64 into structured output. The image bytes must appear exactly once.

Stable summary fields: `mode`, `width`, `height`, `sources` (per input: `kind`, `supplied`,
`consumed`, `trailing`), `used_indices`, `unmapped_indices`, `unmapped_pixel_count`,
`transparent_pixel_count` (sprite modes), `warnings`, `output_path`.

`output_path` is written atomically and fails on an existing target unless `overwrite=true`.

## png.py

Pure Python `zlib` + `struct`, no runtime dependency added. Indexed colour type 3 with `PLTE`,
filter type 0 per scanline, CRC32 per chunk. Indexed preserves the logical index per pixel and
filter 0 is what the PNG specification recommends for indexed images.

**An index beyond the `PLTE` length is invalid PNG** — decoders are not required to render it
black. When indices exceed the supplied palette, `PLTE` is **extended through the highest
observed index with black entries**, and the summary reports `unmapped_indices` and
`unmapped_pixel_count`.

## palette.py

The default is **Pepto PAL**, from <https://www.pepto.de/projects/colorvic/>, listed here so an
implementation cannot silently pick a different variant:

| # | name | RGB | # | name | RGB |
| --- | --- | --- | --- | --- | --- |
| 0 | black | `000000` | 8 | orange | `6F4F25` |
| 1 | white | `FFFFFF` | 9 | brown | `433900` |
| 2 | red | `68372B` | 10 | light red | `9A6759` |
| 3 | cyan | `70A4B2` | 11 | dark grey | `444444` |
| 4 | purple | `6F3D86` | 12 | grey | `6C6C6C` |
| 5 | green | `588D43` | 13 | light green | `9AD284` |
| 6 | blue | `352879` | 14 | light blue | `6C5EB5` |
| 7 | yellow | `B8C76F` | 15 | light grey | `959595` |

A `palette` argument overrides it. A capture uses the palette VICE returned with the frame.

## Deliberately excluded

- **Sprite multiplexing, scrolling, raster-split reconstruction.** Those describe a running
  machine; `vice_capture_screen` shows the composited result.
- **Writing graphics into a program or into VICE.** Read-only.
- **A bundled character ROM.** `charset` stays mandatory for `char_screen`, with a clear
  missing-charset error and documentation pointing at a Ghidra-imported ROM or a live VICE ROM
  bank. Capture is *not* a substitute — it cannot render an off-screen character buffer.

## Testing

Pillow is a **development** dependency, used to decode generated PNGs independently; a
hand-written chunk parser would validate the encoder against its own assumptions.

- **`png.py`:** byte-exact golden output for a small indexed image; every PNG in the suite
  re-decoded with Pillow and compared pixel-for-pixel; `PLTE` extension for out-of-range indices
  with a custom static palette.
- **Cell interleaving:** a **2×2** cell hires fixture with unique markers at offsets `0`, `8`
  and `columns*8`. A one-cell fixture cannot test interleaving.
- **Multicolor bitmap:** one cell exercising all four bit pairs against all four colour sources.
- **Charset:** glyphs `0`, `15` and `16`, so sheet wrapping is exercised; multicolor glyph
  mapping.
- **`char_screen`:** mixed hires and multicolor cells in one image selected by colour-RAM bit 3;
  all four multicolor pairs including `11` taking the low three bits; a hires cell asserted as
  one bit per pixel; `color` omitted with `multicolor=false` using `foreground`; `color` omitted
  with `multicolor=true` rejected; the highest-screen-code charset length rule, including
  rejection one byte short.
- **Sprites:** first and last rows, byte boundaries, all four multicolor pairs, transparency
  compositing onto `background`, two definitions separated by the 64th padding byte, `stride=63`
  packed data, and `sprite_colors` of the wrong length rejected.
- **Sources:** a mixed call — bitmap inline, screen from Ghidra, colour RAM from VICE; missing
  `bank_id` rejected; a VICE read past `$FFFF` rejected; invalid combinations and short sources
  asserted to perform **no remote reads**; two VICE sources while running rejected without
  `allow_non_atomic_vice_reads`, accepted with it and emitting the `non_atomic_vice_reads`
  warning in both summaries, and accepted with no warning while stopped.
- **Capture:** the full signature and its defaults; crop arithmetic; `crop=false` returning the
  debug buffer; `output_path` written atomically; existing path without `overwrite` rejected; a
  connector envelope failing each validation rule surfacing `vice_connector_incompatible`; a
  revision-1 connector handshake rejected with a clear message.
- **Registration:** `graphics` present in `static` and `full`, `vice_capture_screen` in `vice`
  and absent from `static`.
- **Limits:** every numeric cap at boundary and one past it, arithmetic overflow, malformed
  palette, malformed base64.
- **Summary:** exact field set present, and `structuredContent` asserted not to contain base64.

**Acceptance is a deterministic oracle.** Install known bitmap, screen and colour bytes into
VICE, capture the frame, and compare the cropped pixel-index matrix against the static decoder's
output for the same bytes — once for `hires_bitmap` and once for `multicolor_bitmap`. "Renders a
recognisable picture" is how the conventions were discovered; it is not how they are verified.
