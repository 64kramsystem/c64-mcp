"""VIC-II graphics modes: the conventions that get re-derived and misremembered.

Every renderer here produces a matrix of C64 colour indices (0-15), never RGB,
so the logical colour survives into the PNG palette. Sources are plain bytes;
fetching them is `sources.py`'s job.

Shared C64 facts encoded below:

* Bitmap memory is *cell*-interleaved, not linear: the eight bytes of one 8x8
  cell are consecutive, and cells run row-major. The byte holding pixel row `r`
  of the cell at column `c` of cell row `R` is at `R*columns*8 + c*8 + r`.
* In every mode the most significant bit is the leftmost pixel.
* Multicolor modes take two bits per pixel and double each pixel horizontally,
  so a cell is 4 pixels wide at 8 pixels of screen width, and the two-bit value
  selects one of four colour sources.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..errors import GraphicsLimitError, RequestError

MAX_CELL_COLUMNS = 64
MAX_CELL_ROWS = 64
MAX_CELLS = 2048
MAX_GLYPHS = 256
MAX_SPRITES = 256
MAX_SHEET_COLUMNS = 64
MAX_COLOUR_INDEX = 15
GLYPH_BYTES = 8
SPRITE_BYTES = 63
SPRITE_WIDTH = 24
SPRITE_HEIGHT = 21
SPRITE_ROW_BYTES = 3
ACCEPTED_SPRITE_STRIDES = (63, 64)


@dataclass(frozen=True, slots=True)
class CharsetLayout:
    """A validated character-sheet request and the bytes it needs."""

    glyph_count: int
    sheet_columns: int
    foreground: int
    background: int
    pairs: tuple[int, int, int, int] | None
    required: int


@dataclass(frozen=True, slots=True)
class SpriteLayout:
    """A validated sprite-sheet request and the bytes it needs."""

    sprite_count: int
    sprite_stride: int
    sheet_columns: int
    colours: tuple[int, ...]
    background: int
    shared: tuple[int, int] | None
    required: int


@dataclass(frozen=True, slots=True)
class Raster:
    """One rendered image as rows of colour indices."""

    width: int
    height: int
    rows: list[bytearray]
    transparent_pixel_count: int = 0
    glyph_indices: tuple[int, ...] = ()


def colour_index(value: object, name: str) -> int:
    """Validate one VIC-II colour index."""

    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > MAX_COLOUR_INDEX
    ):
        raise RequestError(
            f"{name} must be a colour index from 0 to {MAX_COLOUR_INDEX}"
        )
    return value


def bounded(value: object, name: str, minimum: int, maximum: int) -> int:
    """Validate one contractual integer range."""

    if not isinstance(value, int) or isinstance(value, bool):
        raise RequestError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise RequestError(f"{name} must be from {minimum} to {maximum}")
    return value


def cell_geometry(columns: object, rows: object) -> tuple[int, int]:
    """Validate a character/bitmap cell geometry and its total-cell budget."""

    width = bounded(columns, "columns", 1, MAX_CELL_COLUMNS)
    height = bounded(rows, "rows", 1, MAX_CELL_ROWS)
    if width * height > MAX_CELLS:
        raise GraphicsLimitError(
            f"columns * rows is {width * height}, which exceeds the "
            f"{MAX_CELLS}-cell hard maximum"
        )
    return width, height


def sheet_geometry(count: int, sheet_columns: int) -> tuple[int, int]:
    """Return the (columns, rows) of a sheet holding count items."""

    return sheet_columns, (count + sheet_columns - 1) // sheet_columns


def charset_bytes_required(screen: bytes) -> int:
    """Return the charset length implied by the highest screen code present."""

    if not screen:
        raise RequestError("screen must not be empty")
    return (max(screen) + 1) * GLYPH_BYTES


def require_length(data: bytes, name: str, required: int) -> None:
    """Refuse a source that cannot cover the requested geometry."""

    if len(data) < required:
        raise RequestError(
            f"{name} supplies {len(data)} bytes but {required} are required"
        )


def render_hires_bitmap(
    *,
    bitmap: bytes,
    screen: bytes,
    columns: int,
    rows: int,
) -> Raster:
    """Render standard bitmap mode: one bit per pixel, colours from the screen.

    In hires bitmap mode ($D011 bit 5 set, $D016 bit 4 clear) the video matrix
    is not screen codes but per-cell colours: a set bit takes the high nybble
    of the cell's screen byte, a clear bit its low nybble. Colour RAM is unused.
    """

    columns, rows = cell_geometry(columns, rows)
    bitmap_required = columns * rows * GLYPH_BYTES
    screen_required = columns * rows
    require_length(bitmap, "bitmap", bitmap_required)
    require_length(screen, "screen", screen_required)

    width = columns * 8
    height = rows * 8
    raster = _blank(width, height, 0)
    for cell_row in range(rows):
        for cell_column in range(columns):
            cell = screen[cell_row * columns + cell_column]
            foreground = (cell >> 4) & 0x0F
            background = cell & 0x0F
            base = cell_row * columns * GLYPH_BYTES + cell_column * GLYPH_BYTES
            for line in range(8):
                pixels = bitmap[base + line]
                target = raster[cell_row * 8 + line]
                left = cell_column * 8
                for bit in range(8):
                    target[left + bit] = (
                        foreground if pixels & (0x80 >> bit) else background
                    )
    return Raster(
        width=width,
        height=height,
        rows=raster,
    )


def render_multicolor_bitmap(
    *,
    bitmap: bytes,
    screen: bytes,
    color: bytes,
    columns: int,
    rows: int,
    background: int = 0,
) -> Raster:
    """Render multicolor bitmap mode: two bits per pixel, four colour sources.

    With $D016 bit 4 set the bitmap is read in pixel pairs, each doubled
    horizontally: `00` is the background register ($D021), `01` the screen
    byte's high nybble, `10` its low nybble, and `11` the colour-RAM low nybble.
    """

    columns, rows = cell_geometry(columns, rows)
    background = colour_index(background, "background")
    bitmap_required = columns * rows * GLYPH_BYTES
    cell_required = columns * rows
    require_length(bitmap, "bitmap", bitmap_required)
    require_length(screen, "screen", cell_required)
    require_length(color, "color", cell_required)

    width = columns * 8
    height = rows * 8
    raster = _blank(width, height, background)
    for cell_row in range(rows):
        for cell_column in range(columns):
            index = cell_row * columns + cell_column
            cell = screen[index]
            sources = (
                background,
                (cell >> 4) & 0x0F,
                cell & 0x0F,
                color[index] & 0x0F,
            )
            base = cell_row * columns * GLYPH_BYTES + cell_column * GLYPH_BYTES
            for line in range(8):
                pixels = bitmap[base + line]
                target = raster[cell_row * 8 + line]
                left = cell_column * 8
                for pair in range(4):
                    value = (pixels >> (6 - pair * 2)) & 0x03
                    colour = sources[value]
                    target[left + pair * 2] = colour
                    target[left + pair * 2 + 1] = colour
    return Raster(
        width=width,
        height=height,
        rows=raster,
    )


def charset_layout(
    *,
    glyph_count: object = 256,
    sheet_columns: object = 16,
    foreground: object = 1,
    background: object = 0,
    multicolor: object = False,
    background_1: object = None,
    background_2: object = None,
) -> CharsetLayout:
    """Validate a character-sheet request without touching any bytes."""

    count = bounded(glyph_count, "glyph_count", 1, MAX_GLYPHS)
    columns = bounded(sheet_columns, "sheet_columns", 1, MAX_SHEET_COLUMNS)
    ink = colour_index(foreground, "foreground")
    paper = colour_index(background, "background")
    if not isinstance(multicolor, bool):
        raise RequestError("multicolor must be a boolean")
    pairs = _multicolor_pairs(multicolor, paper, background_1, background_2, ink & 0x07)
    return CharsetLayout(
        glyph_count=count,
        sheet_columns=columns,
        foreground=ink,
        background=paper,
        pairs=pairs,
        required=count * GLYPH_BYTES,
    )


def render_charset(
    *,
    charset: bytes,
    glyph_count: int = 256,
    sheet_columns: int = 16,
    foreground: int = 1,
    background: int = 0,
    multicolor: bool = False,
    background_1: int | None = None,
    background_2: int | None = None,
) -> Raster:
    """Render a character set as a sheet of 8x8 glyphs, row-major.

    Glyph indices are reported in the summary rather than drawn, so the sheet
    stays a faithful pixel rendering. A partly filled final row is padded with
    the background colour.
    """

    layout = charset_layout(
        glyph_count=glyph_count,
        sheet_columns=sheet_columns,
        foreground=foreground,
        background=background,
        multicolor=multicolor,
        background_1=background_1,
        background_2=background_2,
    )
    glyph_count = layout.glyph_count
    sheet_columns = layout.sheet_columns
    foreground = layout.foreground
    background = layout.background
    pairs = layout.pairs
    required = layout.required
    require_length(charset, "charset", required)

    sheet_wide, sheet_high = sheet_geometry(glyph_count, sheet_columns)
    width = sheet_wide * 8
    height = sheet_high * 8
    raster = _blank(width, height, background)
    for glyph in range(glyph_count):
        left = (glyph % sheet_columns) * 8
        top = (glyph // sheet_columns) * 8
        base = glyph * GLYPH_BYTES
        for line in range(8):
            pixels = charset[base + line]
            target = raster[top + line]
            if pairs is None:
                for bit in range(8):
                    target[left + bit] = (
                        foreground if pixels & (0x80 >> bit) else background
                    )
            else:
                _paint_multicolor(target, left, pixels, pairs)
    return Raster(
        width=width,
        height=height,
        rows=raster,
        glyph_indices=tuple(range(glyph_count)),
    )


def render_char_screen(
    *,
    screen: bytes,
    charset: bytes,
    color: bytes | None,
    columns: int,
    rows: int,
    background: int = 0,
    foreground: int = 1,
    multicolor: bool = False,
    background_1: int | None = None,
    background_2: int | None = None,
) -> Raster:
    """Render text mode: screen codes indexing a character set.

    With `multicolor` false every cell is hires: one bit per pixel, the
    foreground being the cell's colour-RAM nybble when colour RAM is supplied
    and the `foreground` argument otherwise.

    With `multicolor` true ($D016 bit 4 set) the mode is chosen **per cell** by
    colour-RAM bit 3. Bit 3 clear leaves the cell hires with bits 0-2 as its
    foreground; bit 3 set makes it multicolor, where `00` is $D021, `01` is
    $D022 (`background_1`), `10` is $D023 (`background_2`), and `11` is the low
    three bits of the cell's colour nybble.
    """

    columns, rows = cell_geometry(columns, rows)
    background = colour_index(background, "background")
    foreground = colour_index(foreground, "foreground")
    shared: tuple[int, int] | None = None
    if multicolor:
        if color is None:
            raise RequestError(
                "color is required when multicolor is true: colour-RAM bit 3 "
                "selects each cell's mode"
            )
        shared = (
            colour_index(background_1, "background_1"),
            colour_index(background_2, "background_2"),
        )
    cell_required = columns * rows
    require_length(screen, "screen", cell_required)
    if color is not None:
        require_length(color, "color", cell_required)
    charset_required = charset_bytes_required(screen[:cell_required])
    require_length(charset, "charset", charset_required)

    width = columns * 8
    height = rows * 8
    raster = _blank(width, height, background)
    for cell_row in range(rows):
        for cell_column in range(columns):
            index = cell_row * columns + cell_column
            base = screen[index] * GLYPH_BYTES
            nybble = foreground if color is None else color[index] & 0x0F
            pairs: tuple[int, int, int, int] | None = None
            if shared is not None and nybble & 0x08:
                pairs = (background, shared[0], shared[1], nybble & 0x07)
            cell_foreground = nybble & 0x07 if multicolor else nybble
            left = cell_column * 8
            for line in range(8):
                pixels = charset[base + line]
                target = raster[cell_row * 8 + line]
                if pairs is None:
                    for bit in range(8):
                        target[left + bit] = (
                            cell_foreground if pixels & (0x80 >> bit) else background
                        )
                else:
                    _paint_multicolor(target, left, pixels, pairs)
    return Raster(width=width, height=height, rows=raster)


def sprite_layout(
    *,
    sprite_count: object,
    sprite_stride: object = 64,
    sheet_columns: object = 8,
    sprite_colors: object,
    multicolor: object = False,
    multicolor_0: object = None,
    multicolor_1: object = None,
    background: object = 0,
) -> SpriteLayout:
    """Validate a sprite-sheet request without touching any bytes."""

    count = bounded(sprite_count, "sprite_count", 1, MAX_SPRITES)
    if sprite_stride not in ACCEPTED_SPRITE_STRIDES:
        raise RequestError(
            "sprite_stride must be 64 for padded definition blocks or 63 "
            "for packed records"
        )
    assert isinstance(sprite_stride, int)
    columns = bounded(sheet_columns, "sheet_columns", 1, MAX_SHEET_COLUMNS)
    paper = colour_index(background, "background")
    if not isinstance(sprite_colors, (list, tuple)):
        raise RequestError("sprite_colors must be an array of colour indices")
    if len(sprite_colors) != count:
        raise RequestError(
            f"sprite_colors holds {len(sprite_colors)} entries but "
            f"sprite_count is {count}"
        )
    colours = tuple(
        colour_index(value, f"sprite_colors[{index}]")
        for index, value in enumerate(sprite_colors)
    )
    if not isinstance(multicolor, bool):
        raise RequestError("multicolor must be a boolean")
    shared: tuple[int, int] | None = None
    if multicolor:
        shared = (
            colour_index(multicolor_0, "multicolor_0"),
            colour_index(multicolor_1, "multicolor_1"),
        )
    return SpriteLayout(
        sprite_count=count,
        sprite_stride=sprite_stride,
        sheet_columns=columns,
        colours=colours,
        background=paper,
        shared=shared,
        required=(count - 1) * sprite_stride + SPRITE_BYTES,
    )


def render_sprites(
    *,
    data: bytes,
    sprite_count: int,
    sprite_colors: Sequence[int],
    sprite_stride: int = 64,
    sheet_columns: int = 8,
    multicolor: bool = False,
    multicolor_0: int | None = None,
    multicolor_1: int | None = None,
    background: int = 0,
) -> Raster:
    """Render sprite definitions onto a sheet, compositing over a background.

    A sprite is 63 bytes: 21 rows of 3 bytes, 24 hires pixels or 12 multicolor
    pixels doubled horizontally. Definitions normally occupy 64-byte blocks
    ($07F8-$07FF hold pointers to them in units of 64), so `sprite_stride`
    defaults to 64 and the 64th byte is padding; a packed 63-byte record layout
    is the other accepted stride.

    Multicolor sprites ($D01C) take `01` from $D025, `11` from $D026, and `10`
    from the sprite's own colour register; `00` is transparent and here shows
    the `background` colour.
    """

    layout = sprite_layout(
        sprite_count=sprite_count,
        sprite_stride=sprite_stride,
        sheet_columns=sheet_columns,
        sprite_colors=sprite_colors,
        multicolor=multicolor,
        multicolor_0=multicolor_0,
        multicolor_1=multicolor_1,
        background=background,
    )
    sprite_count = layout.sprite_count
    sprite_stride = layout.sprite_stride
    sheet_columns = layout.sheet_columns
    background = layout.background
    colours = list(layout.colours)
    required = layout.required
    require_length(data, "sprites", required)

    sheet_wide, sheet_high = sheet_geometry(sprite_count, sheet_columns)
    width = sheet_wide * SPRITE_WIDTH
    height = sheet_high * SPRITE_HEIGHT
    raster = _blank(width, height, background)
    transparent = 0
    for sprite in range(sprite_count):
        left = (sprite % sheet_columns) * SPRITE_WIDTH
        top = (sprite // sheet_columns) * SPRITE_HEIGHT
        base = sprite * sprite_stride
        colour = colours[sprite]
        pairs = (
            (background, layout.shared[0], colour, layout.shared[1])
            if layout.shared is not None
            else None
        )
        for line in range(SPRITE_HEIGHT):
            target = raster[top + line]
            for byte in range(SPRITE_ROW_BYTES):
                pixels = data[base + line * SPRITE_ROW_BYTES + byte]
                offset = left + byte * 8
                if pairs is None:
                    for bit in range(8):
                        if pixels & (0x80 >> bit):
                            target[offset + bit] = colour
                        else:
                            target[offset + bit] = background
                            transparent += 1
                else:
                    for pair in range(4):
                        value = (pixels >> (6 - pair * 2)) & 0x03
                        target[offset + pair * 2] = pairs[value]
                        target[offset + pair * 2 + 1] = pairs[value]
                        if value == 0:
                            transparent += 2
    return Raster(
        width=width,
        height=height,
        rows=raster,
        transparent_pixel_count=transparent,
    )


def _multicolor_pairs(
    multicolor: bool,
    background: int,
    background_1: object,
    background_2: object,
    high: int,
) -> tuple[int, int, int, int] | None:
    if not multicolor:
        return None
    return (
        background,
        colour_index(background_1, "background_1"),
        colour_index(background_2, "background_2"),
        high,
    )


def _paint_multicolor(
    target: bytearray,
    left: int,
    pixels: int,
    pairs: tuple[int, int, int, int],
) -> None:
    for pair in range(4):
        colour = pairs[(pixels >> (6 - pair * 2)) & 0x03]
        target[left + pair * 2] = colour
        target[left + pair * 2 + 1] = colour


def _blank(width: int, height: int, fill: int) -> list[bytearray]:
    return [bytearray([fill]) * width for _ in range(height)]
