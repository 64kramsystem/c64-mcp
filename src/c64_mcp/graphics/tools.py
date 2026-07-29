"""The five per-mode C64 graphics decoders exposed as MCP tools.

Each tool fetches exactly the bytes its geometry needs, renders one VIC-II mode
into colour indices, and returns an indexed PNG together with a summary of what
was read and what was drawn. Nothing here writes to a program or to VICE.

The result is an explicit `CallToolResult` holding one `ImageContent`, one
textual JSON summary, and `structuredContent` carrying only that summary: the
image bytes appear exactly once, never duplicated into structured output.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from mcp.types import CallToolResult, ImageContent, TextContent

from ..errors import RequestError
from .modes import (
    Raster,
    cell_geometry,
    charset_bytes_required,
    charset_layout,
    colour_index,
    render_char_screen,
    render_charset,
    render_hires_bitmap,
    render_multicolor_bitmap,
    render_sprites,
    sprite_layout,
)
from .palette import PEPTO_PAL, Rgb
from .png import encode_indexed_png
from .sources import (
    GraphicsGhidraClient,
    SourcePlan,
    parse_source,
    validate_inline_source,
)

GLYPH_BYTES = 8


def decode_c64_hires_bitmap(
    ghidra: GraphicsGhidraClient,
    *,
    bitmap: object,
    screen: object,
    columns: int = 40,
    rows: int = 25,
    output_path: str | None = None,
    overwrite: bool = False,
) -> CallToolResult:
    """Render standard bitmap mode from bitmap and video-matrix bytes."""

    target = output_target(output_path, overwrite)
    colours = list(PEPTO_PAL)
    columns, rows = cell_geometry(columns, rows)
    bitmap_spec = parse_source(bitmap, "bitmap")
    screen_spec = parse_source(screen, "screen")
    validate_inline_source(bitmap_spec, columns * rows * GLYPH_BYTES)
    validate_inline_source(screen_spec, columns * rows)
    plan = SourcePlan(ghidra)
    raster = render_hires_bitmap(
        bitmap=plan.load(bitmap_spec, columns * rows * GLYPH_BYTES),
        screen=plan.load(screen_spec, columns * rows),
        columns=columns,
        rows=rows,
    )
    return _emit("hires_bitmap", raster, plan, colours, target, overwrite)


def decode_c64_multicolor_bitmap(
    ghidra: GraphicsGhidraClient,
    *,
    bitmap: object,
    screen: object,
    color: object,
    columns: int = 40,
    rows: int = 25,
    background: int = 0,
    output_path: str | None = None,
    overwrite: bool = False,
) -> CallToolResult:
    """Render multicolor bitmap mode from bitmap, screen, and colour RAM."""

    target = output_target(output_path, overwrite)
    colours = list(PEPTO_PAL)
    columns, rows = cell_geometry(columns, rows)
    background = colour_index(background, "background")
    bitmap_spec = parse_source(bitmap, "bitmap")
    screen_spec = parse_source(screen, "screen")
    color_spec = parse_source(color, "color")
    validate_inline_source(bitmap_spec, columns * rows * GLYPH_BYTES)
    validate_inline_source(screen_spec, columns * rows)
    validate_inline_source(color_spec, columns * rows)
    plan = SourcePlan(ghidra)
    raster = render_multicolor_bitmap(
        bitmap=plan.load(bitmap_spec, columns * rows * GLYPH_BYTES),
        screen=plan.load(screen_spec, columns * rows),
        color=plan.load(color_spec, columns * rows),
        columns=columns,
        rows=rows,
        background=background,
    )
    return _emit("multicolor_bitmap", raster, plan, colours, target, overwrite)


def decode_c64_charset(
    ghidra: GraphicsGhidraClient,
    *,
    charset: object,
    glyph_count: int = 256,
    sheet_columns: int = 16,
    foreground: int = 1,
    background: int = 0,
    multicolor: bool = False,
    background_1: int | None = None,
    background_2: int | None = None,
    output_path: str | None = None,
    overwrite: bool = False,
) -> CallToolResult:
    """Render a character set as a sheet of 8x8 glyphs."""

    target = output_target(output_path, overwrite)
    colours = list(PEPTO_PAL)
    layout = charset_layout(
        glyph_count=glyph_count,
        sheet_columns=sheet_columns,
        foreground=foreground,
        background=background,
        multicolor=multicolor,
        background_1=background_1,
        background_2=background_2,
    )
    charset_spec = parse_source(charset, "charset")
    plan = SourcePlan(ghidra)
    raster = render_charset(
        charset=plan.load(charset_spec, layout.required),
        glyph_count=glyph_count,
        sheet_columns=sheet_columns,
        foreground=foreground,
        background=background,
        multicolor=multicolor,
        background_1=background_1,
        background_2=background_2,
    )
    return _emit(
        "charset",
        raster,
        plan,
        colours,
        target,
        overwrite,
        extra={"glyph_indices": list(raster.glyph_indices)},
    )


def decode_c64_char_screen(
    ghidra: GraphicsGhidraClient,
    *,
    screen: object,
    charset: object,
    color: object | None = None,
    columns: int = 40,
    rows: int = 25,
    background: int = 0,
    foreground: int = 1,
    multicolor: bool = False,
    background_1: int | None = None,
    background_2: int | None = None,
    output_path: str | None = None,
    overwrite: bool = False,
) -> CallToolResult:
    """Render text mode: screen codes indexing a character set."""

    target = output_target(output_path, overwrite)
    colours = list(PEPTO_PAL)
    columns, rows = cell_geometry(columns, rows)
    background = colour_index(background, "background")
    foreground = colour_index(foreground, "foreground")
    if not isinstance(multicolor, bool):
        raise RequestError("multicolor must be a boolean")
    if multicolor:
        if color is None:
            raise RequestError(
                "color is required when multicolor is true: colour-RAM bit 3 "
                "selects each cell's mode"
            )
        colour_index(background_1, "background_1")
        colour_index(background_2, "background_2")
    screen_spec = parse_source(screen, "screen")
    charset_spec = parse_source(charset, "charset")
    color_spec = None if color is None else parse_source(color, "color")
    validate_inline_source(screen_spec, columns * rows)
    if color_spec is not None:
        validate_inline_source(color_spec, columns * rows)
    plan = SourcePlan(ghidra)
    screen_bytes = plan.load(screen_spec, columns * rows)
    # The charset requirement is not knowable until the screen codes are in
    # hand: only glyphs up to the highest code present have to be supplied.
    charset_bytes = plan.load(
        charset_spec, charset_bytes_required(screen_bytes[: columns * rows])
    )
    color_bytes = None if color_spec is None else plan.load(color_spec, columns * rows)
    raster = render_char_screen(
        screen=screen_bytes,
        charset=charset_bytes,
        color=color_bytes,
        columns=columns,
        rows=rows,
        background=background,
        foreground=foreground,
        multicolor=multicolor,
        background_1=background_1,
        background_2=background_2,
    )
    return _emit("char_screen", raster, plan, colours, target, overwrite)


def decode_c64_sprites(
    ghidra: GraphicsGhidraClient,
    *,
    sprites: object,
    sprite_count: int,
    sprite_colors: Sequence[int],
    sprite_stride: int = 64,
    sheet_columns: int = 8,
    multicolor: bool = False,
    multicolor_0: int | None = None,
    multicolor_1: int | None = None,
    background: int = 0,
    output_path: str | None = None,
    overwrite: bool = False,
) -> CallToolResult:
    """Render sprite definitions onto a sheet over a background colour."""

    target = output_target(output_path, overwrite)
    colours = list(PEPTO_PAL)
    # Validating up front keeps a bad request from costing a remote read.
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
    sprites_spec = parse_source(sprites, "sprites")
    plan = SourcePlan(ghidra)
    raster = render_sprites(
        data=plan.load(sprites_spec, layout.required),
        sprite_count=sprite_count,
        sprite_stride=sprite_stride,
        sheet_columns=sheet_columns,
        sprite_colors=sprite_colors,
        multicolor=multicolor,
        multicolor_0=multicolor_0,
        multicolor_1=multicolor_1,
        background=background,
    )
    return _emit(
        "sprites",
        raster,
        plan,
        colours,
        target,
        overwrite,
        extra={"transparent_pixel_count": raster.transparent_pixel_count},
    )


def output_target(output_path: object, overwrite: object) -> Path | None:
    """Validate an optional output path before anything is read or rendered."""

    if not isinstance(overwrite, bool):
        raise RequestError("overwrite must be a boolean")
    if output_path is None:
        return None
    if not isinstance(output_path, str) or not output_path.strip():
        raise RequestError("output_path must be a nonblank path")
    target = Path(output_path).expanduser()
    if target.exists() and not overwrite:
        raise RequestError(
            f"output_path {target} already exists; pass overwrite=true to replace it"
        )
    parent = target.parent
    if not parent.is_dir():
        raise RequestError(f"output_path directory {parent} does not exist")
    return target


def write_atomically(target: Path, data: bytes, overwrite: bool) -> None:
    if target.exists() and not overwrite:
        raise RequestError(
            f"output_path {target} already exists; pass overwrite=true to replace it"
        )
    handle, temporary = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".part"
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _emit(
    mode: str,
    raster: Raster,
    plan: SourcePlan,
    palette: list[Rgb],
    target: Path | None,
    overwrite: bool,
    extra: dict[str, Any] | None = None,
) -> CallToolResult:
    encoded = encode_indexed_png(raster.rows, palette)
    if target is not None:
        write_atomically(target, encoded.data, overwrite)
    summary: dict[str, Any] = {
        "mode": mode,
        "width": encoded.width,
        "height": encoded.height,
        "sources": plan.summary(),
        "palette_size": encoded.palette_size,
        "used_indices": list(encoded.used_indices),
        "output_path": None if target is None else str(target),
    }
    if extra:
        summary.update(extra)
    return CallToolResult(
        content=[
            ImageContent(
                type="image",
                data=base64.b64encode(encoded.data).decode("ascii"),
                mimeType="image/png",
            ),
            TextContent(
                type="text",
                text=json.dumps(summary, indent=2, sort_keys=True),
            ),
        ],
        structuredContent=summary,
    )
