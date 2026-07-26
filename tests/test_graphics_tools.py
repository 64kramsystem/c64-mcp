from __future__ import annotations

import base64
import io
import json
from pathlib import Path
from typing import Any

import pytest
from mcp.types import CallToolResult, ImageContent, TextContent
from PIL import Image

from c64_mcp.errors import RequestError
from c64_mcp.graphics.png import PNG_SIGNATURE
from c64_mcp.graphics.tools import (
    COMMON_SUMMARY_FIELDS,
    decode_c64_char_screen,
    decode_c64_charset,
    decode_c64_hires_bitmap,
    decode_c64_multicolor_bitmap,
    decode_c64_sprites,
)


class NoGhidra:
    def read_bytes(self, program: str, start: str, length: int) -> bytes:
        raise AssertionError("no Ghidra read was expected")


class NoVice:
    def status(self) -> dict[str, object]:
        return {"ok": True, "state": "stopped"}

    def read_memory(self, **kwargs: Any) -> dict[str, object]:
        raise AssertionError("no VICE read was expected")


def inline(data: bytes) -> dict[str, object]:
    return {"kind": "inline", "bytes": data.hex()}


def call(function: Any, **arguments: Any) -> CallToolResult:
    return function(NoGhidra(), NoVice(), **arguments)


def summary(result: CallToolResult) -> dict[str, Any]:
    assert result.structuredContent is not None
    return dict(result.structuredContent)


def image_bytes(result: CallToolResult) -> bytes:
    block = result.content[0]
    assert isinstance(block, ImageContent)
    assert block.mimeType == "image/png"
    return base64.b64decode(block.data, validate=True)


def pixels(result: CallToolResult) -> list[list[int]]:
    image = Image.open(io.BytesIO(image_bytes(result)))
    image.load()
    assert image.mode == "P"
    return [
        [image.getpixel((x, y)) for x in range(image.width)]
        for y in range(image.height)
    ]


def test_the_result_holds_one_image_and_one_json_summary() -> None:
    result = call(
        decode_c64_hires_bitmap,
        bitmap=inline(bytes(8)),
        screen=inline(bytes([0x10])),
        columns=1,
        rows=1,
    )

    assert isinstance(result, CallToolResult)
    assert len(result.content) == 2
    assert isinstance(result.content[0], ImageContent)
    assert isinstance(result.content[1], TextContent)
    assert image_bytes(result).startswith(PNG_SIGNATURE)
    assert json.loads(result.content[1].text) == summary(result)


def test_the_image_bytes_appear_exactly_once() -> None:
    result = call(
        decode_c64_hires_bitmap,
        bitmap=inline(bytes(8)),
        screen=inline(bytes([0x10])),
        columns=1,
        rows=1,
    )

    block = result.content[0]
    assert isinstance(block, ImageContent)
    assert result.model_dump_json().count(block.data) == 1


def test_structured_content_carries_no_base64() -> None:
    result = call(
        decode_c64_hires_bitmap,
        bitmap=inline(bytes(8)),
        screen=inline(bytes([0x10])),
        columns=1,
        rows=1,
    )

    block = result.content[0]
    assert isinstance(block, ImageContent)
    structured = json.dumps(summary(result))
    assert block.data not in structured
    assert "data" not in summary(result)
    assert "image" not in summary(result)


def test_the_summary_field_set_is_exact_for_a_bitmap_mode() -> None:
    result = call(
        decode_c64_hires_bitmap,
        bitmap=inline(bytes(8)),
        screen=inline(bytes([0x10])),
        columns=1,
        rows=1,
    )

    fields = summary(result)
    assert set(fields) == set(COMMON_SUMMARY_FIELDS)
    assert set(COMMON_SUMMARY_FIELDS) >= {
        "mode",
        "width",
        "height",
        "sources",
        "used_indices",
        "unmapped_indices",
        "unmapped_pixel_count",
        "warnings",
        "output_path",
    }
    assert fields["mode"] == "hires_bitmap"
    assert (fields["width"], fields["height"]) == (8, 8)
    assert fields["output_path"] is None
    assert fields["palette_size"] == 16
    assert fields["used_indices"] == [0]
    assert fields["unmapped_indices"] == []
    assert fields["unmapped_pixel_count"] == 0
    assert set(fields["sources"]) == {"bitmap", "screen"}
    assert set(fields["sources"]["bitmap"]) == {
        "kind",
        "supplied",
        "consumed",
        "trailing",
    }


def test_sprite_summaries_add_the_transparent_pixel_count() -> None:
    result = call(
        decode_c64_sprites,
        sprites=inline(bytes(63)),
        sprite_count=1,
        sprite_colors=[1],
    )

    fields = summary(result)
    assert set(fields) == set(COMMON_SUMMARY_FIELDS) | {
        "transparent_pixel_count"
    }
    assert fields["mode"] == "sprites"
    assert fields["transparent_pixel_count"] == 24 * 21


def test_charset_summaries_report_the_glyph_indices() -> None:
    result = call(
        decode_c64_charset,
        charset=inline(bytes(2 * 8)),
        glyph_count=2,
        sheet_columns=2,
    )

    fields = summary(result)
    assert set(fields) == set(COMMON_SUMMARY_FIELDS) | {"glyph_indices"}
    assert fields["mode"] == "charset"
    assert fields["glyph_indices"] == [0, 1]


def test_hires_pixels_survive_the_round_trip_through_pillow() -> None:
    bitmap = bytearray(32)
    bitmap[0] = 0x80
    bitmap[8] = 0x01
    bitmap[16] = 0xF0
    bitmap[24] = 0x0F

    result = call(
        decode_c64_hires_bitmap,
        bitmap=inline(bytes(bitmap)),
        screen=inline(bytes([0x12, 0x34, 0x56, 0x78])),
        columns=2,
        rows=2,
    )

    matrix = pixels(result)
    assert matrix[0] == [
        1, 2, 2, 2, 2, 2, 2, 2,
        4, 4, 4, 4, 4, 4, 4, 3,
    ]  # fmt: skip
    assert matrix[8] == [
        5, 5, 5, 5, 6, 6, 6, 6,
        8, 8, 8, 8, 7, 7, 7, 7,
    ]  # fmt: skip
    assert summary(result)["used_indices"] == [1, 2, 3, 4, 5, 6, 7, 8]


def test_multicolor_pixels_survive_the_round_trip_through_pillow() -> None:
    bitmap = bytearray(8)
    bitmap[0] = 0x1B

    result = call(
        decode_c64_multicolor_bitmap,
        bitmap=inline(bytes(bitmap)),
        screen=inline(bytes([0x27])),
        color=inline(bytes([0x5D])),
        columns=1,
        rows=1,
        background=6,
    )

    assert pixels(result)[0] == [6, 6, 2, 2, 7, 7, 13, 13]


def test_char_screen_pixels_survive_the_round_trip_through_pillow() -> None:
    charset = bytearray(4 * 8)
    charset[0] = 0xA5
    charset[8] = 0x1B
    charset[16] = 0xE4
    charset[24] = 0xFF

    result = call(
        decode_c64_char_screen,
        screen=inline(bytes([0, 1, 2, 3])),
        charset=inline(bytes(charset)),
        color=inline(bytes([0x02, 0x0A, 0x08, 0x0F])),
        columns=4,
        rows=1,
        background=6,
        multicolor=True,
        background_1=4,
        background_2=5,
    )

    assert pixels(result)[0] == [
        2, 6, 2, 6, 6, 2, 6, 2,
        6, 6, 4, 4, 5, 5, 2, 2,
        0, 0, 5, 5, 4, 4, 6, 6,
        7, 7, 7, 7, 7, 7, 7, 7,
    ]  # fmt: skip


def test_charset_pixels_survive_the_round_trip_through_pillow() -> None:
    charset = bytearray(17 * 8)
    charset[0] = 0x80
    charset[15 * 8] = 0xFF
    charset[16 * 8] = 0x81

    result = call(
        decode_c64_charset,
        charset=inline(bytes(charset)),
        glyph_count=17,
        sheet_columns=16,
        foreground=1,
        background=0,
    )

    matrix = pixels(result)
    assert len(matrix) == 16
    assert matrix[0][0] == 1
    assert matrix[0][1:120] == [0] * 119
    assert matrix[0][120:128] == [1] * 8
    assert matrix[8][:8] == [1, 0, 0, 0, 0, 0, 0, 1]
    assert summary(result)["glyph_indices"] == list(range(17))


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"columns": 2**62, "rows": 25}, "columns"),
        ({"columns": 40, "rows": 2**62}, "rows"),
        ({"columns": -(2**62), "rows": 25}, "columns"),
    ],
)
def test_absurd_geometry_is_rejected_before_any_allocation(
    arguments: dict[str, int], message: str
) -> None:
    with pytest.raises(RequestError, match=message):
        call(
            decode_c64_hires_bitmap,
            bitmap=inline(bytes(8)),
            screen=inline(bytes(1)),
            **arguments,
        )


@pytest.mark.parametrize(
    ("tool", "arguments", "message"),
    [
        (
            decode_c64_charset,
            {"charset": {"kind": "inline", "bytes": ""}, "glyph_count": 2**62},
            "glyph_count",
        ),
        (
            decode_c64_sprites,
            {
                "sprites": {"kind": "inline", "bytes": ""},
                "sprite_count": 2**62,
                "sprite_colors": [1],
            },
            "sprite_count",
        ),
        (
            decode_c64_sprites,
            {
                "sprites": {"kind": "inline", "bytes": ""},
                "sprite_count": 1,
                "sprite_colors": [1],
                "sprite_stride": 2**62,
            },
            "sprite_stride",
        ),
    ],
)
def test_absurd_counts_are_rejected_before_any_allocation(
    tool: Any, arguments: dict[str, Any], message: str
) -> None:
    with pytest.raises(RequestError, match=message):
        call(tool, **arguments)


def test_the_default_geometry_is_the_c64_screen() -> None:
    result = call(
        decode_c64_hires_bitmap,
        bitmap=inline(bytes(40 * 25 * 8)),
        screen=inline(bytes(40 * 25)),
    )

    fields = summary(result)
    assert (fields["width"], fields["height"]) == (320, 200)


def test_the_default_charset_sheet_is_sixteen_glyphs_wide() -> None:
    result = call(
        decode_c64_charset, charset=inline(bytes(256 * 8))
    )

    fields = summary(result)
    assert (fields["width"], fields["height"]) == (128, 128)


def test_the_default_sprite_sheet_is_eight_sprites_wide() -> None:
    result = call(
        decode_c64_sprites,
        sprites=inline(bytes(8 * 64)),
        sprite_count=8,
        sprite_colors=[1] * 8,
    )

    fields = summary(result)
    assert (fields["width"], fields["height"]) == (192, 21)


def test_a_caller_palette_replaces_pepto_pal() -> None:
    result = call(
        decode_c64_hires_bitmap,
        bitmap=inline(bytes(8)),
        screen=inline(bytes([0x01])),
        columns=1,
        rows=1,
        palette=["#102030", "#405060"],
    )

    image = Image.open(io.BytesIO(image_bytes(result)))
    table = image.getpalette()
    assert table is not None
    assert table[:6] == [0x10, 0x20, 0x30, 0x40, 0x50, 0x60]
    assert summary(result)["palette_size"] == 2


def test_indices_beyond_a_short_palette_are_reported_and_black() -> None:
    result = call(
        decode_c64_hires_bitmap,
        bitmap=inline(bytes([0x80]) + bytes(7)),
        screen=inline(bytes([0x50])),
        columns=1,
        rows=1,
        palette=["#ffffff"],
    )

    fields = summary(result)
    assert fields["unmapped_indices"] == [5]
    assert fields["unmapped_pixel_count"] == 1
    assert fields["palette_size"] == 6
    image = Image.open(io.BytesIO(image_bytes(result)))
    table = image.getpalette()
    assert table is not None
    assert table[15:18] == [0, 0, 0]


def test_output_path_writes_the_png_and_leaves_no_temporary_files(
    tmp_path: Path,
) -> None:
    target = tmp_path / "hires.png"

    result = call(
        decode_c64_hires_bitmap,
        bitmap=inline(bytes(8)),
        screen=inline(bytes([0x10])),
        columns=1,
        rows=1,
        output_path=str(target),
    )

    assert summary(result)["output_path"] == str(target)
    assert target.read_bytes() == image_bytes(result)
    assert list(tmp_path.iterdir()) == [target]


def test_an_existing_output_path_is_refused_without_overwrite(
    tmp_path: Path,
) -> None:
    target = tmp_path / "hires.png"
    target.write_bytes(b"keep me")

    with pytest.raises(RequestError, match="overwrite"):
        call(
            decode_c64_hires_bitmap,
            bitmap=inline(bytes(8)),
            screen=inline(bytes([0x10])),
            columns=1,
            rows=1,
            output_path=str(target),
        )

    assert target.read_bytes() == b"keep me"


def test_overwrite_replaces_an_existing_output_path(
    tmp_path: Path,
) -> None:
    target = tmp_path / "hires.png"
    target.write_bytes(b"replace me")

    result = call(
        decode_c64_hires_bitmap,
        bitmap=inline(bytes(8)),
        screen=inline(bytes([0x10])),
        columns=1,
        rows=1,
        output_path=str(target),
        overwrite=True,
    )

    assert target.read_bytes() == image_bytes(result)
    assert list(tmp_path.iterdir()) == [target]


def test_a_blank_output_path_is_rejected() -> None:
    with pytest.raises(RequestError, match="output_path"):
        call(
            decode_c64_hires_bitmap,
            bitmap=inline(bytes(8)),
            screen=inline(bytes([0x10])),
            columns=1,
            rows=1,
            output_path="  ",
        )


def test_char_screen_without_colour_ram_uses_the_foreground_argument() -> None:
    result = call(
        decode_c64_char_screen,
        screen=inline(bytes([0])),
        charset=inline(bytes([0x80]) + bytes(7)),
        columns=1,
        rows=1,
        foreground=3,
        background=6,
    )

    assert pixels(result)[0] == [3, 6, 6, 6, 6, 6, 6, 6]
    assert set(summary(result)["sources"]) == {"screen", "charset"}


def test_sprite_transparency_composites_onto_the_background() -> None:
    data = bytearray(63)
    data[0] = 0x1B

    result = call(
        decode_c64_sprites,
        sprites=inline(bytes(data)),
        sprite_count=1,
        sprite_colors=[7],
        multicolor=True,
        multicolor_0=4,
        multicolor_1=5,
        background=6,
    )

    assert pixels(result)[0][:8] == [6, 6, 4, 4, 7, 7, 5, 5]
    assert summary(result)["transparent_pixel_count"] == 498
