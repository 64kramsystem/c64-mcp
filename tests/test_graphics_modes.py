from __future__ import annotations

import pytest

from c64_mcp.errors import GraphicsLimitError, RequestError
from c64_mcp.graphics.modes import (
    charset_bytes_required,
    render_char_screen,
    render_charset,
    render_hires_bitmap,
    render_multicolor_bitmap,
    render_sprites,
)


def blank(length: int) -> bytearray:
    return bytearray(length)


def test_hires_cells_interleave_across_two_by_two_cells() -> None:
    # columns=2, rows=2 => 16x16 pixels, 32 bitmap bytes.
    # Markers at 0 (cell 0,0 row 0), 8 (cell 0,1 row 0) and
    # columns*8 = 16 (cell 1,0 row 0), plus 24 (cell 1,1 row 0).
    bitmap = blank(32)
    bitmap[0] = 0x80
    bitmap[8] = 0x01
    bitmap[16] = 0xF0
    bitmap[24] = 0x0F
    screen = bytes([0x12, 0x34, 0x56, 0x78])

    raster = render_hires_bitmap(
        bitmap=bytes(bitmap), screen=screen, columns=2, rows=2
    )

    assert (raster.width, raster.height) == (16, 16)
    assert list(raster.rows[0]) == [
        1, 2, 2, 2, 2, 2, 2, 2,
        4, 4, 4, 4, 4, 4, 4, 3,
    ]  # fmt: skip
    for y in range(1, 8):
        assert list(raster.rows[y]) == [2] * 8 + [4] * 8
    assert list(raster.rows[8]) == [
        5, 5, 5, 5, 6, 6, 6, 6,
        8, 8, 8, 8, 7, 7, 7, 7,
    ]  # fmt: skip
    for y in range(9, 16):
        assert list(raster.rows[y]) == [6] * 8 + [8] * 8
    assert raster.transparent_pixel_count == 0


def test_hires_rows_within_a_cell_are_consecutive_bytes() -> None:
    bitmap = blank(32)
    bitmap[3] = 0xFF  # cell (0,0), pixel row 3
    bitmap[16 + 5] = 0xFF  # cell (1,0), pixel row 5
    screen = bytes([0x10, 0x10, 0x10, 0x10])

    raster = render_hires_bitmap(
        bitmap=bytes(bitmap), screen=screen, columns=2, rows=2
    )

    assert list(raster.rows[3])[:8] == [1] * 8
    assert list(raster.rows[2])[:8] == [0] * 8
    assert list(raster.rows[13])[:8] == [1] * 8
    assert list(raster.rows[12])[:8] == [0] * 8


def test_multicolor_bit_pairs_take_all_four_colour_sources() -> None:
    bitmap = blank(8)
    bitmap[0] = 0x1B  # 00 01 10 11
    screen = bytes([0x27])  # high nybble 2, low nybble 7
    color = bytes([0x5D])  # only the low nybble, 13, is a colour

    raster = render_multicolor_bitmap(
        bitmap=bytes(bitmap),
        screen=screen,
        color=color,
        columns=1,
        rows=1,
        background=6,
    )

    assert (raster.width, raster.height) == (8, 8)
    assert list(raster.rows[0]) == [6, 6, 2, 2, 7, 7, 13, 13]
    for y in range(1, 8):
        assert list(raster.rows[y]) == [6] * 8


def test_multicolor_cells_interleave_like_hires_cells() -> None:
    bitmap = blank(32)
    bitmap[8] = 0x10  # cell (0,1) row 0: second pixel pair is 01
    bitmap[16] = 0xC0  # cell (1,0) row 0: first pixel pair is 11
    screen = bytes([0x00, 0x9F, 0x00, 0x00])
    color = bytes([0x00, 0x00, 0x0B, 0x00])

    raster = render_multicolor_bitmap(
        bitmap=bytes(bitmap),
        screen=screen,
        color=color,
        columns=2,
        rows=2,
        background=1,
    )

    assert list(raster.rows[0]) == [
        1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 9, 9, 1, 1, 1, 1,
    ]  # fmt: skip
    assert list(raster.rows[8])[:4] == [11, 11, 1, 1]


def test_charset_sheet_wraps_after_sheet_columns_glyphs() -> None:
    charset = blank(17 * 8)
    charset[0] = 0x80  # glyph 0, row 0
    charset[15 * 8] = 0xFF  # glyph 15, row 0
    charset[16 * 8] = 0x81  # glyph 16, row 0

    raster = render_charset(
        charset=bytes(charset),
        glyph_count=17,
        sheet_columns=16,
        foreground=1,
        background=0,
    )

    assert (raster.width, raster.height) == (128, 16)
    assert raster.rows[0][0] == 1
    assert list(raster.rows[0][1:120]) == [0] * 119
    assert list(raster.rows[0][120:128]) == [1] * 8
    assert list(raster.rows[8][:8]) == [1, 0, 0, 0, 0, 0, 0, 1]
    assert list(raster.rows[8][8:]) == [0] * 120
    assert raster.glyph_indices == tuple(range(17))


def test_charset_pads_the_final_sheet_row_with_background() -> None:
    charset = bytes([0xFF] * (3 * 8))

    raster = render_charset(
        charset=charset,
        glyph_count=3,
        sheet_columns=2,
        foreground=1,
        background=9,
    )

    assert (raster.width, raster.height) == (16, 16)
    assert list(raster.rows[0]) == [1] * 16
    assert list(raster.rows[8]) == [1] * 8 + [9] * 8


def test_multicolor_charset_maps_pairs_and_gives_11_the_low_three_bits() -> None:
    charset = blank(8)
    charset[0] = 0x1B  # 00 01 10 11

    raster = render_charset(
        charset=bytes(charset),
        glyph_count=1,
        sheet_columns=1,
        foreground=13,
        background=0,
        multicolor=True,
        background_1=2,
        background_2=3,
    )

    assert list(raster.rows[0]) == [0, 0, 2, 2, 3, 3, 5, 5]


def test_multicolor_charset_requires_both_shared_backgrounds() -> None:
    with pytest.raises(RequestError, match="background_2"):
        render_charset(
            charset=bytes(8),
            glyph_count=1,
            sheet_columns=1,
            foreground=1,
            background=0,
            multicolor=True,
            background_1=2,
        )


def test_multicolor_char_screen_requires_both_shared_backgrounds() -> None:
    with pytest.raises(RequestError, match="background_1"):
        render_char_screen(
            screen=bytes([0]),
            charset=bytes(8),
            color=bytes([0x08]),
            columns=1,
            rows=1,
            multicolor=True,
            background_2=3,
        )


def test_char_screen_mixes_hires_and_multicolor_cells_by_colour_bit_3() -> None:
    charset = blank(4 * 8)
    charset[0 * 8] = 0xA5  # 1010 0101
    charset[1 * 8] = 0x1B  # 00 01 10 11
    charset[2 * 8] = 0xE4  # 11 10 01 00
    charset[3 * 8] = 0xFF  # 11 11 11 11
    screen = bytes([0, 1, 2, 3])
    color = bytes([0x02, 0x0A, 0x08, 0x0F])

    raster = render_char_screen(
        screen=screen,
        charset=bytes(charset),
        color=color,
        columns=4,
        rows=1,
        background=6,
        foreground=1,
        multicolor=True,
        background_1=4,
        background_2=5,
    )

    assert (raster.width, raster.height) == (32, 8)
    assert list(raster.rows[0]) == [
        2, 6, 2, 6, 6, 2, 6, 2,
        6, 6, 4, 4, 5, 5, 2, 2,
        0, 0, 5, 5, 4, 4, 6, 6,
        7, 7, 7, 7, 7, 7, 7, 7,
    ]  # fmt: skip
    assert list(raster.rows[1]) == [6] * 32


def test_char_screen_without_colour_ram_paints_every_cell_foreground() -> None:
    charset = blank(8)
    charset[0] = 0xC0

    raster = render_char_screen(
        screen=bytes([0, 0]),
        charset=bytes(charset),
        color=None,
        columns=2,
        rows=1,
        background=6,
        foreground=3,
    )

    assert list(raster.rows[0]) == [3, 3, 6, 6, 6, 6, 6, 6] * 2


def test_char_screen_hires_cells_use_the_whole_colour_nybble() -> None:
    charset = blank(8)
    charset[0] = 0x80

    raster = render_char_screen(
        screen=bytes([0]),
        charset=bytes(charset),
        color=bytes([0x9D]),
        columns=1,
        rows=1,
        background=0,
        foreground=1,
    )

    assert raster.rows[0][0] == 13


def test_char_screen_requires_colour_ram_for_multicolor() -> None:
    with pytest.raises(RequestError, match="color is required"):
        render_char_screen(
            screen=bytes([0]),
            charset=bytes(8),
            color=None,
            columns=1,
            rows=1,
            background=0,
            foreground=1,
            multicolor=True,
            background_1=2,
            background_2=3,
        )


def test_charset_requirement_follows_the_highest_screen_code() -> None:
    assert charset_bytes_required(bytes([0, 3, 1])) == 32
    assert charset_bytes_required(bytes([0])) == 8
    assert charset_bytes_required(bytes([255])) == 2048


def test_sprites_place_first_and_last_rows_and_skip_the_padding_byte() -> None:
    data = blank(127)
    data[0] = 0x80  # sprite 0, row 0, leftmost pixel
    data[62] = 0x01  # sprite 0, row 20, rightmost pixel
    data[63] = 0xFF  # the 64th byte is padding and must be ignored
    data[64] = 0x40  # sprite 1, row 0, second pixel

    raster = render_sprites(
        data=bytes(data),
        sprite_count=2,
        sprite_stride=64,
        sheet_columns=2,
        sprite_colors=[1, 7],
        background=6,
    )

    assert (raster.width, raster.height) == (48, 21)
    assert raster.rows[0][0] == 1
    assert list(raster.rows[0][1:24]) == [6] * 23
    assert raster.rows[0][25] == 7
    assert list(raster.rows[0][24:25]) == [6]
    assert list(raster.rows[0][26:]) == [6] * 22
    assert raster.rows[20][23] == 1
    assert list(raster.rows[20][:23]) == [6] * 23
    assert raster.transparent_pixel_count == 2 * 24 * 21 - 3


def test_sprite_rows_span_three_bytes_left_to_right() -> None:
    data = blank(63)
    data[0] = 0x01  # row 0, byte 0, rightmost bit  -> x = 7
    data[1] = 0x80  # row 0, byte 1, leftmost bit   -> x = 8
    data[2] = 0x01  # row 0, byte 2, rightmost bit  -> x = 23
    data[3] = 0x80  # row 1, byte 0, leftmost bit   -> x = 0

    raster = render_sprites(
        data=bytes(data),
        sprite_count=1,
        sprite_stride=64,
        sheet_columns=1,
        sprite_colors=[1],
        background=6,
    )

    assert [
        index for index, value in enumerate(raster.rows[0]) if value == 1
    ] == [7, 8, 23]
    assert [
        index for index, value in enumerate(raster.rows[1]) if value == 1
    ] == [0]


def test_sprites_accept_packed_stride_63() -> None:
    data = blank(126)
    data[0] = 0x80
    data[63] = 0x80

    raster = render_sprites(
        data=bytes(data),
        sprite_count=2,
        sprite_stride=63,
        sheet_columns=2,
        sprite_colors=[1, 7],
        background=6,
    )

    assert raster.rows[0][0] == 1
    assert raster.rows[0][24] == 7


def test_multicolor_sprite_pairs_composite_transparency_onto_background() -> None:
    data = blank(63)
    data[0] = 0x1B  # 00 01 10 11

    raster = render_sprites(
        data=bytes(data),
        sprite_count=1,
        sprite_stride=64,
        sheet_columns=8,
        sprite_colors=[7],
        multicolor=True,
        multicolor_0=4,
        multicolor_1=5,
        background=6,
    )

    assert (raster.width, raster.height) == (192, 21)
    assert list(raster.rows[0][:8]) == [6, 6, 4, 4, 7, 7, 5, 5]
    assert list(raster.rows[0][8:24]) == [6] * 16
    assert raster.transparent_pixel_count == 498


def test_sprite_sheet_pads_the_final_row_with_background() -> None:
    data = bytes([0xFF] * (2 * 64 + 63))

    raster = render_sprites(
        data=data,
        sprite_count=3,
        sprite_stride=64,
        sheet_columns=2,
        sprite_colors=[1, 1, 1],
        background=9,
    )

    assert (raster.width, raster.height) == (48, 42)
    assert list(raster.rows[21][:24]) == [1] * 24
    assert list(raster.rows[21][24:]) == [9] * 24


def test_sprite_colors_must_match_the_sprite_count() -> None:
    with pytest.raises(RequestError, match="sprite_colors"):
        render_sprites(
            data=bytes(63),
            sprite_count=1,
            sprite_stride=64,
            sheet_columns=8,
            sprite_colors=[1, 2],
            background=0,
        )


def test_multicolor_sprites_require_both_shared_colours() -> None:
    with pytest.raises(RequestError, match="multicolor_0"):
        render_sprites(
            data=bytes(63),
            sprite_count=1,
            sprite_stride=64,
            sheet_columns=8,
            sprite_colors=[1],
            multicolor=True,
            multicolor_1=5,
            background=0,
        )


@pytest.mark.parametrize("stride", [0, 62, 65, 128])
def test_only_strides_63_and_64_are_accepted(stride: int) -> None:
    with pytest.raises(RequestError, match="sprite_stride"):
        render_sprites(
            data=bytes(200),
            sprite_count=1,
            sprite_stride=stride,
            sheet_columns=8,
            sprite_colors=[1],
            background=0,
        )


@pytest.mark.parametrize(
    ("columns", "rows"),
    [(64, 32), (1, 1), (32, 64)],
)
def test_cell_geometry_at_the_caps_is_accepted(
    columns: int, rows: int
) -> None:
    raster = render_hires_bitmap(
        bitmap=bytes(columns * rows * 8),
        screen=bytes(columns * rows),
        columns=columns,
        rows=rows,
    )

    assert (raster.width, raster.height) == (columns * 8, rows * 8)


@pytest.mark.parametrize(
    ("columns", "rows", "message"),
    [
        (65, 1, "columns"),
        (0, 1, "columns"),
        (1, 65, "rows"),
        (1, 0, "rows"),
    ],
)
def test_cell_geometry_past_its_caps_is_rejected(
    columns: int, rows: int, message: str
) -> None:
    with pytest.raises(RequestError, match=message):
        render_hires_bitmap(
            bitmap=bytes(8),
            screen=bytes(1),
            columns=columns,
            rows=rows,
        )


def test_the_cell_budget_boundary_is_accepted_and_one_past_is_not() -> None:
    render_hires_bitmap(
        bitmap=bytes(2048 * 8), screen=bytes(2048), columns=64, rows=32
    )

    with pytest.raises(GraphicsLimitError, match="2048"):
        render_hires_bitmap(
            bitmap=bytes(64 * 33 * 8),
            screen=bytes(64 * 33),
            columns=64,
            rows=33,
        )


@pytest.mark.parametrize("glyph_count", [1, 256])
def test_glyph_count_at_its_caps_is_accepted(glyph_count: int) -> None:
    raster = render_charset(
        charset=bytes(glyph_count * 8),
        glyph_count=glyph_count,
        sheet_columns=16,
        foreground=1,
        background=0,
    )

    assert raster.height == ((glyph_count + 15) // 16) * 8


@pytest.mark.parametrize("glyph_count", [0, 257])
def test_glyph_count_past_its_caps_is_rejected(glyph_count: int) -> None:
    with pytest.raises(RequestError, match="glyph_count"):
        render_charset(
            charset=bytes(257 * 8),
            glyph_count=glyph_count,
            sheet_columns=16,
            foreground=1,
            background=0,
        )


@pytest.mark.parametrize("sheet_columns", [1, 64])
def test_sheet_columns_at_its_caps_is_accepted(sheet_columns: int) -> None:
    raster = render_charset(
        charset=bytes(8),
        glyph_count=1,
        sheet_columns=sheet_columns,
        foreground=1,
        background=0,
    )

    assert raster.width == sheet_columns * 8


@pytest.mark.parametrize("sheet_columns", [0, 65])
def test_sheet_columns_past_its_caps_is_rejected(
    sheet_columns: int,
) -> None:
    with pytest.raises(RequestError, match="sheet_columns"):
        render_charset(
            charset=bytes(8),
            glyph_count=1,
            sheet_columns=sheet_columns,
            foreground=1,
            background=0,
        )


@pytest.mark.parametrize("sprite_count", [1, 256])
def test_sprite_count_at_its_caps_is_accepted(sprite_count: int) -> None:
    raster = render_sprites(
        data=bytes((sprite_count - 1) * 64 + 63),
        sprite_count=sprite_count,
        sprite_stride=64,
        sheet_columns=16,
        sprite_colors=[1] * sprite_count,
        background=0,
    )

    assert raster.height == ((sprite_count + 15) // 16) * 21


@pytest.mark.parametrize("sprite_count", [0, 257])
def test_sprite_count_past_its_caps_is_rejected(sprite_count: int) -> None:
    with pytest.raises(RequestError, match="sprite_count"):
        render_sprites(
            data=bytes(257 * 64),
            sprite_count=sprite_count,
            sprite_stride=64,
            sheet_columns=16,
            sprite_colors=[1] * max(sprite_count, 1),
            background=0,
        )


@pytest.mark.parametrize("colour", [0, 15])
def test_colour_indices_at_their_caps_are_accepted(colour: int) -> None:
    raster = render_charset(
        charset=bytes(8),
        glyph_count=1,
        sheet_columns=1,
        foreground=colour,
        background=colour,
    )

    assert raster.rows[0][0] == colour


@pytest.mark.parametrize("colour", [-1, 16])
def test_colour_indices_past_their_caps_are_rejected(colour: int) -> None:
    with pytest.raises(RequestError, match="foreground"):
        render_charset(
            charset=bytes(8),
            glyph_count=1,
            sheet_columns=1,
            foreground=colour,
            background=0,
        )


def test_short_sources_are_refused_by_the_renderers_too() -> None:
    with pytest.raises(RequestError, match="bitmap"):
        render_hires_bitmap(
            bitmap=bytes(7), screen=bytes(1), columns=1, rows=1
        )
