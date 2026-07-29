from __future__ import annotations

import binascii
import io
import struct
import zlib

import pytest
from PIL import Image

from c64_mcp.errors import GraphicsLimitError, RequestError
from c64_mcp.graphics.png import (
    MAX_OUTPUT_PIXELS,
    MAX_PNG_BYTES,
    encode_indexed_png,
    ensure_output_pixels,
    ensure_png_size,
)

WHITE = (255, 255, 255)
BLACK = (0, 0, 0)


def chunk(kind: bytes, body: bytes) -> bytes:
    """Build one PNG chunk independently of the encoder under test."""

    return (
        struct.pack(">I", len(body))
        + kind
        + body
        + struct.pack(">I", binascii.crc32(kind + body) & 0xFFFFFFFF)
    )


def decoded(data: bytes) -> tuple[Image.Image, list[list[int]]]:
    image = Image.open(io.BytesIO(data))
    image.load()
    pixels = [
        [image.getpixel((x, y)) for x in range(image.width)]
        for y in range(image.height)
    ]
    return image, pixels


def test_small_indexed_image_matches_a_hand_built_golden_file() -> None:
    rows = [bytearray([0, 1]), bytearray([1, 0])]

    result = encode_indexed_png(rows, [BLACK, WHITE])

    expected = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(
            b"IHDR",
            struct.pack(">IIBBBBB", 2, 2, 8, 3, 0, 0, 0),
        )
        + chunk(b"PLTE", bytes([0, 0, 0, 255, 255, 255]))
        + chunk(
            b"IDAT",
            zlib.compress(b"\x00\x00\x01\x00\x01\x00", 9),
        )
        + chunk(b"IEND", b"")
    )
    assert result.data == expected
    assert result.width == 2
    assert result.height == 2
    assert result.palette_size == 2
    assert result.used_indices == (0, 1)


def test_pillow_reads_back_the_indices_and_palette() -> None:
    rows = [bytearray([0, 1, 2]), bytearray([2, 1, 0])]

    result = encode_indexed_png(rows, [BLACK, WHITE, (0x68, 0x37, 0x2B)])

    image, pixels = decoded(result.data)
    assert image.mode == "P"
    assert (image.width, image.height) == (3, 2)
    assert pixels == [[0, 1, 2], [2, 1, 0]]
    table = image.getpalette()
    assert table is not None
    assert table[:9] == [0, 0, 0, 255, 255, 255, 0x68, 0x37, 0x2B]


def test_pixel_index_beyond_palette_is_rejected() -> None:
    rows = [bytearray([0, 5])]

    with pytest.raises(RequestError, match="exceeds"):
        encode_indexed_png(rows, [WHITE, (1, 2, 3)])


def test_every_scanline_uses_filter_type_zero() -> None:
    rows = [bytearray([1, 1, 1]), bytearray([0, 0, 0])]

    result = encode_indexed_png(rows, [BLACK, WHITE])

    start = result.data.index(b"IDAT") + 4
    length = struct.unpack(">I", result.data[start - 8 : start - 4])[0]
    raw = zlib.decompress(result.data[start : start + length])
    assert raw == b"\x00\x01\x01\x01\x00\x00\x00\x00"


def test_ragged_rows_are_rejected() -> None:
    with pytest.raises(RequestError, match="same width"):
        encode_indexed_png([bytearray([0, 1]), bytearray([0])], [BLACK, WHITE])


def test_an_empty_image_is_rejected() -> None:
    with pytest.raises(RequestError, match="at least one"):
        encode_indexed_png([], [BLACK])


def test_output_pixel_cap_boundary_is_accepted() -> None:
    assert ensure_output_pixels(2048, 2048) == MAX_OUTPUT_PIXELS


def test_one_pixel_past_the_output_cap_is_rejected() -> None:
    with pytest.raises(GraphicsLimitError, match="4194304"):
        ensure_output_pixels(2049, 2048)


def test_png_size_cap_boundary_is_accepted() -> None:
    ensure_png_size(MAX_PNG_BYTES)


def test_one_byte_past_the_png_size_cap_is_rejected() -> None:
    with pytest.raises(GraphicsLimitError, match="8388608"):
        ensure_png_size(MAX_PNG_BYTES + 1)
