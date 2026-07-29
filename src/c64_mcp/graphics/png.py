"""Minimal indexed-colour PNG encoder built on the standard library only.

Colour type 3 keeps one logical C64 colour index per pixel, which is what the
decoders produce and what an agent wants to reason about; filter type 0 is what
the PNG specification recommends for indexed images. No runtime dependency is
added: `zlib`, `struct`, and `binascii` are all that is required.
"""

from __future__ import annotations

import binascii
import struct
import zlib
from collections.abc import Sequence
from dataclasses import dataclass

from ..errors import GraphicsLimitError, RequestError
from .palette import Rgb

MAX_OUTPUT_PIXELS = 4_194_304
MAX_PNG_BYTES = 8 * 1024 * 1024
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_COMPRESSION_LEVEL = 9


@dataclass(frozen=True, slots=True)
class EncodedPng:
    """One encoded indexed PNG."""

    data: bytes
    width: int
    height: int
    palette_size: int
    used_indices: tuple[int, ...]


def ensure_output_pixels(width: int, height: int) -> int:
    """Return width*height, refusing an image beyond the hard pixel cap."""

    if width <= 0 or height <= 0:
        raise RequestError("an image must have at least one pixel")
    total = width * height
    if total > MAX_OUTPUT_PIXELS:
        raise GraphicsLimitError(
            f"output of {total} pixels exceeds the {MAX_OUTPUT_PIXELS}-pixel "
            "hard maximum"
        )
    return total


def ensure_png_size(size: int) -> int:
    """Refuse an encoded image beyond the hard byte cap."""

    if size > MAX_PNG_BYTES:
        raise GraphicsLimitError(
            f"encoded PNG of {size} bytes exceeds the {MAX_PNG_BYTES}-byte hard maximum"
        )
    return size


def encode_indexed_png(
    rows: Sequence[Sequence[int]],
    palette: Sequence[Rgb],
) -> EncodedPng:
    """Encode equal-length index rows as an indexed PNG.

    Every pixel index must name an entry in the supplied palette.
    """

    if not rows:
        raise RequestError("an image must have at least one row")
    height = len(rows)
    width = len(rows[0])
    if width == 0:
        raise RequestError("an image must have at least one column")
    for row in rows:
        if len(row) != width:
            raise RequestError("every image row must have the same width")
    ensure_output_pixels(width, height)
    if not palette:
        raise RequestError("palette must hold at least one entry")

    counts: dict[int, int] = {}
    for row in rows:
        for index in row:
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or index < 0
                or index > 255
            ):
                raise RequestError("pixel indices must be integers from 0 to 255")
            counts[index] = counts.get(index, 0) + 1
    used = tuple(sorted(counts))
    if used and used[-1] >= len(palette):
        raise RequestError("pixel index exceeds the supplied palette")

    plte = bytearray()
    for red, green, blue in palette:
        plte.extend((red & 0xFF, green & 0xFF, blue & 0xFF))
    raw = bytearray()
    for row in rows:
        raw.append(0)  # filter type 0: None
        raw.extend(row)
    data = (
        PNG_SIGNATURE
        + _chunk(
            b"IHDR",
            struct.pack(
                ">IIBBBBB",
                width,
                height,
                8,  # bit depth
                3,  # colour type 3: indexed
                0,  # compression method: deflate
                0,  # filter method: adaptive, per-scanline byte
                0,  # interlace method: none
            ),
        )
        + _chunk(b"PLTE", bytes(plte))
        + _chunk(b"IDAT", zlib.compress(bytes(raw), _COMPRESSION_LEVEL))
        + _chunk(b"IEND", b"")
    )
    ensure_png_size(len(data))
    return EncodedPng(
        data=data,
        width=width,
        height=height,
        palette_size=len(palette),
        used_indices=used,
    )


def _chunk(kind: bytes, body: bytes) -> bytes:
    return (
        struct.pack(">I", len(body))
        + kind
        + body
        + struct.pack(">I", binascii.crc32(kind + body) & 0xFFFFFFFF)
    )
