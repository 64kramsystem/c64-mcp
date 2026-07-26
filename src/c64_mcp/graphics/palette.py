"""The C64 colour palette used to turn colour indices into RGB triples."""

from __future__ import annotations

import re

from ..errors import RequestError

Rgb = tuple[int, int, int]

# Pepto PAL, from https://www.pepto.de/projects/colorvic/. Listed literally so
# no other VIC-II palette variant can be substituted by accident.
PEPTO_PAL: tuple[Rgb, ...] = (
    (0x00, 0x00, 0x00),  # 0 black
    (0xFF, 0xFF, 0xFF),  # 1 white
    (0x68, 0x37, 0x2B),  # 2 red
    (0x70, 0xA4, 0xB2),  # 3 cyan
    (0x6F, 0x3D, 0x86),  # 4 purple
    (0x58, 0x8D, 0x43),  # 5 green
    (0x35, 0x28, 0x79),  # 6 blue
    (0xB8, 0xC7, 0x6F),  # 7 yellow
    (0x6F, 0x4F, 0x25),  # 8 orange
    (0x43, 0x39, 0x00),  # 9 brown
    (0x9A, 0x67, 0x59),  # 10 light red
    (0x44, 0x44, 0x44),  # 11 dark grey
    (0x6C, 0x6C, 0x6C),  # 12 grey
    (0x9A, 0xD2, 0x84),  # 13 light green
    (0x6C, 0x5E, 0xB5),  # 14 light blue
    (0x95, 0x95, 0x95),  # 15 light grey
)
PALETTE_NAMES: tuple[str, ...] = (
    "black",
    "white",
    "red",
    "cyan",
    "purple",
    "green",
    "blue",
    "yellow",
    "orange",
    "brown",
    "light red",
    "dark grey",
    "grey",
    "light green",
    "light blue",
    "light grey",
)
MAX_PALETTE_ENTRIES = 256
_HEX_TRIPLE = re.compile(r"^#?[0-9a-fA-F]{6}$")


def resolve_palette(value: object | None) -> list[Rgb]:
    """Return Pepto PAL, or a caller palette of hex strings or RGB triples."""

    if value is None:
        return list(PEPTO_PAL)
    if not isinstance(value, list) or not value:
        raise RequestError(
            "palette must be a non-empty array of '#rrggbb' strings or "
            "[r, g, b] triples"
        )
    if len(value) > MAX_PALETTE_ENTRIES:
        raise RequestError(
            f"palette must not exceed {MAX_PALETTE_ENTRIES} entries"
        )
    result: list[Rgb] = []
    for index, entry in enumerate(value):
        result.append(_entry(entry, index))
    return result


def _entry(entry: object, index: int) -> Rgb:
    if isinstance(entry, str):
        if not _HEX_TRIPLE.fullmatch(entry):
            raise RequestError(
                f"palette entry {index} must be six hexadecimal digits, "
                "optionally '#'-prefixed"
            )
        digits = entry.lstrip("#")
        return (
            int(digits[0:2], 16),
            int(digits[2:4], 16),
            int(digits[4:6], 16),
        )
    if isinstance(entry, (list, tuple)):
        if len(entry) != 3:
            raise RequestError(
                f"palette entry {index} must hold exactly three channels"
            )
        channels: list[int] = []
        for channel in entry:
            if (
                not isinstance(channel, int)
                or isinstance(channel, bool)
                or channel < 0
                or channel > 255
            ):
                raise RequestError(
                    f"palette entry {index} channels must be integers "
                    "from 0 to 255"
                )
            channels.append(channel)
        return (channels[0], channels[1], channels[2])
    raise RequestError(
        f"palette entry {index} must be a hex string or an [r, g, b] triple"
    )
