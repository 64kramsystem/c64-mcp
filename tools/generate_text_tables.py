#!/usr/bin/env python3
"""Generate reviewed C64 text package data from compact appendix rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypedDict


class Entry(TypedDict):
    byte: int
    glyph: str | None
    name: str
    printable: bool
    reverse_video: bool


SOURCE_URL = (
    "https://www.commodore.ca/wp-content/uploads/2018/11/"
    "c64-programmers_reference_guide-07-appendices.pdf"
)

CONTROL_NAMES = {
    0x03: "STOP",
    0x05: "WHITE",
    0x08: "DISABLE_SHIFT_CBM",
    0x09: "ENABLE_SHIFT_CBM",
    0x0D: "RETURN",
    0x0E: "LOWERCASE_GRAPHICS",
    0x11: "CURSOR_DOWN",
    0x12: "REVERSE_ON",
    0x13: "HOME",
    0x14: "DELETE",
    0x1C: "RED",
    0x1D: "CURSOR_RIGHT",
    0x1E: "GREEN",
    0x1F: "BLUE",
    0x81: "ORANGE",
    0x85: "F1",
    0x86: "F3",
    0x87: "F5",
    0x88: "F7",
    0x89: "F2",
    0x8A: "F4",
    0x8B: "F6",
    0x8C: "F8",
    0x8D: "SHIFT_RETURN",
    0x8E: "UPPERCASE_GRAPHICS",
    0x90: "BLACK",
    0x91: "CURSOR_UP",
    0x92: "REVERSE_OFF",
    0x93: "CLR",
    0x94: "INSERT",
    0x95: "BROWN",
    0x96: "LIGHT_RED",
    0x97: "DARK_GRAY",
    0x98: "GRAY",
    0x99: "LIGHT_GREEN",
    0x9A: "LIGHT_BLUE",
    0x9B: "LIGHT_GRAY",
    0x9C: "PURPLE",
    0x9D: "CURSOR_LEFT",
    0x9E: "YELLOW",
    0x9F: "CYAN",
}

SPECIAL_SCREEN = {
    0x00: ("@", "AT"),
    0x1B: ("[", "LEFT_BRACKET"),
    0x1C: ("£", "POUND"),
    0x1D: ("]", "RIGHT_BRACKET"),
    0x1E: ("↑", "UP_ARROW"),
    0x1F: ("←", "LEFT_ARROW"),
    0x20: (" ", "SPACE"),
}


def entry(
    byte: int,
    glyph: str | None,
    name: str,
    *,
    printable: bool,
    reverse_video: bool = False,
) -> Entry:
    return {
        "byte": byte,
        "glyph": glyph,
        "name": name,
        "printable": printable,
        "reverse_video": reverse_video,
    }


def screen_base(lower: bool) -> list[Entry]:
    result: list[Entry] = []
    for value in range(128):
        glyph: str | None = None
        name = f"GRAPHIC_{value:02X}"
        if value in SPECIAL_SCREEN:
            glyph, name = SPECIAL_SCREEN[value]
        elif 1 <= value <= 26:
            glyph = chr((ord("a") if lower else ord("A")) + value - 1)
            name = f"LETTER_{glyph.upper()}"
        elif 0x21 <= value <= 0x3F:
            glyph = chr(value)
            name = f"CHAR_{value:02X}"
        elif lower and value == 0x40:
            glyph, name = "@", "AT"
        elif lower and 0x41 <= value <= 0x5A:
            glyph = chr(ord("A") + value - 0x41)
            name = f"LETTER_{glyph}"
        elif lower and 0x5B <= value <= 0x5F:
            glyph, name = SPECIAL_SCREEN[value - 0x40]
        elif value == 0x5E:
            glyph, name = "π", "PI"
        result.append(
            entry(value, glyph, name, printable=True)
        )
    return result


def screen_table(lower: bool) -> list[Entry]:
    base = screen_base(lower)
    result = list(base)
    for value in range(128, 256):
        original = base[value & 0x7F]
        result.append(
            entry(
                value,
                original["glyph"],
                f"REVERSE_{original['name']}",
                printable=True,
                reverse_video=True,
            )
        )
    return result


def petscii_screen_code(value: int) -> int | None:
    if 0x20 <= value <= 0x3F:
        return value
    if 0x40 <= value <= 0x5F:
        return value - 0x40
    if 0x60 <= value <= 0x7F:
        return value - 0x20
    if 0xA0 <= value <= 0xBF:
        return value - 0x40
    if 0xC0 <= value <= 0xFE:
        return value - 0x80
    if value == 0xFF:
        return 0x5E
    return None


def petscii_table(lower: bool) -> list[Entry]:
    screen = screen_base(lower)
    result: list[Entry] = []
    for value in range(256):
        screen_code = petscii_screen_code(value)
        if screen_code is None:
            result.append(
                entry(
                    value,
                    None,
                    CONTROL_NAMES.get(value, f"CONTROL_{value:02X}"),
                    printable=False,
                )
            )
            continue
        source = screen[screen_code]
        result.append(
            entry(
                value,
                source["glyph"],
                source["name"],
                printable=True,
            )
        )
    return result


def main() -> None:
    document = {
        "schema_version": 1,
        "source": {
            "title": "Commodore 64 Programmer's Reference Guide",
            "url": SOURCE_URL,
            "pages": {
                "screen_codes": "Appendix B, printed pages 376-378",
                "petscii": "Appendix C, printed pages 379-381",
            },
            "notes": (
                "Unicode glyphs are recorded only for unambiguous textual "
                "forms. Other documented graphics retain stable names."
            ),
        },
        "tables": {
            "petscii_upper": petscii_table(False),
            "petscii_lower": petscii_table(True),
            "screen_code_upper": screen_table(False),
            "screen_code_lower": screen_table(True),
        },
    }
    target = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "ghidra_mcp_c64"
        / "text"
        / "tables.json"
    )
    target.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
