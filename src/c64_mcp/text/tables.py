"""Strict immutable access to the bundled C64 character tables."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from importlib import resources
from types import MappingProxyType

from ..errors import CodecDataError


class Encoding(str, Enum):
    """Supported C64 character encodings and character-set modes."""

    PETSCII_UPPER = "petscii_upper"
    PETSCII_LOWER = "petscii_lower"
    SCREEN_CODE_UPPER = "screen_code_upper"
    SCREEN_CODE_LOWER = "screen_code_lower"

    @property
    def is_screen_code(self) -> bool:
        return self in {
            Encoding.SCREEN_CODE_UPPER,
            Encoding.SCREEN_CODE_LOWER,
        }


@dataclass(frozen=True, slots=True)
class Codepoint:
    """One immutable entry in a complete 256-byte mapping."""

    byte: int
    glyph: str | None
    name: str
    printable: bool


def table_for(encoding: Encoding) -> tuple[Codepoint, ...]:
    """Return one reviewed immutable 256-entry table."""

    if not isinstance(encoding, Encoding):
        raise CodecDataError(f"unsupported encoding: {encoding!r}")
    return _all_tables()[encoding]


@lru_cache(maxsize=1)
def _all_tables() -> MappingProxyType[Encoding, tuple[Codepoint, ...]]:
    try:
        raw = resources.files("c64_mcp.text").joinpath("tables.json").read_text("utf-8")
        document = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CodecDataError("cannot load bundled C64 text tables") from error
    if not isinstance(document, dict):
        raise CodecDataError("C64 text table document must be an object")
    tables = document.get("tables")
    if not isinstance(tables, dict):
        raise CodecDataError("C64 text table document omits tables")

    result: dict[Encoding, tuple[Codepoint, ...]] = {}
    for encoding in Encoding:
        raw_entries = tables.get(encoding.value)
        if not isinstance(raw_entries, list):
            raise CodecDataError(f"invalid {encoding.value} table: expected an array")
        entries = tuple(
            _parse_entry(encoding, index, raw_entry)
            for index, raw_entry in enumerate(raw_entries)
        )
        if len(entries) != 256 or tuple(entry.byte for entry in entries) != tuple(
            range(256)
        ):
            raise CodecDataError(
                f"invalid {encoding.value} table: expected bytes 0..255"
            )
        result[encoding] = entries
    return MappingProxyType(result)


def _parse_entry(
    encoding: Encoding,
    index: int,
    raw: object,
) -> Codepoint:
    if not isinstance(raw, dict):
        raise CodecDataError(
            f"invalid {encoding.value} entry {index}: expected an object"
        )
    expected = {
        "byte",
        "glyph",
        "name",
        "printable",
    }
    if set(raw) != expected:
        raise CodecDataError(
            f"invalid {encoding.value} entry {index}: unexpected fields"
        )
    byte = raw["byte"]
    glyph = raw["glyph"]
    name = raw["name"]
    printable = raw["printable"]
    if (
        not isinstance(byte, int)
        or isinstance(byte, bool)
        or byte != index
        or (glyph is not None and not isinstance(glyph, str))
        or not isinstance(name, str)
        or not name
        or not isinstance(printable, bool)
    ):
        raise CodecDataError(f"invalid {encoding.value} entry {index}: invalid value")
    return Codepoint(
        byte=byte,
        glyph=glyph,
        name=name,
        printable=printable,
    )
