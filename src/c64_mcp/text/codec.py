"""Small, bounded PETSCII and C64 screen-code decoder."""

from __future__ import annotations

from dataclasses import dataclass

from ..errors import RequestError, TextLimitError
from .tables import Encoding, table_for

MAX_INPUT_BYTES = 65_536
MAX_RENDERED_CHARS = 262_144


@dataclass(frozen=True, slots=True)
class DecodeResult:
    consumed: bytes
    text: str
    terminated: bool
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "consumed_hex": self.consumed.hex(),
            "consumed_length": len(self.consumed),
            "text": self.text,
            "terminated": self.terminated,
            "warnings": list(self.warnings),
        }


def decode_c64_bytes(
    data: bytes,
    *,
    encoding: Encoding,
    length: int | None = None,
    terminator: int | None = None,
    prefix_size: int | None = None,
    prefix_includes_self: bool = False,
    tokens: dict[int, str] | None = None,
) -> DecodeResult:
    if not isinstance(data, bytes):
        raise RequestError("data must be bytes")
    if len(data) > MAX_INPUT_BYTES:
        raise TextLimitError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    selected, text_start, text_end, terminated, warnings = _select(
        data,
        length=length,
        terminator=terminator,
        prefix_size=prefix_size,
        prefix_includes_self=prefix_includes_self,
    )
    table = table_for(encoding)
    replacements = tokens or {}
    parts: list[str] = []
    for value in selected[text_start:text_end]:
        replacement = replacements.get(value)
        if replacement is not None:
            parts.append(replacement)
            continue
        lookup = value & 0x7F if encoding.is_screen_code else value
        point = table[lookup]
        fragment = (
            point.glyph
            if point.printable and point.glyph is not None
            else f"{{{point.name}}}"
        )
        if encoding.is_screen_code and value & 0x80:
            fragment = f"{{REV {fragment}}}"
        parts.append(fragment)
    text = "".join(parts)
    if len(text) > MAX_RENDERED_CHARS:
        raise TextLimitError(f"rendered output exceeds {MAX_RENDERED_CHARS} characters")
    return DecodeResult(selected, text, terminated, warnings)


def _select(
    data: bytes,
    *,
    length: int | None,
    terminator: int | None,
    prefix_size: int | None,
    prefix_includes_self: bool,
) -> tuple[bytes, int, int, bool, tuple[str, ...]]:
    modes = sum(value is not None for value in (length, terminator, prefix_size))
    if modes > 1:
        raise RequestError("choose only one of length, terminator, or prefix_size")
    if not isinstance(prefix_includes_self, bool):
        raise RequestError("prefix_includes_self must be a boolean")
    if length is not None:
        count = _positive(length, "length")
        if count > len(data):
            raise RequestError("length exceeds the byte source")
        return data[:count], 0, count, False, ()
    if terminator is not None:
        value = _byte(terminator, "terminator")
        found = data.find(bytes((value,)))
        if found < 0:
            return (
                data,
                0,
                len(data),
                False,
                (f"terminator ${value:02X} was not found",),
            )
        return data[: found + 1], 0, found, True, ()
    if prefix_size is not None:
        if prefix_size not in (1, 2) or isinstance(prefix_size, bool):
            raise RequestError("prefix_size must be 1 or 2")
        if len(data) < prefix_size:
            raise RequestError("source is shorter than its length prefix")
        declared = int.from_bytes(data[:prefix_size], "little")
        total = declared if prefix_includes_self else prefix_size + declared
        if total < prefix_size or total > len(data):
            raise RequestError("length prefix exceeds the byte source")
        return data[:total], prefix_size, total, False, ()
    return data, 0, len(data), False, ()


def _positive(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise RequestError(f"{field} must be a positive integer")
    return value


def _byte(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFF:
        raise RequestError(f"{field} must be in 0..255")
    return value
