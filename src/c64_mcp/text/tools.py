"""One public C64 text decoder over inline bytes or a bounded Ghidra read."""

from __future__ import annotations

import re
from typing import Protocol

from ..errors import RequestError
from .codec import MAX_INPUT_BYTES, decode_c64_bytes
from .tables import Encoding

BytesInput = str | list[int]
_HEX = re.compile(r"^[0-9a-fA-F]*$")


class TextGhidraClient(Protocol):
    def read_bytes(self, program: str, start: str, length: int) -> bytes: ...


def decode_c64_text(
    ghidra: TextGhidraClient,
    *,
    bytes: BytesInput | None = None,
    program: str | None = None,
    start: str | None = None,
    max_length: int | None = None,
    encoding: str = "petscii_upper",
    length: int | None = None,
    terminator: int | None = None,
    prefix_size: int | None = None,
    prefix_includes_self: bool = False,
    tokens: dict[str, str] | None = None,
) -> dict[str, object]:
    try:
        selected_encoding = Encoding(encoding)
    except ValueError as error:
        raise RequestError("unsupported C64 text encoding") from error
    if bytes is not None:
        if any(value is not None for value in (program, start, max_length)):
            raise RequestError("choose inline bytes or a Ghidra source")
        data = _parse_bytes(bytes)
        source: dict[str, object] = {"kind": "inline"}
    else:
        if (
            not isinstance(program, str)
            or not program
            or not isinstance(start, str)
            or not start
            or not isinstance(max_length, int)
            or isinstance(max_length, bool)
            or not 1 <= max_length <= MAX_INPUT_BYTES
        ):
            raise RequestError("program, start, and max_length are required for Ghidra")
        data = ghidra.read_bytes(program, start, max_length)
        source = {"kind": "ghidra", "program": program, "start": start}
    result = decode_c64_bytes(
        data,
        encoding=selected_encoding,
        length=length,
        terminator=terminator,
        prefix_size=prefix_size,
        prefix_includes_self=prefix_includes_self,
        tokens=_tokens(tokens),
    ).as_dict()
    result["source"] = source
    result["encoding"] = selected_encoding.value
    return result


def _parse_bytes(value: BytesInput) -> bytes:
    if isinstance(value, str):
        text = "".join(value.split())
        if text.startswith(("0x", "0X")):
            text = text[2:]
        if len(text) % 2 or _HEX.fullmatch(text) is None:
            raise RequestError("bytes must be an even-length hexadecimal string")
        return bytes.fromhex(text)
    if isinstance(value, list):
        if any(
            not isinstance(item, int) or isinstance(item, bool) or not 0 <= item <= 0xFF
            for item in value
        ):
            raise RequestError("byte arrays must contain integers in 0..255")
        return bytes(value)
    raise RequestError("bytes must be hexadecimal text or an integer array")


def _tokens(value: dict[str, str] | None) -> dict[int, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RequestError("tokens must be an object")
    result: dict[int, str] = {}
    for key, replacement in value.items():
        try:
            number = int(key, 0) if key.lower().startswith("0x") else int(key, 10)
        except (AttributeError, ValueError) as error:
            raise RequestError("token keys must be byte values") from error
        if not 0 <= number <= 0xFF or not isinstance(replacement, str):
            raise RequestError("tokens must map byte values to strings")
        result[number] = replacement
    return result
