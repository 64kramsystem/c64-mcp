"""Bounded inline or Ghidra byte sources for VIC-II renderers."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from ..errors import RequestError

MAX_SOURCE_BYTES = 65_536
_HEX = re.compile(r"^[0-9a-fA-F]*$")


class GraphicsGhidraClient(Protocol):
    def read_bytes(self, program: str, start: str, length: int) -> bytes: ...


@dataclass(frozen=True, slots=True)
class SourceSpec:
    name: str
    kind: str
    data: bytes | None = None
    program: str | None = None
    address: str | None = None


def parse_source(value: object, name: str) -> SourceSpec:
    if not isinstance(value, Mapping):
        raise RequestError(f"{name} must be an inline or ghidra source")
    kind = value.get("kind")
    if kind == "inline" and set(value) == {"kind", "bytes"}:
        return SourceSpec(name, kind, data=_parse_bytes(value.get("bytes"), name))
    if kind == "ghidra" and set(value) == {"kind", "program", "start"}:
        program = value.get("program")
        start = value.get("start")
        if (
            not isinstance(program, str)
            or not program
            or not isinstance(start, str)
            or not start
        ):
            raise RequestError(f"{name} ghidra source requires program and start")
        return SourceSpec(name, kind, program=program, address=start)
    raise RequestError(f"{name} must have kind inline or ghidra with no extra fields")


class SourcePlan:
    def __init__(self, ghidra: GraphicsGhidraClient) -> None:
        self._ghidra = ghidra
        self._loaded: dict[str, tuple[str, bytes, int]] = {}

    def load(self, spec: SourceSpec, required: int) -> bytes:
        validate_inline_source(spec, required)
        if spec.kind == "inline":
            assert spec.data is not None
            data = spec.data
        else:
            assert spec.program is not None and spec.address is not None
            data = self._ghidra.read_bytes(spec.program, spec.address, required)
        if len(data) < required:
            raise RequestError(
                f"{spec.name} supplies {len(data)} bytes; {required} are required"
            )
        self._loaded[spec.name] = (spec.kind, data, required)
        return data

    def summary(self) -> dict[str, object]:
        return {
            name: {
                "kind": kind,
                "supplied": len(data),
                "consumed": required,
            }
            for name, (kind, data, required) in self._loaded.items()
        }


def validate_inline_source(spec: SourceSpec, required: int) -> None:
    """Reject a short inline source before any remote source is read."""

    if not 0 <= required <= MAX_SOURCE_BYTES:
        raise RequestError("graphics source length is out of range")
    if spec.kind == "inline":
        assert spec.data is not None
        if len(spec.data) < required:
            raise RequestError(
                f"{spec.name} supplies {len(spec.data)} bytes; {required} are required"
            )


def _parse_bytes(value: object, name: str) -> bytes:
    if isinstance(value, str):
        text = "".join(value.split())
        if text.startswith(("0x", "0X")):
            text = text[2:]
        if len(text) % 2 or _HEX.fullmatch(text) is None:
            raise RequestError(f"{name} bytes must be hexadecimal")
        data = bytes.fromhex(text)
    elif isinstance(value, list) and all(
        isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255
        for item in value
    ):
        data = bytes(value)
    else:
        raise RequestError(f"{name} bytes must be hexadecimal or an integer array")
    if len(data) > MAX_SOURCE_BYTES:
        raise RequestError(f"{name} exceeds {MAX_SOURCE_BYTES} bytes")
    return data
