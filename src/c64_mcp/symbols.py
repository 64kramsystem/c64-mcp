"""Bundled C64 symbol loading and application."""

from __future__ import annotations

import json
from importlib import resources
from typing import Protocol, cast

from .errors import RequestError, SymbolDataError


class SymbolGhidraClient(Protocol):
    """Generic Ghidra operation used by the C64 symbol tool."""

    def create_labels(
        self, program: str, labels: list[dict[str, str]]
    ) -> dict[str, object]: ...


def load_c64_symbols() -> list[dict[str, str]]:
    """Load a fresh copy of the bundled C64 labels."""

    try:
        raw = (
            resources.files("c64_mcp.data")
            .joinpath("c64_symbols.json")
            .read_text("utf-8")
        )
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SymbolDataError("bundled C64 symbols could not be loaded") from error
    if not isinstance(value, list):
        raise SymbolDataError("bundled C64 symbols must be a JSON array")
    symbols = value
    for symbol in symbols:
        if (
            not isinstance(symbol, dict)
            or not isinstance(symbol.get("address"), str)
            or not isinstance(symbol.get("name"), str)
        ):
            raise SymbolDataError("bundled C64 symbols contain an invalid entry")
    return cast(list[dict[str, str]], symbols)


def apply_c64_symbols(ghidra: SymbolGhidraClient, *, program: str) -> dict[str, object]:
    """Create the bundled labels through Ghidra's batch primitive."""

    if not isinstance(program, str) or not program.strip():
        raise RequestError("program must not be blank")
    labels = [
        {
            key: symbol[key]
            for key in ("address", "name", "namespace")
            if isinstance(symbol.get(key), str) and symbol[key]
        }
        for symbol in load_c64_symbols()
    ]
    return ghidra.create_labels(program, labels)
