from __future__ import annotations

import re
from copy import deepcopy

from c64_mcp.profile_tools import load_c64_profile


def test_bundled_symbols_are_populated_and_use_default_ram_addresses() -> None:
    profile = load_c64_profile()
    symbols = profile["symbols"]

    assert isinstance(symbols, list)
    assert symbols
    for symbol in symbols:
        assert isinstance(symbol, dict)
        assert re.fullmatch(r"RAM:[0-9a-f]{4}", symbol["address"])


def test_each_load_returns_an_independent_json_object() -> None:
    baseline = deepcopy(load_c64_profile())
    first = load_c64_profile()
    second = load_c64_profile()

    assert first == second == baseline
    assert first is not second
    symbols = first["symbols"]
    assert isinstance(symbols, list)
    symbols.clear()
    first.clear()

    assert load_c64_profile() == baseline
