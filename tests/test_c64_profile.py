from __future__ import annotations

import json
import re
import runpy
from collections import Counter
from pathlib import Path

from c64_mcp.profile_tools import load_c64_profile

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _symbols() -> list[dict[str, object]]:
    value = load_c64_profile()["symbols"]
    assert isinstance(value, list)
    return value


def test_profile_identity_and_representative_addresses() -> None:
    profile = load_c64_profile()

    assert profile["schema_version"] == 1
    assert profile["id"] == "c64"
    assert profile["version"] == "1.1.0"
    symbols = {
        (item["namespace"], item["name"]): item["address"]
        for item in _symbols()
    }
    assert symbols[("C64::CPU", "PROCESSOR_PORT")] == "RAM:0001"
    assert symbols[("C64::VIC", "CONTROL_1")] == "RAM:d011"
    assert symbols[("C64::SID", "VOICE1_FREQ_LO")] == "RAM:d400"
    assert symbols[("C64::CIA1", "DATA_PORT_A")] == "RAM:dc00"
    assert symbols[("C64::CIA2", "DATA_PORT_A")] == "RAM:dd00"
    assert symbols[("C64::KERNAL", "LOAD")] == "RAM:ffd5"
    assert symbols[("C64::KERNAL", "NMI_VECTOR")] == "RAM:fffa"


def test_all_symbol_addresses_explicitly_target_default_ram() -> None:
    symbols = _symbols()

    assert len(symbols) == 165
    for item in symbols:
        address = str(item["address"])
        assert re.fullmatch(r"RAM:[0-9a-f]{4}", address)
        assert 0 <= int(address.removeprefix("RAM:"), 16) <= 0xFFFF


def test_profile_has_exact_required_group_cardinalities() -> None:
    symbols = _symbols()
    namespaces = Counter(item["namespace"] for item in symbols)

    assert namespaces == {
        "C64::CPU": 2,
        "C64::VIC": 48,
        "C64::SID": 29,
        "C64::CIA1": 16,
        "C64::CIA2": 16,
        "C64::KERNAL": 42,
        "C64::WORKSPACE": 12,
    }
    vic_addresses = {
        int(str(item["address"]).removeprefix("RAM:"), 16)
        for item in symbols
        if item["namespace"] == "C64::VIC"
        and item["name"] != "COLOR_RAM"
    }
    assert vic_addresses == set(range(0xD000, 0xD02F))


def test_profile_sources_and_definitions_are_complete_and_unique() -> None:
    profile = load_c64_profile()
    symbols = _symbols()
    equates = profile["equates"]
    blocks = profile["memory_blocks"]
    assert isinstance(equates, list)
    assert isinstance(blocks, list)

    assert all(
        "Commodore" in str(item["source_note"])
        and "http" in str(item["source_note"])
        for item in symbols
    )
    assert len({item["name"] for item in equates}) == len(equates)
    assert len(equates) >= 80
    assert all(
        isinstance(item.get("applications", []), list)
        and not item.get("applications", [])
        for item in equates
    )
    assert {
        item["name"] for item in equates
    } >= {
        "C64_VIC_CONTROL1_DISPLAY_ENABLE",
        "C64_VIC_CONTROL2_MULTICOLOR_MODE",
        "C64_SID_CONTROL_GATE",
        "C64_CIA_ICR_TIMER_A",
    }


def test_optional_block_templates_model_ram_and_overlays() -> None:
    blocks = load_c64_profile()["memory_blocks"]
    assert isinstance(blocks, list)
    by_name = {item["name"]: item for item in blocks}

    assert set(by_name) == {
        "RAM",
        "BASIC_ROM",
        "KERNAL_ROM",
        "IO",
        "COLOR_RAM",
    }
    assert by_name["RAM"] == {
        "name": "RAM",
        "start": "0000",
        "length": 0x10000,
        "fill": 0,
        "overlay": False,
        "read": True,
        "write": True,
        "execute": True,
        "comment": by_name["RAM"]["comment"],
    }
    assert all(
        item["overlay"] is True
        for name, item in by_name.items()
        if name != "RAM"
    )
    assert by_name["BASIC_ROM"]["start"] == "a000"
    assert by_name["KERNAL_ROM"]["start"] == "e000"
    assert by_name["IO"]["start"] == "d000"
    assert by_name["COLOR_RAM"]["start"] == "d800"
    io_start = int(str(by_name["IO"]["start"]), 16)
    io_end = io_start + int(by_name["IO"]["length"]) - 1
    color_start = int(str(by_name["COLOR_RAM"]["start"]), 16)
    color_end = color_start + int(by_name["COLOR_RAM"]["length"]) - 1
    # COLOR RAM is physically decoded inside the D000-DFFF I/O window, but
    # each template is a distinct Ghidra overlay address space. The generic
    # profile engine intentionally excludes overlays from same-space overlap
    # checks and MemoryBlockCore creates each against the physical base.
    assert io_start < color_start <= color_end < io_end


def test_each_load_returns_an_independent_json_object() -> None:
    first = load_c64_profile()
    second = load_c64_profile()

    assert first == second
    assert first is not second
    first["id"] = "mutated"
    first_symbols = first["symbols"]
    assert isinstance(first_symbols, list)
    first_symbols.clear()

    third = load_c64_profile()
    assert third["id"] == "c64"
    assert third["symbols"]


def test_checked_in_profile_is_byte_identical_to_generator_output() -> None:
    generator_path = REPOSITORY_ROOT / "tools" / "generate_c64_profile.py"
    generator = runpy.run_path(str(generator_path))
    generated = generator["profile"]()
    generated_text = (
        json.dumps(
            generated,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    checked_in = (
        REPOSITORY_ROOT
        / "src"
        / "c64_mcp"
        / "profiles"
        / "c64.json"
    ).read_text(encoding="utf-8")

    assert checked_in == generated_text
