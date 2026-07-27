from __future__ import annotations

import os
from copy import deepcopy

import pytest

from c64_mcp.errors import GhidraError
from c64_mcp.ghidra_client import GhidraClient
from c64_mcp.profile_tools import (
    apply_c64_symbol_profile,
    load_c64_profile,
)


def _client() -> GhidraClient:
    return GhidraClient(
        os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089"),
        os.environ.get("GHIDRA_MCP_AUTH_TOKEN"),
    )


def _assert_symbols_resolve_to_default_space(
    result: dict[str, object],
    *,
    default_space: str,
) -> None:
    symbols = result.get("symbols")
    assert isinstance(symbols, list)
    assert len(symbols) == 165
    expected = default_space.casefold()

    for item in symbols:
        assert isinstance(item, dict)
        address = item.get("address")
        assert isinstance(address, str)
        space, separator, offset = address.partition(":")
        assert separator == ":"
        assert space.casefold() == expected
        assert len(offset) == 4


def _legacy_c64_profile() -> dict[str, object]:
    legacy = deepcopy(load_c64_profile())
    legacy["version"] = "1.0.0"
    symbols = legacy["symbols"]
    assert isinstance(symbols, list)
    for item in symbols:
        assert isinstance(item, dict)
        address = item["address"]
        assert isinstance(address, str)
        item["address"] = address.removeprefix("RAM:")
    return legacy


def test_live_generic_endpoint_accepts_bundled_profile_schema() -> None:
    if os.environ.get("C64_MCP_LIVE") != "1":
        pytest.skip(
            "set C64_MCP_LIVE=1 to validate the bundled profile "
            "against a running generic Ghidra MCP server"
        )

    result = _client().call_post(
        "/validate_symbol_profile",
        {"profile": load_c64_profile()},
        {},
    )

    assert result["valid"] is True
    assert result["program_checks_performed"] is False


def test_live_profile_apply_is_idempotent_on_explicit_full_map_fixture() -> None:
    program = os.environ.get("C64_MCP_PROFILE_TEST_PROGRAM")
    if (
        os.environ.get("C64_MCP_PROFILE_MUTATE") != "1"
        or not program
    ):
        pytest.skip(
            "set C64_MCP_PROFILE_MUTATE=1 and "
            "C64_MCP_PROFILE_TEST_PROGRAM to a disposable named "
            "6502 program with default-space 0000..ffff mapped; the "
            "fixture should contain operands referencing d011 and ffd5"
        )
    client = _client()

    first = apply_c64_symbol_profile(
        client,
        program=program,
        dry_run=False,
        create_memory_blocks=False,
    )
    second = apply_c64_symbol_profile(
        client,
        program=program,
        dry_run=False,
        create_memory_blocks=False,
    )
    vic = client.call_get(
        "/get_listing_range",
        {"program": program, "start": "d011", "end": "d011"},
    )
    kernal = client.call_get(
        "/get_listing_range",
        {"program": program, "start": "ffd5", "end": "ffd5"},
    )

    assert first["committed"] is True
    assert second["committed"] is True
    assert second["idempotent"]
    assert "CONTROL_1" in str(vic)
    assert "LOAD" in str(kernal)


def test_live_profile_apply_is_idempotent_with_existing_overlays() -> None:
    program = os.environ.get("C64_MCP_PROFILE_OVERLAY_TEST_PROGRAM")
    if (
        os.environ.get("C64_MCP_PROFILE_MUTATE") != "1"
        or not program
    ):
        pytest.skip(
            "set C64_MCP_PROFILE_MUTATE=1 and "
            "C64_MCP_PROFILE_OVERLAY_TEST_PROGRAM to a disposable "
            "named 6502 program with full default RAM and overlays "
            "covering C64 platform-symbol offsets; no overlay may be "
            "named RAM"
        )
    client = _client()

    with pytest.raises(GhidraError, match="Ambiguous unqualified address"):
        client.apply_profile(
            program,
            _legacy_c64_profile(),
            dry_run=True,
            conflict_policy="error",
            create_memory_blocks=False,
        )

    first = apply_c64_symbol_profile(
        client,
        program=program,
        dry_run=False,
        conflict_policy="error",
        create_memory_blocks=False,
    )
    second = apply_c64_symbol_profile(
        client,
        program=program,
        dry_run=False,
        conflict_policy="error",
        create_memory_blocks=False,
    )

    assert first["committed"] is True
    assert first["kept_conflicts"] == []
    _assert_symbols_resolve_to_default_space(
        first,
        default_space="RAM",
    )
    assert second["committed"] is True
    assert second["kept_conflicts"] == []
    assert second["idempotent"]
    _assert_symbols_resolve_to_default_space(
        second,
        default_space="RAM",
    )


def test_live_profile_upgrade_from_unqualified_1_0_0_is_idempotent() -> None:
    program = os.environ.get("C64_MCP_PROFILE_UPGRADE_TEST_PROGRAM")
    if (
        os.environ.get("C64_MCP_PROFILE_MUTATE") != "1"
        or not program
    ):
        pytest.skip(
            "set C64_MCP_PROFILE_MUTATE=1 and "
            "C64_MCP_PROFILE_UPGRADE_TEST_PROGRAM to a disposable "
            "named 6502 program with full ordinary RAM, no C64 "
            "overlays, and no C64 profile annotations"
        )
    client = _client()
    legacy = _legacy_c64_profile()

    legacy_result = client.apply_profile(
        program,
        legacy,
        dry_run=False,
        conflict_policy="error",
        create_memory_blocks=False,
    )
    upgraded = apply_c64_symbol_profile(
        client,
        program=program,
        dry_run=False,
        conflict_policy="error",
        create_memory_blocks=False,
    )

    assert legacy_result["committed"] is True
    assert upgraded["committed"] is True
    assert upgraded["kept_conflicts"] == []
    assert upgraded["idempotent"]
    for group in ("symbols", "equates", "comments"):
        definitions = upgraded[group]
        assert isinstance(definitions, list)
        assert all(item["action"] == "idempotent" for item in definitions)
    _assert_symbols_resolve_to_default_space(
        upgraded,
        default_space="RAM",
    )


def test_live_profile_creates_optional_overlays_from_matching_ram() -> None:
    program = os.environ.get("C64_MCP_PROFILE_BLOCK_TEST_PROGRAM")
    if (
        os.environ.get("C64_MCP_PROFILE_MUTATE") != "1"
        or not program
    ):
        pytest.skip(
            "set C64_MCP_PROFILE_MUTATE=1 and "
            "C64_MCP_PROFILE_BLOCK_TEST_PROGRAM to a disposable "
            "named 6502 program whose only block exactly matches the "
            "bundled zero-filled RAM template"
        )
    client = _client()

    first = apply_c64_symbol_profile(
        client,
        program=program,
        dry_run=False,
        conflict_policy="error",
        create_memory_blocks=True,
    )
    second = apply_c64_symbol_profile(
        client,
        program=program,
        dry_run=False,
        conflict_policy="error",
        create_memory_blocks=True,
    )
    first_blocks = {
        item["name"]: item["action"]
        for item in first["memory_blocks"]
    }
    second_blocks = {
        item["name"]: item["action"]
        for item in second["memory_blocks"]
    }

    assert first["committed"] is True
    assert first["kept_conflicts"] == []
    assert first_blocks == {
        "RAM": "idempotent",
        "BASIC_ROM": "create",
        "KERNAL_ROM": "create",
        "IO": "create",
        "COLOR_RAM": "create",
    }
    assert second["committed"] is True
    assert second["kept_conflicts"] == []
    assert set(second_blocks.values()) == {"idempotent"}
    _assert_symbols_resolve_to_default_space(
        second,
        default_space="RAM",
    )
