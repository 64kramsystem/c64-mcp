from __future__ import annotations

import os

import pytest

from ghidra_mcp_c64.ghidra_client import GhidraClient
from ghidra_mcp_c64.profile_tools import (
    apply_c64_symbol_profile,
    load_c64_profile,
)


def _client() -> GhidraClient:
    return GhidraClient(
        os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089"),
        os.environ.get("GHIDRA_MCP_AUTH_TOKEN"),
    )


def test_live_generic_endpoint_accepts_bundled_profile_schema() -> None:
    if os.environ.get("GHIDRA_MCP_C64_LIVE") != "1":
        pytest.skip(
            "set GHIDRA_MCP_C64_LIVE=1 to validate the bundled profile "
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
    program = os.environ.get("GHIDRA_MCP_C64_PROFILE_TEST_PROGRAM")
    if (
        os.environ.get("GHIDRA_MCP_C64_PROFILE_MUTATE") != "1"
        or not program
    ):
        pytest.skip(
            "set GHIDRA_MCP_C64_PROFILE_MUTATE=1 and "
            "GHIDRA_MCP_C64_PROFILE_TEST_PROGRAM to a disposable named "
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
