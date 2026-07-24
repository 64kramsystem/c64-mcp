from __future__ import annotations

import os

import pytest

from ghidra_mcp_c64.ghidra_client import GhidraClient
from ghidra_mcp_c64.text.tools import define_c64_text


def test_live_definition_dry_run_uses_public_ghidra_api() -> None:
    program = os.environ.get("GHIDRA_MCP_C64_TEST_PROGRAM")
    start = os.environ.get("GHIDRA_MCP_C64_TEST_START")
    if not program or not start:
        pytest.skip(
            "set GHIDRA_MCP_C64_TEST_PROGRAM and "
            "GHIDRA_MCP_C64_TEST_START to enable the live dry-run gate"
        )
    client = GhidraClient(
        os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089"),
        os.environ.get("GHIDRA_MCP_AUTH_TOKEN"),
    )

    result = define_c64_text(
        client,
        program=program,
        start=start,
        length=1,
        dry_run=True,
    )

    assert result["dry_run"] is True
    assert result["decoded"]["consumed_length"] == 1
