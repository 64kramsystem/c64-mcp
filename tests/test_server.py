from __future__ import annotations

from ghidra_mcp_c64.config import Settings
from ghidra_mcp_c64.server import create_server


def test_server_exposes_management_metadata() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    assert server.name == "ghidra-mcp-c64"


def test_server_keeps_explicit_dependencies_for_later_tool_registration() -> None:
    dependency = object()
    server = create_server(Settings.from_environ({}), ghidra=dependency)

    assert server.name == "ghidra-mcp-c64"
