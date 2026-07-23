"""MCP server construction."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .config import Settings


def create_server(
    settings: Settings,
    ghidra: Any | None = None,
) -> FastMCP:
    """Create the stdio server without opening external connections.

    Tool modules are added in later implementation stages. Accepting the
    explicit Ghidra boundary here keeps construction testable and prevents
    hidden bridge imports.
    """

    del settings, ghidra
    return FastMCP("ghidra-mcp-c64")

