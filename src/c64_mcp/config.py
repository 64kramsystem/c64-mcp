"""Environment-backed configuration for the C64 MCP server."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Validated process settings.

    The generic Ghidra server is a trusted local Unix socket service.
    """

    ghidra_timeout: float

    ghidra_mcp_socket: str | None = None

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> Settings:
        socket_path = environ.get("GHIDRA_MCP_SOCKET")
        if socket_path is not None and not socket_path.strip():
            raise ValueError("GHIDRA_MCP_SOCKET must not be blank")

        timeout_text = environ.get("GHIDRA_MCP_TIMEOUT", "30")
        try:
            timeout = float(timeout_text)
        except ValueError as error:
            raise ValueError(
                "GHIDRA_MCP_TIMEOUT must be a finite positive number"
            ) from error
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("GHIDRA_MCP_TIMEOUT must be a finite positive number")

        return cls(
            ghidra_timeout=timeout,
            ghidra_mcp_socket=socket_path,
        )
