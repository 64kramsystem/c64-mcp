"""Environment-backed configuration for the C64 MCP server."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, cast
from urllib.parse import urlsplit

ToolProfile = Literal["minimal", "static", "vice", "full"]
TOOL_PROFILE_NAMES = ("minimal", "static", "vice", "full")


@dataclass(frozen=True)
class Settings:
    """Validated process settings.

    The bearer token is excluded from the dataclass representation so ordinary
    diagnostics cannot leak it.
    """

    ghidra_mcp_url: str
    ghidra_auth_token: str | None = field(repr=False)
    ghidra_timeout: float
    transport: Literal["stdio"] = "stdio"
    tool_profile: ToolProfile = "static"

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> Settings:
        url = environ.get(
            "GHIDRA_MCP_URL", "http://127.0.0.1:8089"
        ).rstrip("/")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(
                "GHIDRA_MCP_URL must be an absolute http or https URL"
            )
        if parsed.query or parsed.fragment:
            raise ValueError(
                "GHIDRA_MCP_URL must not contain a query or fragment"
            )

        timeout_text = environ.get("GHIDRA_MCP_TIMEOUT", "30")
        try:
            timeout = float(timeout_text)
        except ValueError as error:
            raise ValueError(
                "GHIDRA_MCP_TIMEOUT must be a finite positive number"
            ) from error
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError(
                "GHIDRA_MCP_TIMEOUT must be a finite positive number"
            )

        token = environ.get("GHIDRA_MCP_AUTH_TOKEN") or None
        profile = environ.get(
            "C64_MCP_TOOL_PROFILE", "static"
        )
        if profile not in TOOL_PROFILE_NAMES:
            choices = ", ".join(TOOL_PROFILE_NAMES)
            raise ValueError(
                "C64_MCP_TOOL_PROFILE must be one of: "
                f"{choices}"
            )
        return cls(
            ghidra_mcp_url=url,
            ghidra_auth_token=token,
            ghidra_timeout=timeout,
            tool_profile=cast(ToolProfile, profile),
        )
