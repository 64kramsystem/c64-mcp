from __future__ import annotations

import math

import pytest

from ghidra_mcp_c64.config import Settings


def test_defaults_are_loopback_and_stdio() -> None:
    settings = Settings.from_environ({})

    assert settings.ghidra_mcp_url == "http://127.0.0.1:8089"
    assert settings.ghidra_auth_token is None
    assert settings.ghidra_timeout == 30.0
    assert settings.transport == "stdio"
    assert settings.tool_profile == "static"


def test_environment_values_are_normalized_without_exposing_token() -> None:
    settings = Settings.from_environ(
        {
            "GHIDRA_MCP_URL": "http://localhost:9000/",
            "GHIDRA_MCP_AUTH_TOKEN": "secret-token",
            "GHIDRA_MCP_TIMEOUT": "4.5",
        }
    )

    assert settings.ghidra_mcp_url == "http://localhost:9000"
    assert settings.ghidra_auth_token == "secret-token"
    assert settings.ghidra_timeout == 4.5
    assert "secret-token" not in repr(settings)


@pytest.mark.parametrize(
    "value",
    ["", "0", "-1", "nan", "inf", "-inf", "not-a-number"],
)
def test_timeout_must_be_finite_and_positive(value: str) -> None:
    with pytest.raises(ValueError, match="GHIDRA_MCP_TIMEOUT"):
        Settings.from_environ({"GHIDRA_MCP_TIMEOUT": value})


def test_default_timeout_is_finite() -> None:
    assert math.isfinite(Settings.from_environ({}).ghidra_timeout)


@pytest.mark.parametrize("profile", ["minimal", "static", "vice", "full"])
def test_tool_profile_accepts_documented_values(profile: str) -> None:
    settings = Settings.from_environ(
        {"GHIDRA_MCP_C64_TOOL_PROFILE": profile}
    )

    assert settings.tool_profile == profile


def test_tool_profile_rejects_unknown_value() -> None:
    with pytest.raises(
        ValueError, match="GHIDRA_MCP_C64_TOOL_PROFILE"
    ):
        Settings.from_environ(
            {"GHIDRA_MCP_C64_TOOL_PROFILE": "everything"}
        )
