from __future__ import annotations

from typing import Any

import pytest

from c64_mcp import __main__ as entrypoint


def test_cli_profile_overrides_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class Server:
        def run(self, *, transport: str) -> None:
            observed["transport"] = transport

    def create_server(settings: Any) -> Server:
        observed["settings"] = settings
        return Server()

    monkeypatch.setenv(
        "C64_MCP_TOOL_PROFILE", "invalid-environment-value"
    )
    monkeypatch.setattr(entrypoint, "create_server", create_server)

    entrypoint.main(["--tool-profile", "vice"])

    assert observed["settings"].tool_profile == "vice"
    assert observed["transport"] == "stdio"
