from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from mcp.server.fastmcp import Context, FastMCP

from ghidra_mcp_c64.config import Settings
from ghidra_mcp_c64.server import create_server
from ghidra_mcp_c64.tool_profiles import ToolProfileRegistry


async def _call(
    server: FastMCP, name: str, arguments: dict[str, object]
) -> dict[str, Any]:
    _, structured = await server.call_tool(name, arguments)
    assert structured is not None
    return structured


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("profile", "expected_count", "representative"),
    [
        ("minimal", 4, "list_c64_tool_groups"),
        ("static", 9, "decode_c64_text"),
        ("vice", 24, "vice_connect"),
        ("full", 29, "vice_connect"),
    ],
)
async def test_profiles_expose_exact_initial_surfaces(
    profile: str, expected_count: int, representative: str
) -> None:
    settings = Settings.from_environ(
        {"GHIDRA_MCP_C64_TOOL_PROFILE": profile}
    )
    server = create_server(settings, ghidra=object())

    names = {tool.name for tool in await server.list_tools()}

    assert len(names) == expected_count
    assert representative in names
    if profile == "vice":
        assert "decode_c64_text" not in names


@pytest.mark.asyncio
async def test_group_load_and_unload_are_idempotent() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    loaded = await _call(
        server, "load_c64_tool_group", {"group": "vice"}
    )
    loaded_again = await _call(
        server, "load_c64_tool_group", {"group": "vice"}
    )
    unloaded = await _call(
        server, "unload_c64_tool_group", {"group": "vice"}
    )
    unloaded_again = await _call(
        server, "unload_c64_tool_group", {"group": "vice"}
    )

    assert loaded["changed"] is True
    assert loaded["new_tools"] == 20
    assert loaded_again["changed"] is False
    assert unloaded["changed"] is True
    assert unloaded["removed_tools"] == 20
    assert unloaded_again["changed"] is False
    names = {tool.name for tool in await server.list_tools()}
    assert "vice_connect" not in names


@pytest.mark.asyncio
async def test_load_all_keeps_only_profile_baseline_protected() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    loaded = await _call(
        server, "load_c64_tool_group", {"group": "all"}
    )
    protected = await _call(
        server, "unload_c64_tool_group", {"group": "text"}
    )
    unloaded = await _call(
        server, "unload_c64_tool_group", {"group": "vice"}
    )

    assert loaded["loaded_groups"] == ["symbols", "text", "vice"]
    assert protected["error"]["code"] == "protected_group"
    assert unloaded["changed"] is True


@pytest.mark.asyncio
async def test_full_profile_refuses_partial_unload() -> None:
    settings = Settings.from_environ(
        {"GHIDRA_MCP_C64_TOOL_PROFILE": "full"}
    )
    server = create_server(settings, ghidra=object())

    result = await _call(
        server, "unload_c64_tool_group", {"group": "vice"}
    )

    assert result["error"]["code"] == "no_partial_unload"


@pytest.mark.asyncio
async def test_unknown_group_is_structured_and_does_not_mutate() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())
    before = {tool.name for tool in await server.list_tools()}

    result = await _call(
        server, "load_c64_tool_group", {"group": "unknown"}
    )

    assert result["error"]["code"] == "unknown_group"
    assert {tool.name for tool in await server.list_tools()} == before


@pytest.mark.asyncio
async def test_search_finds_hidden_tools_and_supplies_load_call() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    result = await _call(
        server, "search_c64_tools", {"query": "registers"}
    )

    match = next(
        item
        for item in result["matches"]
        if item["name"] == "vice_get_registers"
    )
    assert match["status"] == "not_loaded"
    assert match["fix"] == 'load_c64_tool_group("vice")'


@pytest.mark.asyncio
async def test_search_includes_callable_management_tools() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    result = await _call(
        server, "search_c64_tools", {"query": "groups"}
    )

    match = next(
        item
        for item in result["matches"]
        if item["name"] == "list_c64_tool_groups"
    )
    assert match["status"] == "callable"
    assert "fix" not in match


@pytest.mark.asyncio
async def test_changed_load_sends_notification_once() -> None:
    server = FastMCP("test")
    registry = ToolProfileRegistry(server, "minimal")

    @registry.tool("vice")
    async def vice_example() -> dict[str, object]:
        return {"ok": True}

    sender = AsyncMock()
    request_context = SimpleNamespace(
        session=SimpleNamespace(send_tool_list_changed=sender)
    )
    ctx = Context(
        request_context=cast(Any, request_context),
        fastmcp=server,
    )

    changed = await registry.load("vice", ctx)
    unchanged = await registry.load("vice", ctx)

    assert changed["tools_changed"] == {
        "attempted": True,
        "sent": True,
        "error": None,
    }
    assert unchanged["tools_changed"]["attempted"] is False
    sender.assert_awaited_once()


@pytest.mark.asyncio
async def test_notification_failure_is_reported_after_committed_load() -> None:
    server = FastMCP("test")
    registry = ToolProfileRegistry(server, "minimal")

    @registry.tool("vice")
    async def vice_example() -> dict[str, object]:
        return {"ok": True}

    sender = AsyncMock(side_effect=RuntimeError("broken notification"))
    request_context = SimpleNamespace(
        session=SimpleNamespace(send_tool_list_changed=sender)
    )
    ctx = Context(
        request_context=cast(Any, request_context),
        fastmcp=server,
    )

    result = await registry.load("vice", ctx)

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["tools_changed"] == {
        "attempted": True,
        "sent": False,
        "error": "broken notification",
    }
    assert {tool.name for tool in await server.list_tools()} == {
        "vice_example"
    }


@pytest.mark.asyncio
async def test_failed_group_registration_rolls_back_all_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = FastMCP("test")
    registry = ToolProfileRegistry(server, "minimal")

    @registry.tool("vice")
    async def vice_alpha() -> dict[str, object]:
        return {"ok": True}

    @registry.tool("vice")
    async def vice_beta() -> dict[str, object]:
        return {"ok": True}

    real_add = server.add_tool

    def fail_second(function: Any, *args: Any, **kwargs: Any) -> None:
        if function.__name__ == "vice_beta":
            raise RuntimeError("registration failure")
        real_add(function, *args, **kwargs)

    monkeypatch.setattr(server, "add_tool", fail_second)

    result = await registry.load("vice")

    assert result["error"]["code"] == "registration_failed"
    assert await server.list_tools() == []
    state = await registry.list_groups()
    assert state["loaded_groups"] == []


@pytest.mark.asyncio
async def test_concurrent_group_loads_publish_once() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    first, second = await asyncio.gather(
        _call(server, "load_c64_tool_group", {"group": "vice"}),
        _call(server, "load_c64_tool_group", {"group": "vice"}),
    )

    assert sorted([first["changed"], second["changed"]]) == [False, True]
    assert len(await server.list_tools()) == 29
