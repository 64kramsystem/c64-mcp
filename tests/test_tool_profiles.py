from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from mcp.server.fastmcp import Context, FastMCP

from c64_mcp.config import Settings
from c64_mcp.server import create_server
from c64_mcp.tool_profiles import ToolProfileRegistry


async def _call(
    server: FastMCP, name: str, arguments: dict[str, object]
) -> dict[str, Any]:
    _, structured = await server.call_tool(name, arguments)
    assert structured is not None
    return structured


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("profile", "representative"),
    [
        ("minimal", "list_c64_tool_groups"),
        ("static", "decode_c64_text"),
        ("vice", "vice_capture_screen"),
        ("full", "vice_connect"),
    ],
)
async def test_profiles_expose_representative_initial_tools(
    profile: str, representative: str
) -> None:
    settings = Settings.from_environ(
        {"C64_MCP_TOOL_PROFILE": profile}
    )
    server = create_server(settings, ghidra=object())

    names = {tool.name for tool in await server.list_tools()}

    assert representative in names
    if profile == "vice":
        assert "decode_c64_text" not in names


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", ["static", "full"])
async def test_graphics_is_a_baseline_group_of_static_and_full(
    profile: str,
) -> None:
    settings = Settings.from_environ({"C64_MCP_TOOL_PROFILE": profile})
    server = create_server(settings, ghidra=object())

    listing = await _call(server, "list_c64_tool_groups", {})

    graphics = next(
        group
        for group in listing["groups"]
        if group["group"] == "graphics"
    )
    assert graphics["baseline"] is True
    assert graphics["loaded"] is True
    assert "decode_c64_hires_bitmap" in graphics["tools"]
    assert graphics["tool_count"] == len(graphics["tools"])


@pytest.mark.asyncio
async def test_screen_capture_belongs_to_vice_not_graphics() -> None:
    settings = Settings.from_environ({"C64_MCP_TOOL_PROFILE": "full"})
    server = create_server(settings, ghidra=object())

    listing = await _call(server, "list_c64_tool_groups", {})
    groups = {group["group"]: group for group in listing["groups"]}

    assert "vice_capture_screen" in groups["vice"]["tools"]
    assert "vice_capture_screen" not in groups["graphics"]["tools"]


@pytest.mark.asyncio
async def test_graphics_is_hidden_from_the_vice_profile() -> None:
    settings = Settings.from_environ({"C64_MCP_TOOL_PROFILE": "vice"})
    server = create_server(settings, ghidra=object())

    names = {tool.name for tool in await server.list_tools()}

    assert "decode_c64_hires_bitmap" not in names


@pytest.mark.asyncio
async def test_group_load_and_unload_are_idempotent() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())
    initial_names = {tool.name for tool in await server.list_tools()}

    loaded = await _call(
        server, "load_c64_tool_group", {"group": "vice"}
    )
    loaded_again = await _call(
        server, "load_c64_tool_group", {"group": "vice"}
    )
    loaded_names = {tool.name for tool in await server.list_tools()}
    unloaded = await _call(
        server, "unload_c64_tool_group", {"group": "vice"}
    )
    unloaded_again = await _call(
        server, "unload_c64_tool_group", {"group": "vice"}
    )

    assert loaded["changed"] is True
    assert loaded["new_tools"] == len(loaded_names - initial_names)
    assert "vice_connect" in loaded_names
    assert loaded_again["changed"] is False
    assert loaded_again["new_tools"] == 0
    assert unloaded["changed"] is True
    assert unloaded_again["changed"] is False
    names = {tool.name for tool in await server.list_tools()}
    assert unloaded["removed_tools"] == len(loaded_names - names)
    assert unloaded_again["removed_tools"] == 0
    assert "vice_connect" not in names


@pytest.mark.asyncio
async def test_load_all_keeps_only_profile_baseline_protected() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())
    listing = await _call(server, "list_c64_tool_groups", {})
    expected_groups = {group["group"] for group in listing["groups"]}

    loaded = await _call(
        server, "load_c64_tool_group", {"group": "all"}
    )
    protected = await _call(
        server, "unload_c64_tool_group", {"group": "text"}
    )
    unloaded = await _call(
        server, "unload_c64_tool_group", {"group": "vice"}
    )

    assert loaded["changed"] is True
    assert set(loaded["loaded_groups"]) == expected_groups
    assert protected["error"]["code"] == "protected_group"
    assert unloaded["changed"] is True


@pytest.mark.asyncio
async def test_full_profile_refuses_partial_unload() -> None:
    settings = Settings.from_environ(
        {"C64_MCP_TOOL_PROFILE": "full"}
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
    assert "vice_connect" in {
        tool.name for tool in await server.list_tools()
    }
