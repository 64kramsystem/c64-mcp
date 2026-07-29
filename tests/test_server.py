from __future__ import annotations

import asyncio
import threading

import pytest
from mcp.types import CallToolResult

from c64_mcp.config import Settings
from c64_mcp.server import create_server


def test_server_exposes_management_metadata() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    assert server.name == "c64-mcp"


def test_server_keeps_explicit_dependencies_for_later_tool_registration() -> None:
    dependency = object()
    server = create_server(Settings.from_environ({}), ghidra=dependency)

    assert server.name == "c64-mcp"


@pytest.mark.asyncio
async def test_server_registers_c64_text_tools() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    tools = await server.list_tools()

    names = {tool.name for tool in tools}
    assert {"decode_c64_text", "define_c64_text"} <= names
    by_name = {tool.name: tool.inputSchema for tool in tools}
    assert by_name["decode_c64_text"]["properties"]["encoding"]["enum"] == [
        "petscii_upper",
        "petscii_lower",
        "screen_code_upper",
        "screen_code_lower",
    ]
    assert by_name["search_c64_text"]["properties"]["query_mode"]["enum"] == [
        "text",
        "bytes",
    ]


@pytest.mark.asyncio
async def test_server_registers_c64_graphics_tools_with_safe_defaults() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    tools = await server.list_tools()
    by_name = {tool.name: tool.inputSchema for tool in tools}

    assert {
        "decode_c64_hires_bitmap",
        "decode_c64_sprites",
    } <= set(by_name)
    hires = by_name["decode_c64_hires_bitmap"]
    assert hires["properties"]["columns"]["default"] == 40
    assert hires["properties"]["rows"]["default"] == 25
    assert hires["properties"]["overwrite"]["default"] is False
    assert (
        hires["properties"]["allow_non_atomic_vice_reads"]["default"] is False
    )
    assert set(hires["required"]) == {"bitmap", "screen"}
    sprites = by_name["decode_c64_sprites"]
    assert sprites["properties"]["sprite_stride"]["default"] == 64
    assert sprites["properties"]["sheet_columns"]["default"] == 8
    assert set(sprites["required"]) == {
        "sprites",
        "sprite_count",
        "sprite_colors",
    }
    charset = by_name["decode_c64_charset"]
    assert charset["properties"]["glyph_count"]["default"] == 256
    assert charset["properties"]["sheet_columns"]["default"] == 16
    char_screen = by_name["decode_c64_char_screen"]
    assert set(char_screen["required"]) == {"screen", "charset"}
    # A declared output schema would make FastMCP validate, and the lowlevel
    # server duplicate, the image content into structured output.
    assert all(
        tool.outputSchema is None
        for tool in tools
        if tool.name.startswith("decode_c64_")
        and tool.name != "decode_c64_text"
    )


@pytest.mark.asyncio
async def test_graphics_tools_return_an_image_and_a_summary() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    result = await server.call_tool(
        "decode_c64_hires_bitmap",
        {
            "bitmap": {"kind": "inline", "bytes": "80" + "00" * 7},
            "screen": {"kind": "inline", "bytes": "10"},
            "columns": 1,
            "rows": 1,
        },
    )

    assert isinstance(result, CallToolResult)
    assert [block.type for block in result.content] == ["image", "text"]
    assert result.structuredContent is not None
    assert result.structuredContent["mode"] == "hires_bitmap"


@pytest.mark.asyncio
async def test_server_registers_c64_profile_tools_with_safe_defaults() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    tools = await server.list_tools()
    by_name = {tool.name: tool.inputSchema for tool in tools}

    assert {
        "get_c64_symbol_profile",
        "apply_c64_symbol_profile",
    } <= set(by_name)
    properties = by_name["apply_c64_symbol_profile"]["properties"]
    assert properties["conflict_policy"]["enum"] == [
        "error",
        "keep",
        "replace",
    ]
    assert properties["dry_run"]["default"] is True
    assert properties["replace_user_definitions"]["default"] is False
    assert properties["create_memory_blocks"]["default"] is False


@pytest.mark.asyncio
async def test_server_registers_representative_vice_tools_with_safe_defaults() -> None:
    server = create_server(
        Settings.from_environ(
            {"C64_MCP_TOOL_PROFILE": "full"}
        ),
        ghidra=object(),
    )

    tools = await server.list_tools()
    by_name = {tool.name: tool.inputSchema for tool in tools}
    assert {
        "vice_connect",
        "vice_capture_screen",
        "copy_vice_memory_to_ghidra",
    } <= set(by_name)
    capture = by_name["vice_capture_screen"]["properties"]
    assert capture["crop"]["default"] is True
    assert capture["use_vic"]["default"] is True
    assert capture["timeout_ms"]["default"] == 10_000
    assert capture["overwrite"]["default"] is False
    assert by_name["vice_capture_screen"].get("required", []) == []
    # An output schema would make the lowlevel server duplicate the image
    # content into structured output.
    assert all(
        tool.outputSchema is None
        for tool in tools
        if tool.name == "vice_capture_screen"
    )
    copy = by_name["copy_vice_memory_to_ghidra"]["properties"]
    assert copy["dry_run"]["default"] is True
    assert copy["conflict_policy"]["enum"] == [
        "error",
        "overwrite_bytes",
    ]
    assert by_name["vice_reset"]["properties"]["kind"]["enum"] == [
        "soft",
        "hard",
        "drive8",
        "drive9",
    ]
    phase = by_name["import_vice_phase"]["properties"]
    assert phase["dry_run"]["default"] is True
    assert phase["overwrite"]["default"] is False
    assert phase["ghidra_timeout_ms"]["default"] == 30_000
    transition = by_name["vice_capture_transition"]["properties"]
    assert transition["checkpoint_operations"]["default"] == 4
    assert transition["overwrite"]["default"] is False
    indexed = by_name["search_6502_indexed_operands"]["properties"]
    assert indexed["limit"]["default"] == 1_000
    assert "dry_run" not in indexed
    assert "batch_update" not in indexed


@pytest.mark.asyncio
async def test_vice_runtime_tools_execute_without_a_binding() -> None:
    server = create_server(
        Settings.from_environ({"C64_MCP_TOOL_PROFILE": "full"}),
        ghidra=object(),
    )

    _, status = await server.call_tool("vice_status", {})

    assert status is not None
    assert status["state"] == "unbound"
    with pytest.raises(Exception, match="vice_connect"):
        await server.call_tool("vice_capture_screen", {})


@pytest.mark.asyncio
async def test_default_profile_exposes_static_and_management_tools() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    names = {tool.name for tool in await server.list_tools()}

    assert {
        "decode_c64_text",
        "decode_c64_hires_bitmap",
        "list_c64_tool_groups",
    } <= names
    assert "vice_connect" not in names
    # Capture is a live-debugger tool, so the static profile must not carry it.
    assert "vice_capture_screen" not in names


@pytest.mark.asyncio
async def test_management_tools_hide_context_from_their_schemas() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    by_name = {
        tool.name: tool.inputSchema for tool in await server.list_tools()
    }

    assert set(
        by_name["load_c64_tool_group"]["properties"]
    ) == {"group"}
    assert set(
        by_name["unload_c64_tool_group"]["properties"]
    ) == {"group"}


@pytest.mark.asyncio
async def test_blocking_ghidra_read_runs_off_the_event_loop() -> None:
    class BlockingGhidra:
        def read_bytes(
            self, program: str, start: str, length: int
        ) -> bytes:
            del program, start
            assert threading.current_thread() is not threading.main_thread()
            return b"A" * length

    server = create_server(Settings.from_environ({}), ghidra=BlockingGhidra())
    loop_progressed = False

    async def tick() -> None:
        nonlocal loop_progressed
        await asyncio.sleep(0)
        loop_progressed = True

    call = server.call_tool(
        "decode_c64_text",
        {
            "program": "p",
            "start": "1000",
            "max_length": 1,
            "length": 1,
        },
    )
    await asyncio.gather(call, tick())

    assert loop_progressed is True
