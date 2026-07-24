from __future__ import annotations

import asyncio
import threading

import pytest

from ghidra_mcp_c64.config import Settings
from ghidra_mcp_c64.server import create_server


def test_server_exposes_management_metadata() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    assert server.name == "ghidra-mcp-c64"


def test_server_keeps_explicit_dependencies_for_later_tool_registration() -> None:
    dependency = object()
    server = create_server(Settings.from_environ({}), ghidra=dependency)

    assert server.name == "ghidra-mcp-c64"


@pytest.mark.asyncio
async def test_server_registers_c64_text_tools() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    tools = await server.list_tools()

    assert {
        "decode_c64_text",
        "search_c64_text",
        "define_c64_text",
    } <= {tool.name for tool in tools}
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
async def test_server_registers_complete_vice_surface_with_safe_defaults() -> None:
    server = create_server(Settings.from_environ({}), ghidra=object())

    tools = await server.list_tools()
    by_name = {tool.name: tool.inputSchema for tool in tools}
    expected = {
        "vice_connect",
        "vice_disconnect",
        "vice_status",
        "vice_get_registers",
        "vice_set_registers",
        "vice_list_banks",
        "vice_read_memory",
        "vice_write_memory",
        "vice_list_checkpoints",
        "vice_set_checkpoint",
        "vice_delete_checkpoint",
        "vice_toggle_checkpoint",
        "vice_step",
        "vice_next",
        "vice_finish",
        "vice_resume",
        "vice_interrupt",
        "vice_wait_for_stop",
        "vice_reset",
        "copy_vice_memory_to_ghidra",
    }

    assert expected <= set(by_name)
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
