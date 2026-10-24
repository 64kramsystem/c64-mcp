import base64

import pytest
from mcp import Client
from mcp_types import CallToolResult

from c64_mcp.config import Settings
from c64_mcp.errors import GhidraTransportError
from c64_mcp.server import create_server


async def tools():
    server = create_server(Settings.from_environ({}), ghidra=object())
    return {tool.name: tool for tool in await server.list_tools()}


@pytest.mark.asyncio
async def test_server_exposes_only_the_retained_c64_surface():
    by_name = await tools()

    assert set(by_name) == {
        "apply_c64_symbols",
        "decode_c64_text",
        "decode_c64_hires_bitmap",
        "decode_c64_multicolor_bitmap",
        "decode_c64_charset",
        "decode_c64_char_screen",
        "decode_c64_sprites",
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
        "vice_feed_keyboard",
        "vice_set_joyport",
        "vice_set_keyboard_matrix",
        "vice_save_snapshot",
        "vice_load_snapshot",
        "vice_reset",
        "vice_capture_screen",
        "copy_vice_memory_to_ghidra",
    }


@pytest.mark.asyncio
async def test_static_bitmap_tool_returns_image_content():
    server = create_server(Settings.from_environ({}), ghidra=object())

    result = await server.call_tool(
        "decode_c64_hires_bitmap",
        {
            "bitmap": {"kind": "inline", "bytes": "00" * 8},
            "screen": {"kind": "inline", "bytes": "10"},
            "columns": 1,
            "rows": 1,
        },
    )

    assert isinstance(result, CallToolResult)
    assert [block.type for block in result.content] == ["image", "text"]


@pytest.mark.asyncio
async def test_current_protocol_lists_and_calls_bitmap_tool():
    server = create_server(Settings.from_environ({}), ghidra=object())
    async with Client(server, mode="2026-07-28") as client:
        listing = await client.list_tools()
        bitmap = next(
            tool for tool in listing.tools if tool.name == "decode_c64_hires_bitmap"
        )
        assert "bitmap" in bitmap.input_schema["required"]
        result = await client.call_tool(
            bitmap.name,
            {
                "bitmap": {"kind": "inline", "bytes": "00" * 8},
                "screen": {"kind": "inline", "bytes": "10"},
                "columns": 1,
                "rows": 1,
            },
        )

    assert not result.is_error
    assert [block.type for block in result.content] == ["image", "text"]
    assert result.content[0].mime_type == "image/png"
    assert base64.b64decode(result.content[0].data).startswith(b"\x89PNG\r\n\x1a\n")
    assert result.structured_content["mode"] == "hires_bitmap"


@pytest.mark.asyncio
async def test_current_protocol_explains_invalid_input():
    server = create_server(Settings.from_environ({}), ghidra=object())
    async with Client(server, mode="2026-07-28") as client:
        result = await client.call_tool("decode_c64_text", {"bytes": "123"})

    assert result.is_error
    assert "even-length hexadecimal string" in result.content[0].text


@pytest.mark.asyncio
async def test_current_protocol_explains_backend_failure():
    class UnavailableGhidra:
        def read_bytes(self, *args, **kwargs):
            raise GhidraTransportError(
                "Ghidra connection refused",
                code="ghidra_transport_failure",
                timeout_layer=None,
                outcome_unknown=False,
                request_committed=False,
            )

    server = create_server(Settings.from_environ({}), ghidra=UnavailableGhidra())
    async with Client(server, mode="2026-07-28") as client:
        result = await client.call_tool(
            "decode_c64_text",
            {"program": "Test", "start": "c000", "max_length": 4},
        )

    assert result.is_error
    assert "Ghidra connection refused" in result.content[0].text
