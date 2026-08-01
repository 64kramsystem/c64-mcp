import pytest
from mcp.types import CallToolResult

from c64_mcp.config import Settings
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
