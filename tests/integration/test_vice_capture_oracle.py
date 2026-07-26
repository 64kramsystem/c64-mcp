"""The deterministic acceptance oracle for `vice_capture_screen`.

Install known bitmap, screen and colour bytes into a live C64, capture the
frame, and compare the cropped pixel-index matrix against the static decoder's
output for the same bytes. Both sides are indexed images whose indices are C64
colour numbers, so equality is exact rather than a visual judgement.

**This suite is opt-in and has never been executed here.** It needs a VICE at
r46020 or later: earlier builds, including the 3.10 release installed on this
machine, overrun their allocation while answering `display get`, and the
connector refuses them by design. Run it with `C64_MCP_VICE_LIVE=1` and
`C64_MCP_VICE_MUTATE=1` against a disposable emulator, launched without
`-warp`.
"""

from __future__ import annotations

import base64
import io
import os
import time
from typing import Any

import pytest
from mcp.types import CallToolResult, ImageContent
from PIL import Image

from c64_mcp.config import Settings
from c64_mcp.ghidra_client import GhidraClient
from c64_mcp.graphics.capture import vice_capture_screen
from c64_mcp.graphics.tools import (
    decode_c64_hires_bitmap,
    decode_c64_multicolor_bitmap,
)
from c64_mcp.vice import ViceSession

BITMAP_BASE = 0x2000
SCREEN_BASE = 0x0400
COLOR_BASE = 0xD800
BITMAP_BYTES = 8_000
SCREEN_BYTES = 1_000
WRITE_CHUNK = 1_024
BITMAP = bytes((index * 37 + 11) & 0xFF for index in range(BITMAP_BYTES))
SCREEN = bytes((index * 7 + 3) & 0xFF for index in range(SCREEN_BYTES))
COLOR = bytes((index * 5 + 1) & 0x0F for index in range(SCREEN_BYTES))


def live_session() -> ViceSession:
    if (
        os.environ.get("C64_MCP_VICE_LIVE") != "1"
        or os.environ.get("C64_MCP_VICE_MUTATE") != "1"
    ):
        pytest.skip(
            "set C64_MCP_VICE_LIVE=1 and C64_MCP_VICE_MUTATE=1 with a "
            "disposable VICE at r46020 or later; earlier builds are refused "
            "by the connector because display get overruns its allocation"
        )
    settings = Settings.from_environ(os.environ)
    return ViceSession(
        GhidraClient(
            settings.ghidra_mcp_url,
            settings.ghidra_auth_token,
            settings.ghidra_timeout,
        )
    )


class NoGhidra:
    def read_bytes(self, program: str, start: str, length: int) -> bytes:
        raise AssertionError("the oracle decodes inline bytes only")


class NoVice:
    def status(self) -> dict[str, object]:
        return {"ok": True, "state": "stopped"}

    def read_memory(self, **kwargs: Any) -> dict[str, object]:
        raise AssertionError("the oracle decodes inline bytes only")


def inline(data: bytes) -> dict[str, object]:
    return {"kind": "inline", "bytes": data.hex()}


def pixels(result: CallToolResult) -> list[list[int]]:
    block = result.content[0]
    assert isinstance(block, ImageContent)
    image = Image.open(io.BytesIO(base64.b64decode(block.data)))
    image.load()
    return [
        [image.getpixel((x, y)) for x in range(image.width)]
        for y in range(image.height)
    ]


def poke(session: ViceSession, address: int, value: int) -> None:
    written = session.write_memory(
        bank_id=0, start=address, bytes=bytes([value]).hex()
    )
    assert written["ok"] is True, written


def fill(session: ViceSession, start: int, data: bytes) -> None:
    for offset in range(0, len(data), WRITE_CHUNK):
        chunk = data[offset : offset + WRITE_CHUNK]
        written = session.write_memory(
            bank_id=0, start=start + offset, bytes=chunk.hex()
        )
        assert written["ok"] is True, written


@pytest.mark.parametrize("multicolor", [False, True])
def test_live_capture_matches_the_static_decoder(multicolor: bool) -> None:
    session = live_session()
    assert session.connect()["ok"] is True
    assert session.interrupt()["ok"] is True

    # Silence the KERNAL IRQ first: its cursor blink writes into $0400, which
    # is the video matrix once bitmap mode is on, and would desynchronise the
    # captured frame from the bytes the static decoder is given.
    poke(session, 0xDC0D, 0x7F)
    fill(session, BITMAP_BASE, BITMAP)
    fill(session, SCREEN_BASE, SCREEN)
    fill(session, COLOR_BASE, COLOR)
    poke(session, 0xDD00, 0x03)  # VIC bank 0: $0000-$3FFF
    poke(session, 0xD018, 0x18)  # video matrix $0400, bitmap $2000
    poke(session, 0xD011, 0x3B)  # bitmap mode, screen on, YSCROLL 3
    poke(session, 0xD016, 0xD8 if multicolor else 0xC8)  # XSCROLL 0, 40 cols
    poke(session, 0xD021, 0x00)  # multicolor bit pair 00

    # A stopped emulator still shows the frame it last drew, so let it run
    # long enough to composite the bytes just installed.
    assert session.resume()["ok"] is True
    time.sleep(0.5)
    assert session.interrupt()["ok"] is True

    captured = vice_capture_screen(session)
    if multicolor:
        expected = decode_c64_multicolor_bitmap(
            NoGhidra(),
            NoVice(),
            bitmap=inline(BITMAP),
            screen=inline(SCREEN),
            color=inline(COLOR),
            background=0,
        )
    else:
        expected = decode_c64_hires_bitmap(
            NoGhidra(),
            NoVice(),
            bitmap=inline(BITMAP),
            screen=inline(SCREEN),
        )

    summary = captured.structuredContent
    assert summary is not None
    assert (summary["width"], summary["height"]) == (320, 200)
    assert summary["cropped"] is True
    # A blank frame would satisfy every structural check while proving
    # nothing, so require real variety.
    assert summary["distinct_index_count"] >= 2
    assert pixels(captured) == pixels(expected)
