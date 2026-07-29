import base64
import json

import pytest
from mcp.types import ImageContent, TextContent

from c64_mcp.errors import RequestError
from c64_mcp.graphics.png import PNG_SIGNATURE
from c64_mcp.graphics.tools import (
    decode_c64_char_screen,
    decode_c64_hires_bitmap,
    decode_c64_multicolor_bitmap,
)


class FakeGhidra:
    def __init__(self, data=b""):
        self.data = data
        self.calls = []

    def read_bytes(self, program, start, length):
        self.calls.append((program, start, length))
        return self.data[:length]


def inline(data):
    return {"kind": "inline", "bytes": data.hex()}


def test_decoder_returns_one_png_and_one_matching_summary():
    result = decode_c64_hires_bitmap(
        FakeGhidra(),
        bitmap=inline(bytes(8)),
        screen=inline(b"\x10"),
        columns=1,
        rows=1,
    )

    image, text = result.content
    assert isinstance(image, ImageContent)
    assert isinstance(text, TextContent)
    assert base64.b64decode(image.data).startswith(PNG_SIGNATURE)
    assert json.loads(text.text) == result.structuredContent
    assert result.structuredContent["mode"] == "hires_bitmap"


def test_character_screen_reads_only_the_needed_remote_glyphs():
    ghidra = FakeGhidra(bytes(16))
    result = decode_c64_char_screen(
        ghidra,
        screen=inline(b"\x01"),
        charset={
            "kind": "ghidra",
            "program": "game",
            "start": "RAM:2000",
        },
        columns=1,
        rows=1,
    )

    assert result.structuredContent["mode"] == "char_screen"
    assert ghidra.calls == [("game", "RAM:2000", 16)]


def test_short_inline_source_is_rejected_before_remote_read():
    ghidra = FakeGhidra(bytes(8))
    with pytest.raises(RequestError, match="screen supplies"):
        decode_c64_multicolor_bitmap(
            ghidra,
            bitmap={"kind": "ghidra", "program": "game", "start": "RAM:2000"},
            screen=inline(b""),
            color=inline(b"\x00"),
            columns=1,
            rows=1,
        )

    assert ghidra.calls == []
