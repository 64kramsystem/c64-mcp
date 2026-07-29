import pytest

from c64_mcp.errors import RequestError
from c64_mcp.text.tools import decode_c64_text


class FakeGhidra:
    def __init__(self):
        self.calls = []

    def read_bytes(self, program, start, length):
        self.calls.append((program, start, length))
        return b"ABC"[:length]


def test_inline_hex_and_tokens_decode_without_ghidra():
    result = decode_c64_text(
        FakeGhidra(),
        bytes="41 42",
        tokens={"65": "<A>"},
    )

    assert result["text"] == "<A>B"
    assert result["source"] == {"kind": "inline"}


def test_ghidra_source_is_one_bounded_read():
    ghidra = FakeGhidra()

    result = decode_c64_text(
        ghidra,
        program="game",
        start="RAM:1000",
        max_length=3,
    )

    assert result["text"] == "ABC"
    assert ghidra.calls == [("game", "RAM:1000", 3)]


def test_source_forms_cannot_be_mixed():
    with pytest.raises(RequestError, match="choose inline"):
        decode_c64_text(
            FakeGhidra(),
            bytes="41",
            program="game",
            start="RAM:1000",
            max_length=1,
        )
