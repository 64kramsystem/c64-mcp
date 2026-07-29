import pytest

from c64_mcp.errors import RequestError
from c64_mcp.text.codec import decode_c64_bytes
from c64_mcp.text.tables import Encoding


def test_petscii_and_reverse_screen_codes_are_readable():
    petscii = decode_c64_bytes(b"ABC", encoding=Encoding.PETSCII_UPPER)
    screen = decode_c64_bytes(bytes([1, 0x81]), encoding=Encoding.SCREEN_CODE_UPPER)

    assert petscii.as_dict()["text"] == "ABC"
    assert petscii.as_dict()["consumed_hex"] == "414243"
    assert screen.text == "A{REV A}"


def test_length_terminator_prefix_and_token_selection():
    assert (
        decode_c64_bytes(b"ABC", encoding=Encoding.PETSCII_UPPER, length=2).text == "AB"
    )
    terminated = decode_c64_bytes(
        b"AB\x00C", encoding=Encoding.PETSCII_UPPER, terminator=0
    )
    assert terminated.text == "AB"
    assert terminated.terminated is True
    prefixed = decode_c64_bytes(
        b"\x02ABZ",
        encoding=Encoding.PETSCII_UPPER,
        prefix_size=1,
        tokens={ord("A"): "<A>"},
    )
    assert prefixed.text == "<A>B"
    assert prefixed.consumed == b"\x02AB"


def test_missing_terminator_is_reported_without_discarding_data():
    result = decode_c64_bytes(b"AB", encoding=Encoding.PETSCII_UPPER, terminator=0)

    assert result.text == "AB"
    assert result.terminated is False
    assert result.warnings


def test_selection_modes_are_mutually_exclusive():
    with pytest.raises(RequestError, match="only one"):
        decode_c64_bytes(
            b"AB",
            encoding=Encoding.PETSCII_UPPER,
            length=1,
            terminator=0,
        )
