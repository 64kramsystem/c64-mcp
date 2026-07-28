from __future__ import annotations

import pytest

from c64_mcp.errors import CodecDataError
from c64_mcp.text.tables import Encoding, table_for


@pytest.mark.parametrize("encoding", list(Encoding))
def test_every_encoding_has_exactly_256_indexed_entries(
    encoding: Encoding,
) -> None:
    table = table_for(encoding)

    assert len(table) == 256
    assert [entry.byte for entry in table] == list(range(256))


def test_selected_normative_petscii_entries() -> None:
    upper = table_for(Encoding.PETSCII_UPPER)
    lower = table_for(Encoding.PETSCII_LOWER)

    assert upper[0x0D].name == "RETURN"
    assert upper[0x41].glyph == "A"
    assert lower[0x41].glyph == "a"
    assert upper[0x93].name == "CLR"
    assert upper[0x93].printable is False


def test_selected_normative_screen_code_entries() -> None:
    upper = table_for(Encoding.SCREEN_CODE_UPPER)
    lower = table_for(Encoding.SCREEN_CODE_LOWER)

    assert upper[0x00].glyph == "@"
    assert upper[0x01].glyph == "A"
    assert lower[0x01].glyph == "a"
    assert lower[0x41].glyph == "A"
    assert upper[0x81].reverse_video is True
    assert upper[0x81].glyph == upper[0x01].glyph


def test_normative_mode_specific_aliases() -> None:
    petscii_upper = table_for(Encoding.PETSCII_UPPER)
    petscii_lower = table_for(Encoding.PETSCII_LOWER)
    screen_upper = table_for(Encoding.SCREEN_CODE_UPPER)
    screen_lower = table_for(Encoding.SCREEN_CODE_LOWER)

    assert screen_upper[0x5E].glyph == "π"
    assert screen_lower[0x5E].glyph == "↑"
    assert petscii_upper[0xFF].glyph == screen_upper[0x5E].glyph
    assert petscii_lower[0xFF].glyph == screen_lower[0x5E].glyph
    assert all(entry.reverse_video for entry in screen_upper[0x80:])
    assert all(not entry.reverse_video for entry in screen_upper[:0x80])
    assert all(
        not entry.printable
        for entry in (
            *petscii_upper[:0x20],
            *petscii_upper[0x80:0xA0],
        )
    )


def test_tables_and_entries_are_immutable() -> None:
    table = table_for(Encoding.PETSCII_UPPER)

    with pytest.raises(TypeError):
        table[0] = table[1]  # type: ignore[index]
    with pytest.raises((AttributeError, TypeError)):
        table[0].glyph = "X"  # type: ignore[misc]


def test_table_for_rejects_non_encoding_values() -> None:
    with pytest.raises(CodecDataError, match="unsupported encoding"):
        table_for("petscii_upper")  # type: ignore[arg-type]
