from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from c64_mcp.errors import RequestError
from c64_mcp.graphics.tools import (
    decode_c64_char_screen,
    decode_c64_charset,
    decode_c64_hires_bitmap,
    decode_c64_multicolor_bitmap,
    decode_c64_sprites,
)


class FakeGhidra:
    def __init__(self, memory: bytes = b"") -> None:
        self.memory = memory
        self.reads: list[tuple[str, str, int]] = []

    def read_bytes(self, program: str, start: str, length: int) -> bytes:
        self.reads.append((program, start, length))
        if len(self.memory) < length:
            raise AssertionError("fake Ghidra memory is too short")
        return self.memory[:length]


class FakeVice:
    def __init__(
        self, memory: bytes = b"", state: str = "stopped"
    ) -> None:
        self.memory = memory
        self.state = state
        self.reads: list[tuple[int, int, int]] = []

    def status(self) -> dict[str, object]:
        return {"ok": True, "state": self.state}

    def read_memory(
        self,
        *,
        bank_id: int,
        start: int,
        end: int,
        side_effects: bool = False,
        max_bytes: int = 4096,
        memspace: int = 0,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        self.reads.append((bank_id, start, end))
        length = end - start + 1
        window = self.memory[start : start + length]
        if len(window) != length:
            raise AssertionError("fake VICE memory is too short")
        return {
            "connection_state": "connected",
            "execution_state": self.state,
            "command_sequence": 1,
            "result": {
                "bytes": window.hex(),
                "byte_count": length,
                "complete": True,
                "next_address": None,
            },
        }


def inline(data: bytes) -> dict[str, object]:
    return {"kind": "inline", "bytes": data.hex()}


def summary(result: Any) -> dict[str, Any]:
    assert result.structuredContent is not None
    return dict(result.structuredContent)


def test_one_call_mixes_inline_ghidra_and_vice_sources() -> None:
    bitmap = bytes([0x1B]) + bytes(7)
    ghidra = FakeGhidra(bytes([0x27]))
    vice = FakeVice(bytes(0x2000) + bytes([0x0D]))

    result = decode_c64_multicolor_bitmap(
        ghidra,
        vice,
        bitmap=inline(bitmap),
        screen={"kind": "ghidra", "program": "snapshot", "start": "ram:400"},
        color={"kind": "vice", "bank_id": 1, "start": 0x2000},
        columns=1,
        rows=1,
        background=6,
    )

    assert ghidra.reads == [("snapshot", "ram:400", 1)]
    assert vice.reads == [(1, 0x2000, 0x2000)]
    sources = summary(result)["sources"]
    assert sources["bitmap"]["kind"] == "inline"
    assert sources["screen"]["kind"] == "ghidra"
    assert sources["color"]["kind"] == "vice"
    assert sources["screen"] == {
        "kind": "ghidra",
        "supplied": 1,
        "consumed": 1,
        "trailing": 0,
    }


def test_a_vice_source_without_bank_id_is_rejected_before_any_read() -> None:
    ghidra = FakeGhidra()
    vice = FakeVice(bytes(0x10000))

    with pytest.raises(RequestError, match="bank_id"):
        decode_c64_hires_bitmap(
            ghidra,
            vice,
            bitmap={"kind": "vice", "start": 0x2000},
            screen=inline(bytes(1)),
            columns=1,
            rows=1,
        )

    assert vice.reads == []


def test_a_vice_read_past_ffff_is_rejected_with_both_lengths() -> None:
    ghidra = FakeGhidra()
    vice = FakeVice(bytes(0x10000))

    with pytest.raises(RequestError) as error:
        decode_c64_hires_bitmap(
            ghidra,
            vice,
            bitmap={"kind": "vice", "bank_id": 0, "start": 0xFFF9},
            screen=inline(bytes(1)),
            columns=1,
            rows=1,
        )

    assert "8" in str(error.value)
    assert "7" in str(error.value)
    assert vice.reads == []


@pytest.mark.parametrize(
    "source",
    [
        {"kind": "elsewhere", "bytes": "00"},
        {"bytes": "00"},
        {"kind": "inline", "bytes": "0"},
        {"kind": "inline", "bytes": "zz"},
        {"kind": "inline"},
        {"kind": "inline", "bytes": "00", "program": "p"},
        {"kind": "ghidra", "program": "p"},
        {"kind": "ghidra", "program": " ", "start": "ram:0"},
        {"kind": "vice", "bank_id": 0},
        {"kind": "vice", "bank_id": 0, "start": -1},
        {"kind": "vice", "bank_id": 0, "start": 0x10000},
        {"kind": "vice", "bank_id": -1, "start": 0},
        "inline",
    ],
)
def test_a_malformed_source_is_rejected_without_remote_reads(
    source: object,
) -> None:
    ghidra = FakeGhidra(bytes(64))
    vice = FakeVice(bytes(0x10000))

    with pytest.raises(RequestError):
        decode_c64_hires_bitmap(
            ghidra,
            vice,
            bitmap=source,
            screen={
                "kind": "ghidra",
                "program": "snapshot",
                "start": "ram:400",
            },
            columns=1,
            rows=1,
        )

    assert ghidra.reads == []
    assert vice.reads == []


def test_a_short_inline_source_renders_nothing_and_reads_nothing(
    tmp_path: Path,
) -> None:
    ghidra = FakeGhidra(bytes(64))
    vice = FakeVice(bytes(0x10000))
    target = tmp_path / "out.png"

    with pytest.raises(RequestError) as error:
        decode_c64_hires_bitmap(
            ghidra,
            vice,
            bitmap=inline(bytes(7)),
            screen={
                "kind": "ghidra",
                "program": "snapshot",
                "start": "ram:400",
            },
            columns=1,
            rows=1,
            output_path=str(target),
        )

    assert "7" in str(error.value)
    assert "8" in str(error.value)
    assert ghidra.reads == []
    assert vice.reads == []
    assert not target.exists()


def test_an_invalid_colour_combination_reads_nothing() -> None:
    ghidra = FakeGhidra(bytes(4096))
    vice = FakeVice(bytes(0x10000))

    with pytest.raises(RequestError, match="color is required"):
        decode_c64_char_screen(
            ghidra,
            vice,
            screen={
                "kind": "ghidra",
                "program": "snapshot",
                "start": "ram:400",
            },
            charset={"kind": "vice", "bank_id": 0, "start": 0x1000},
            columns=1,
            rows=1,
            multicolor=True,
            background_1=1,
            background_2=2,
        )

    assert ghidra.reads == []
    assert vice.reads == []


def test_an_out_of_range_colour_reads_nothing() -> None:
    ghidra = FakeGhidra(bytes(4096))
    vice = FakeVice(bytes(0x10000))

    with pytest.raises(RequestError, match="background"):
        decode_c64_multicolor_bitmap(
            ghidra,
            vice,
            bitmap={"kind": "vice", "bank_id": 0, "start": 0},
            screen=inline(bytes(1)),
            color=inline(bytes(1)),
            columns=1,
            rows=1,
            background=16,
        )

    assert vice.reads == []


def test_two_vice_sources_while_running_need_the_atomicity_flag() -> None:
    ghidra = FakeGhidra()
    vice = FakeVice(bytes(0x10000), state="running")

    with pytest.raises(RequestError, match="allow_non_atomic_vice_reads"):
        decode_c64_hires_bitmap(
            ghidra,
            vice,
            bitmap={"kind": "vice", "bank_id": 0, "start": 0x2000},
            screen={"kind": "vice", "bank_id": 0, "start": 0x400},
            columns=1,
            rows=1,
        )

    assert vice.reads == []


def test_the_atomicity_flag_permits_the_reads_and_warns_in_both_summaries() -> (
    None
):
    ghidra = FakeGhidra()
    vice = FakeVice(bytes(0x10000), state="running")

    result = decode_c64_hires_bitmap(
        ghidra,
        vice,
        bitmap={"kind": "vice", "bank_id": 0, "start": 0x2000},
        screen={"kind": "vice", "bank_id": 0, "start": 0x400},
        columns=1,
        rows=1,
        allow_non_atomic_vice_reads=True,
    )

    assert len(vice.reads) == 2
    assert summary(result)["warnings"] == ["non_atomic_vice_reads"]
    text = json.loads(result.content[1].text)
    assert text["warnings"] == ["non_atomic_vice_reads"]


def test_two_vice_sources_while_stopped_need_no_flag_and_do_not_warn() -> None:
    ghidra = FakeGhidra()
    vice = FakeVice(bytes(0x10000), state="stopped")

    result = decode_c64_hires_bitmap(
        ghidra,
        vice,
        bitmap={"kind": "vice", "bank_id": 0, "start": 0x2000},
        screen={"kind": "vice", "bank_id": 0, "start": 0x400},
        columns=1,
        rows=1,
    )

    assert len(vice.reads) == 2
    assert summary(result)["warnings"] == []


def test_one_vice_source_while_running_needs_no_flag() -> None:
    ghidra = FakeGhidra()
    vice = FakeVice(bytes(0x10000), state="running")

    result = decode_c64_hires_bitmap(
        ghidra,
        vice,
        bitmap={"kind": "vice", "bank_id": 0, "start": 0x2000},
        screen=inline(bytes(1)),
        columns=1,
        rows=1,
    )

    assert len(vice.reads) == 1
    assert summary(result)["warnings"] == []


def test_a_failing_vice_read_surfaces_the_connector_error() -> None:
    class BrokenVice(FakeVice):
        def read_memory(self, **kwargs: Any) -> dict[str, object]:
            self.reads.append((0, 0, 0))
            return {
                "ok": False,
                "error": {
                    "code": "vice_not_connected",
                    "message": "run vice_connect first",
                },
            }

    vice = BrokenVice()

    with pytest.raises(Exception, match="run vice_connect first"):
        decode_c64_hires_bitmap(
            FakeGhidra(),
            vice,
            bitmap={"kind": "vice", "bank_id": 0, "start": 0x2000},
            screen=inline(bytes(1)),
            columns=1,
            rows=1,
        )


def test_a_short_vice_read_is_refused() -> None:
    class ShortVice(FakeVice):
        def read_memory(self, **kwargs: Any) -> dict[str, object]:
            self.reads.append((0, 0, 0))
            return {
                "result": {
                    "bytes": "00",
                    "byte_count": 1,
                    "complete": False,
                    "next_address": 1,
                }
            }

    with pytest.raises(RequestError, match="8"):
        decode_c64_hires_bitmap(
            FakeGhidra(),
            ShortVice(),
            bitmap={"kind": "vice", "bank_id": 0, "start": 0x2000},
            screen=inline(bytes(1)),
            columns=1,
            rows=1,
        )


def test_trailing_inline_bytes_are_ignored_and_counted() -> None:
    result = decode_c64_hires_bitmap(
        FakeGhidra(),
        FakeVice(),
        bitmap=inline(bytes(12)),
        screen=inline(bytes(3)),
        columns=1,
        rows=1,
    )

    sources = summary(result)["sources"]
    assert sources["bitmap"] == {
        "kind": "inline",
        "supplied": 12,
        "consumed": 8,
        "trailing": 4,
    }
    assert sources["screen"] == {
        "kind": "inline",
        "supplied": 3,
        "consumed": 1,
        "trailing": 2,
    }


def test_an_inline_byte_array_is_accepted() -> None:
    result = decode_c64_charset(
        FakeGhidra(),
        FakeVice(),
        charset={"kind": "inline", "bytes": [0x80, 0, 0, 0, 0, 0, 0, 0]},
        glyph_count=1,
        sheet_columns=1,
    )

    assert summary(result)["sources"]["charset"]["supplied"] == 8


def test_the_char_screen_charset_length_follows_the_highest_screen_code() -> (
    None
):
    ghidra = FakeGhidra(bytes(4096))
    vice = FakeVice(bytes(0x10000))

    decode_c64_char_screen(
        ghidra,
        vice,
        screen=inline(bytes([0, 3, 1, 2])),
        charset={"kind": "vice", "bank_id": 0, "start": 0x1000},
        columns=4,
        rows=1,
    )

    assert vice.reads == [(0, 0x1000, 0x1000 + 32 - 1)]


def test_a_charset_one_byte_short_of_the_highest_screen_code_is_refused() -> (
    None
):
    with pytest.raises(RequestError, match="32"):
        decode_c64_char_screen(
            FakeGhidra(),
            FakeVice(),
            screen=inline(bytes([0, 3, 1, 2])),
            charset=inline(bytes(31)),
            columns=4,
            rows=1,
        )


def test_sprite_sources_use_the_stride_derived_length() -> None:
    vice = FakeVice(bytes(0x10000))

    decode_c64_sprites(
        FakeGhidra(),
        vice,
        sprites={"kind": "vice", "bank_id": 0, "start": 0x3000},
        sprite_count=3,
        sprite_colors=[1, 2, 3],
    )

    assert vice.reads == [(0, 0x3000, 0x3000 + (2 * 64 + 63) - 1)]
