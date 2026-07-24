from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from ghidra_mcp_c64.errors import RequestError, TextLimitError
from ghidra_mcp_c64.text.tools import (
    decode_c64_text,
    define_c64_text,
    search_c64_text,
)


class FakeGhidra:
    def __init__(self, memory: bytes = b"") -> None:
        self.memory = memory
        self.read_calls: list[tuple[str, str, int]] = []
        self.apply_calls: list[
            tuple[str, list[Mapping[str, object]], bool]
        ] = []

    def read_bytes(self, program: str, start: str, length: int) -> bytes:
        self.read_calls.append((program, start, length))
        if len(self.memory) < length:
            raise AssertionError(
                f"fake has {len(self.memory)} bytes, requested {length}"
            )
        return self.memory[:length]

    def apply_data_regions(
        self,
        program: str,
        regions: list[Mapping[str, object]],
        *,
        dry_run: bool = True,
    ) -> dict[str, object]:
        self.apply_calls.append((program, regions, dry_run))
        return {"applied": not dry_run, "dry_run": dry_run}


def fixed(**extra: Any) -> dict[str, Any]:
    return {
        "encoding": "petscii_upper",
        "length": 2,
        **extra,
    }


def test_decode_requires_exactly_one_source() -> None:
    ghidra = FakeGhidra()

    with pytest.raises(RequestError, match="exactly one byte source"):
        decode_c64_text(
            ghidra,
            bytes="41",
            program="p",
            start="1000",
            max_length=1,
            **fixed(length=1),
        )
    with pytest.raises(RequestError, match="exactly one byte source"):
        decode_c64_text(ghidra, **fixed())


def test_inline_accepts_hex_and_integer_arrays() -> None:
    ghidra = FakeGhidra()

    from_hex = decode_c64_text(ghidra, bytes="41 42", **fixed())
    from_list = decode_c64_text(ghidra, bytes=[0x41, 0x42], **fixed())

    assert from_hex["plain_text"] == "AB"
    assert from_list == from_hex


@pytest.mark.parametrize(
    "value",
    ["4", "GG", [0, True], [256], [-1], [1.0]],
)
def test_inline_rejects_malformed_bytes(value: object) -> None:
    with pytest.raises(RequestError):
        decode_c64_text(
            FakeGhidra(),
            bytes=value,  # type: ignore[arg-type]
            **fixed(),
        )


def test_inline_and_ghidra_sources_decode_identically() -> None:
    ghidra = FakeGhidra(b"AB")

    inline = decode_c64_text(ghidra, bytes="4142", **fixed())
    remote = decode_c64_text(
        ghidra,
        program="snapshot",
        start="ram:1000",
        max_length=2,
        **fixed(),
    )

    assert {
        key: value for key, value in remote.items() if key != "source"
    } == {
        key: value for key, value in inline.items() if key != "source"
    }
    assert ghidra.read_calls == [("snapshot", "ram:1000", 2)]


def test_decode_validates_options_before_reading_ghidra() -> None:
    ghidra = FakeGhidra(b"A")

    with pytest.raises(RequestError, match="encoding"):
        decode_c64_text(
            ghidra,
            program="p",
            start="1000",
            max_length=1,
            encoding="invalid",
            length=1,
        )

    assert ghidra.read_calls == []


def test_exactly_one_length_mode_is_required() -> None:
    with pytest.raises(RequestError, match="exactly one length mode"):
        decode_c64_text(
            FakeGhidra(),
            bytes="41",
            length=1,
            terminator=0,
        )
    with pytest.raises(RequestError, match="exactly one length mode"):
        decode_c64_text(FakeGhidra(), bytes="41")


def test_token_keys_are_strict_decimal_or_prefixed_hex() -> None:
    result = decode_c64_text(
        FakeGhidra(),
        bytes="4142",
        tokens={"65": "decimal", "0x42": "hex"},
        **fixed(),
    )

    assert result["plain_text"] == "decimalhex"
    for invalid in ({" 65": "x"}, {"GG": "x"}, {"256": "x"}):
        with pytest.raises(RequestError, match="token"):
            decode_c64_text(
                FakeGhidra(),
                bytes="41",
                tokens=invalid,
                **fixed(length=1),
            )


def test_search_finds_overlapping_exact_byte_matches() -> None:
    ghidra = FakeGhidra(b"ABABA")

    result = search_c64_text(
        ghidra,
        program="snapshot",
        start="1000",
        end="1004",
        query="414241",
        query_mode="bytes",
    )

    assert [match["address"] for match in result["matches"]] == [
        "1000",
        "1002",
    ]
    assert result["matches"][0]["raw_bytes"] == [0x41, 0x42, 0x41]
    assert result["scanned_bytes"] == 5


def test_byte_search_honors_and_records_codec_options() -> None:
    ghidra = FakeGhidra(b"\xc1")

    result = search_c64_text(
        ghidra,
        program="snapshot",
        start="1000",
        end="1000",
        query="c1",
        query_mode="bytes",
        high_bit="strip",
        controls="escaped",
        tokens={"193": "TOKEN"},
    )

    match = result["matches"][0]
    assert match["decoded_text"] == "TOKEN"
    assert match["configuration"]["high_bit"] == "strip"
    assert result["configuration"]["tokens"] == {"193": "TOKEN"}


def test_byte_search_validates_codec_options_even_without_matches() -> None:
    ghidra = FakeGhidra(b"A")

    with pytest.raises(RequestError, match="encoding"):
        search_c64_text(
            ghidra,
            program="snapshot",
            start="1000",
            end="1000",
            query="42",
            query_mode="bytes",
            encoding="not-an-encoding",
        )
    assert ghidra.read_calls == []


def test_search_text_is_exact_without_case_folding_or_normalization() -> None:
    ghidra = FakeGhidra(b"ABAB")

    exact = search_c64_text(
        ghidra,
        program="snapshot",
        start="ram:1000",
        end="ram:1003",
        query="AB",
        query_mode="text",
        length=2,
        stride=2,
    )
    wrong_case = search_c64_text(
        ghidra,
        program="snapshot",
        start="ram:1000",
        end="ram:1003",
        query="ab",
        query_mode="text",
        length=2,
    )

    assert [item["address"] for item in exact["matches"]] == [
        "ram:1000",
        "ram:1002",
    ]
    assert wrong_case["matches"] == []


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        ("0x1000", "0x1001", "0x1000"),
        ("ram:0x1000", "ram:0x1001", "ram:0x1000"),
        (
            "OVERLAY::0X1000",
            "OVERLAY::0X1001",
            "OVERLAY::0X1000",
        ),
    ],
)
def test_search_accepts_and_preserves_ghidra_0x_address_forms(
    start: str,
    end: str,
    expected: str,
) -> None:
    result = search_c64_text(
        FakeGhidra(b"AB"),
        program="p",
        start=start,
        end=end,
        query="41",
        query_mode="bytes",
    )

    assert result["matches"][0]["address"] == expected


def test_search_accepts_mixed_hex_prefix_styles_in_one_space() -> None:
    result = search_c64_text(
        FakeGhidra(b"A"),
        program="p",
        start="ram:0x1000",
        end="ram:1000",
        query="41",
        query_mode="bytes",
    )

    assert result["matches"][0]["address"] == "ram:0x1000"


def test_search_prefix_skips_invalid_candidates_and_reports_them() -> None:
    ghidra = FakeGhidra(b"\xffA\x01B")

    result = search_c64_text(
        ghidra,
        program="p",
        start="1000",
        end="1003",
        query="B",
        query_mode="text",
        prefix_size=1,
    )

    assert [item["address"] for item in result["matches"]] == ["1002"]
    assert result["invalid_candidates"] >= 1
    assert any("invalid" in warning for warning in result["warnings"])


def test_search_validates_bounds_spaces_stride_and_caps() -> None:
    ghidra = FakeGhidra(b"A")

    for changes, message in [
        ({"start": "ram:1000", "end": "other:1000"}, "address space"),
        ({"start": "1001", "end": "1000"}, "before"),
        ({"stride": 0}, "stride"),
        ({"max_scan_bytes": 1_048_577}, "max_scan_bytes"),
        ({"max_results": 1001}, "max_results"),
    ]:
        kwargs = {
            "program": "p",
            "start": "1000",
            "end": "1000",
            "query": "41",
            "query_mode": "bytes",
            **changes,
        }
        with pytest.raises(RequestError, match=message):
            search_c64_text(ghidra, **kwargs)


@pytest.mark.parametrize("length", [0, -1, 1_048_577])
def test_text_search_rejects_invalid_fixed_lengths(length: int) -> None:
    with pytest.raises(RequestError, match="length"):
        search_c64_text(
            FakeGhidra(b"A"),
            program="p",
            start="1000",
            end="1000",
            query="A",
            query_mode="text",
            length=length,
        )


def test_text_search_enforces_aggregate_rendering_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ghidra_mcp_c64.text.tools.MAX_RENDERED_CHARS", 10
    )

    with pytest.raises(TextLimitError, match="rendered output"):
        search_c64_text(
            FakeGhidra(b"\x80\x80"),
            program="p",
            start="1000",
            end="1001",
            query="not present",
            query_mode="text",
            length=1,
            tokens={"128": "123456"},
        )


def test_search_honors_max_scan_results_and_stride() -> None:
    ghidra = FakeGhidra(b"AAAAAA")

    result = search_c64_text(
        ghidra,
        program="p",
        start="1000",
        end="1005",
        query="41",
        query_mode="bytes",
        stride=2,
        max_scan_bytes=5,
        max_results=2,
    )

    assert [item["address"] for item in result["matches"]] == [
        "1000",
        "1002",
    ]
    assert result["truncated_scan"] is True
    assert result["result_limit_reached"] is True


def test_define_uses_one_atomic_flat_data_region_request() -> None:
    ghidra = FakeGhidra(b"ABC")

    result = define_c64_text(
        ghidra,
        program="p",
        start="overlay::9a8a",
        encoding="petscii_upper",
        length=3,
        max_length=3,
        label="message",
        namespace="STORY",
        comment="intro",
        dry_run=False,
    )

    assert result["decoded"]["plain_text"] == "ABC"
    assert len(ghidra.apply_calls) == 1
    program, regions, dry_run = ghidra.apply_calls[0]
    assert program == "p"
    assert dry_run is False
    assert regions == [
        {
            "kind": "contiguous",
            "start": "overlay::9a8a",
            "end": "overlay::9a8c",
            "type_name": "byte",
            "clear_conflicts": False,
            "name": "message",
            "namespace": "STORY",
            "plate_comment": (
                "intro\nC64 petscii_upper: "
                "{A:$41}{B:$42}{C:$43}"
            ),
        }
    ]


def test_define_defaults_to_dry_run_and_omits_absent_metadata() -> None:
    ghidra = FakeGhidra(b"A")

    define_c64_text(
        ghidra,
        program="p",
        start="1000",
        length=1,
        max_length=1,
    )

    _, regions, dry_run = ghidra.apply_calls[0]
    assert dry_run is True
    assert "name" not in regions[0]
    assert "namespace" not in regions[0]


def test_define_rejects_invalid_self_inclusive_prefix_without_mutation() -> None:
    ghidra = FakeGhidra(b"\x00")

    with pytest.raises(RequestError, match="smaller than prefix size"):
        define_c64_text(
            ghidra,
            program="p",
            start="1000",
            prefix_size=1,
            prefix_includes_self=True,
            max_length=1,
        )
    assert ghidra.apply_calls == []
