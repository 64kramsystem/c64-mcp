from __future__ import annotations

from dataclasses import replace

import pytest

from ghidra_mcp_c64.errors import (
    RequestError,
    TextLimitError,
    TokenCycleError,
)
from ghidra_mcp_c64.text.codec import (
    ControlMode,
    DecodeOptions,
    HighBitMode,
    LengthMode,
    TokenOptions,
    decode_c64_bytes,
)
from ghidra_mcp_c64.text.tables import Encoding


def options(**changes: object) -> DecodeOptions:
    base = DecodeOptions(
        encoding=Encoding.PETSCII_UPPER,
        mode=LengthMode.FIXED,
        length=1,
    )
    return replace(base, **changes)


@pytest.mark.parametrize("encoding", list(Encoding))
def test_every_byte_has_stable_distinct_lossless_rendering(
    encoding: Encoding,
) -> None:
    renderings = {
        decode_c64_bytes(
            bytes([value]),
            options(encoding=encoding),
        ).lossless
        for value in range(256)
    }

    assert len(renderings) == 256


def test_terminator_is_consumed_and_recorded_but_not_rendered() -> None:
    result = decode_c64_bytes(
        bytes([0x41, 0x42, 0x00, 0x43]),
        options(
            mode=LengthMode.TERMINATOR,
            length=None,
            terminator=0,
        ),
    )

    assert result.consumed == bytes([0x41, 0x42, 0x00])
    assert result.plain_text == "AB"
    assert len(result.records) == 3
    assert result.records[-1].included_in_text is False
    assert result.terminated is True


def test_absent_terminator_consumes_the_source_boundary() -> None:
    result = decode_c64_bytes(
        b"AB",
        options(
            mode=LengthMode.TERMINATOR,
            length=None,
            terminator=0,
        ),
    )

    assert result.consumed == b"AB"
    assert result.plain_text == "AB"
    assert result.terminated is False
    assert result.warnings == ("terminator 0x00 was not found",)


@pytest.mark.parametrize(
    ("data", "prefix_size", "includes_self", "expected"),
    [
        (b"\x02ABZ", 1, False, b"\x02AB"),
        (b"\x03ABZ", 1, True, b"\x03AB"),
        (b"\x02\x00ABZ", 2, False, b"\x02\x00AB"),
        (b"\x04\x00ABZ", 2, True, b"\x04\x00AB"),
        (b"\x00Z", 1, False, b"\x00"),
    ],
)
def test_length_prefix_forms(
    data: bytes,
    prefix_size: int,
    includes_self: bool,
    expected: bytes,
) -> None:
    result = decode_c64_bytes(
        data,
        options(
            mode=LengthMode.PREFIX,
            length=None,
            prefix_size=prefix_size,
            prefix_includes_self=includes_self,
        ),
    )

    assert result.consumed == expected
    expected_text = "AB" if len(expected) > prefix_size else ""
    assert result.plain_text == expected_text
    assert all(
        not record.included_in_text
        for record in result.records[:prefix_size]
    )


def test_declared_prefix_beyond_source_is_an_error() -> None:
    with pytest.raises(RequestError, match="declares 6 bytes"):
        decode_c64_bytes(
            b"\x05AB",
            options(
                mode=LengthMode.PREFIX,
                length=None,
                prefix_size=1,
            ),
        )


def test_self_inclusive_prefix_cannot_be_smaller_than_prefix() -> None:
    with pytest.raises(RequestError, match="smaller than prefix size"):
        decode_c64_bytes(
            b"\x01\x00",
            options(
                mode=LengthMode.PREFIX,
                length=None,
                prefix_size=2,
                prefix_includes_self=True,
            ),
        )


def test_fixed_length_is_positive_and_exact() -> None:
    with pytest.raises(RequestError, match="positive"):
        decode_c64_bytes(b"A", options(length=0))
    with pytest.raises(RequestError, match="exceeds source boundary"):
        decode_c64_bytes(b"A", options(length=2))


def test_high_bit_modes_preserve_original_byte() -> None:
    stripped = decode_c64_bytes(
        b"\xc1",
        options(high_bit=HighBitMode.STRIP),
    )
    annotated = decode_c64_bytes(
        b"\x81",
        options(
            encoding=Encoding.SCREEN_CODE_UPPER,
            high_bit=HighBitMode.ANNOTATE_REVERSE,
        ),
    )

    assert stripped.records[0].original_byte == 0xC1
    assert stripped.records[0].selected_byte == 0x41
    assert stripped.plain_text == "A"
    assert annotated.records[0].selected_byte == 0x01
    assert annotated.records[0].reverse_video is True
    assert "REV" in annotated.lossless


def test_annotate_reverse_is_rejected_for_petscii() -> None:
    with pytest.raises(RequestError, match="screen-code"):
        decode_c64_bytes(
            b"A",
            options(high_bit=HighBitMode.ANNOTATE_REVERSE),
        )


def test_control_rendering_modes() -> None:
    named = decode_c64_bytes(
        b"\x93",
        options(controls=ControlMode.NAMES),
    )
    escaped = decode_c64_bytes(
        b"\x93",
        options(controls=ControlMode.ESCAPED),
    )
    unicode_fallback = decode_c64_bytes(
        b"\x93",
        options(controls=ControlMode.UNICODE),
    )

    assert named.plain_text == "{CLR}"
    assert escaped.plain_text == r"\x93"
    assert unicode_fallback.plain_text == "{CLR}"


def test_single_pass_and_recursive_tokens() -> None:
    single = decode_c64_bytes(
        b"\x80",
        options(
            tokens=TokenOptions(
                replacements={0x80: "GO {81}", 0x81: "NORTH"},
            )
        ),
    )
    recursive = decode_c64_bytes(
        b"\x80",
        options(
            tokens=TokenOptions(
                replacements={0x80: "GO {81}", 0x81: "NORTH"},
                recursive=True,
                recursion_limit=4,
            )
        ),
    )

    assert single.plain_text == "GO {81}"
    assert recursive.plain_text == "GO NORTH"


def test_recursive_tokens_detect_cycles() -> None:
    with pytest.raises(TokenCycleError, match="0x80"):
        decode_c64_bytes(
            b"\x80",
            options(
                tokens=TokenOptions(
                    replacements={0x80: "{81}", 0x81: "{80}"},
                    recursive=True,
                    recursion_limit=8,
                )
            ),
        )


def test_unknown_token_reference_does_not_consume_recursion_depth() -> None:
    result = decode_c64_bytes(
        b"\x80",
        options(
            tokens=TokenOptions(
                replacements={0x80: "{81}", 0x81: "{FF}"},
                recursive=True,
                recursion_limit=1,
            )
        ),
    )

    assert result.plain_text == "{FF}"


def test_recursive_tokens_enforce_depth_and_aggregate_caps() -> None:
    with pytest.raises(TextLimitError, match="recursion limit"):
        decode_c64_bytes(
            b"\x80",
            options(
                tokens=TokenOptions(
                    replacements={
                        0x80: "{81}",
                        0x81: "{82}",
                        0x82: "done",
                    },
                    recursive=True,
                    recursion_limit=1,
                )
            ),
        )
    with pytest.raises(TextLimitError, match="rendered output"):
        decode_c64_bytes(
            b"\x80",
            options(
                tokens=TokenOptions(
                    replacements={0x80: "X" * 4_194_305},
                )
            ),
        )


def test_aggregate_cap_is_checked_before_joining_all_fragments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ghidra_mcp_c64.text.codec.MAX_RENDERED_CHARS", 20
    )

    with pytest.raises(TextLimitError, match="rendered output"):
        decode_c64_bytes(
            b"\x80\x80\x80",
            options(
                length=3,
                tokens=TokenOptions(replacements={0x80: "123456"}),
            ),
        )


def test_decode_rejects_more_than_one_mebibyte() -> None:
    with pytest.raises(TextLimitError, match="1048576"):
        decode_c64_bytes(
            b"A" * 1_048_577,
            options(length=1_048_577),
        )
