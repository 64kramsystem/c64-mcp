"""Pure bounded PETSCII and C64 screen-code decoding."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..errors import RequestError, TextLimitError, TokenCycleError
from .tables import Codepoint, Encoding, table_for

MAX_INPUT_BYTES = 1_048_576
MAX_RENDERED_CHARS = 4_194_304
_TOKEN_REFERENCE = re.compile(r"\{([0-9a-fA-F]{2})\}")


class LengthMode(str, Enum):
    """How the codec selects bytes from its bounded source."""

    FIXED = "length"
    TERMINATOR = "terminator"
    PREFIX = "length_prefix"


class HighBitMode(str, Enum):
    """How a source byte's high bit affects table lookup."""

    EXACT = "exact"
    STRIP = "strip"
    ANNOTATE_REVERSE = "annotate_reverse"


class ControlMode(str, Enum):
    """How non-printable bytes appear in plain text."""

    NAMES = "names"
    ESCAPED = "escaped"
    UNICODE = "unicode"


@dataclass(frozen=True, slots=True)
class TokenOptions:
    """Caller-owned token replacements and recursive-expansion policy."""

    replacements: dict[int, str] = field(default_factory=dict)
    recursive: bool = False
    recursion_limit: int = 8


@dataclass(frozen=True, slots=True)
class DecodeOptions:
    """Complete options for one pure decode."""

    encoding: Encoding = Encoding.PETSCII_UPPER
    mode: LengthMode = LengthMode.FIXED
    length: int | None = None
    terminator: int | None = None
    prefix_size: int | None = None
    prefix_includes_self: bool = False
    high_bit: HighBitMode = HighBitMode.EXACT
    controls: ControlMode = ControlMode.NAMES
    tokens: TokenOptions = field(default_factory=TokenOptions)


@dataclass(frozen=True, slots=True)
class DecodedByte:
    """Decoded record that always retains the original source byte."""

    offset: int
    original_byte: int
    selected_byte: int
    glyph: str | None
    name: str
    printable: bool
    reverse_video: bool
    included_in_text: bool
    token_expanded: bool
    plain_fragment: str
    lossless_fragment: str

    def as_dict(self) -> dict[str, object]:
        return {
            "offset": self.offset,
            "original_byte": self.original_byte,
            "selected_byte": self.selected_byte,
            "glyph": self.glyph,
            "name": self.name,
            "printable": self.printable,
            "reverse_video": self.reverse_video,
            "included_in_text": self.included_in_text,
            "token_expanded": self.token_expanded,
            "plain_fragment": self.plain_fragment,
            "lossless_fragment": self.lossless_fragment,
        }


@dataclass(frozen=True, slots=True)
class DecodeResult:
    """Lossless decode output for one bounded source.

    ``lossless`` renders payload bytes only. ``consumed`` and ``records``
    retain framing prefixes and terminators.
    """

    consumed: bytes
    plain_text: str
    lossless: str
    records: tuple[DecodedByte, ...]
    terminated: bool
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "consumed_bytes": list(self.consumed),
            "consumed_hex": self.consumed.hex(),
            "consumed_length": len(self.consumed),
            "plain_text": self.plain_text,
            "lossless": self.lossless,
            "records": [record.as_dict() for record in self.records],
            "terminated": self.terminated,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class _Selection:
    consumed: bytes
    text_start: int
    text_end: int
    terminated: bool
    warnings: tuple[str, ...]


def decode_c64_bytes(data: bytes, options: DecodeOptions) -> DecodeResult:
    """Decode a bounded byte source without I/O or mutation."""

    if not isinstance(data, bytes):
        raise RequestError("data must be bytes")
    if len(data) > MAX_INPUT_BYTES:
        raise TextLimitError(
            f"input exceeds the {MAX_INPUT_BYTES}-byte hard maximum"
        )
    validate_decode_options(options)
    selection = select_consumed(data, options)
    records: list[DecodedByte] = []
    plain_parts: list[str] = []
    lossless_parts: list[str] = []
    rendered_chars = 0
    for offset, value in enumerate(selection.consumed):
        record = _decode_record(
            offset,
            value,
            selection.text_start <= offset < selection.text_end,
            options,
        )
        records.append(record)
        if not record.included_in_text:
            continue
        rendered_chars += len(record.plain_fragment)
        rendered_chars += len(record.lossless_fragment)
        if rendered_chars > MAX_RENDERED_CHARS:
            raise TextLimitError(
                f"rendered output exceeds {MAX_RENDERED_CHARS} characters"
            )
        plain_parts.append(record.plain_fragment)
        lossless_parts.append(record.lossless_fragment)
    plain_text = "".join(plain_parts)
    lossless = "".join(lossless_parts)
    return DecodeResult(
        consumed=selection.consumed,
        plain_text=plain_text,
        lossless=lossless,
        records=tuple(records),
        terminated=selection.terminated,
        warnings=selection.warnings,
    )


def select_consumed(data: bytes, options: DecodeOptions) -> _Selection:
    """Select complete consumed and textual ranges from the source."""

    if options.mode is LengthMode.FIXED:
        length = _plain_int(options.length, "length")
        if length <= 0:
            raise RequestError("fixed length must be positive")
        if length > len(data):
            raise RequestError(
                f"fixed length {length} exceeds source boundary {len(data)}"
            )
        return _Selection(data[:length], 0, length, False, ())

    if options.mode is LengthMode.TERMINATOR:
        terminator = _byte_value(options.terminator, "terminator")
        index = data.find(bytes([terminator]))
        if index < 0:
            return _Selection(
                data,
                0,
                len(data),
                False,
                (f"terminator 0x{terminator:02x} was not found",),
            )
        return _Selection(data[: index + 1], 0, index, True, ())

    prefix_size = _plain_int(options.prefix_size, "prefix_size")
    if prefix_size not in {1, 2}:
        raise RequestError("prefix_size must be 1 or 2")
    if len(data) < prefix_size:
        raise RequestError(
            f"source boundary {len(data)} is shorter than prefix size "
            f"{prefix_size}"
        )
    declared = int.from_bytes(data[:prefix_size], "little")
    if options.prefix_includes_self:
        if declared < prefix_size:
            raise RequestError(
                f"declared length {declared} is smaller than prefix size "
                f"{prefix_size}"
            )
        total = declared
    else:
        total = prefix_size + declared
    if total > len(data):
        raise RequestError(
            f"length prefix declares {total} bytes beyond source boundary "
            f"{len(data)}"
        )
    return _Selection(
        data[:total],
        prefix_size,
        total,
        False,
        (),
    )


def render_byte_fragment(
    value: int,
    options: DecodeOptions,
) -> tuple[str, str]:
    """Render one textual byte for bounded search indexing."""

    _validate_options(options, validate_length=False)
    record = _decode_record(0, _byte_value(value, "byte"), True, options)
    _enforce_rendered_limit(
        record.plain_fragment,
        record.lossless_fragment,
    )
    return record.plain_fragment, record.lossless_fragment


def validate_decode_options(options: DecodeOptions) -> None:
    """Validate an entire request before external I/O."""

    _validate_options(options)


def _decode_record(
    offset: int,
    original: int,
    included: bool,
    options: DecodeOptions,
) -> DecodedByte:
    selected, codepoint, reverse_video = _lookup(original, options)
    token = options.tokens.replacements.get(original) if included else None
    if token is not None:
        plain = _expand_token(original, options.tokens)
    else:
        plain = _plain_fragment(original, codepoint, options.controls)
    lossless = _lossless_fragment(original, codepoint, reverse_video)
    return DecodedByte(
        offset=offset,
        original_byte=original,
        selected_byte=selected,
        glyph=codepoint.glyph,
        name=codepoint.name,
        printable=codepoint.printable,
        reverse_video=reverse_video,
        included_in_text=included,
        token_expanded=token is not None,
        plain_fragment=plain,
        lossless_fragment=lossless,
    )


def _lookup(
    original: int,
    options: DecodeOptions,
) -> tuple[int, Codepoint, bool]:
    if options.high_bit is HighBitMode.EXACT:
        selected = original
        codepoint = table_for(options.encoding)[selected]
        return selected, codepoint, codepoint.reverse_video
    selected = original & 0x7F
    codepoint = table_for(options.encoding)[selected]
    if options.high_bit is HighBitMode.ANNOTATE_REVERSE:
        return selected, codepoint, bool(original & 0x80)
    return selected, codepoint, codepoint.reverse_video


def _plain_fragment(
    original: int,
    codepoint: Codepoint,
    controls: ControlMode,
) -> str:
    # Fallback priority is unambiguous glyph, stable brace name, then a hex
    # escape when the caller explicitly requests escaped controls.
    if codepoint.printable and codepoint.glyph is not None:
        return codepoint.glyph
    if codepoint.printable:
        return f"{{{codepoint.name}}}"
    if controls is ControlMode.ESCAPED:
        return f"\\x{original:02x}"
    if controls is ControlMode.UNICODE and codepoint.glyph is not None:
        return codepoint.glyph
    return f"{{{codepoint.name}}}"


def _lossless_fragment(
    original: int,
    codepoint: Codepoint,
    reverse_video: bool,
) -> str:
    label = (
        codepoint.glyph
        if codepoint.printable and codepoint.glyph is not None
        else codepoint.name
    )
    prefix = "REV " if reverse_video else ""
    return f"{{{prefix}{label}:${original:02X}}}"


def _expand_token(value: int, options: TokenOptions) -> str:
    replacement = options.replacements[value]
    if not options.recursive:
        return replacement

    def expand(current: int, stack: tuple[int, ...], depth: int) -> str:
        if current in stack:
            cycle = " -> ".join(
                f"0x{item:02x}" for item in (*stack, current)
            )
            raise TokenCycleError(f"recursive token cycle: {cycle}")
        text = options.replacements[current]
        if not _TOKEN_REFERENCE.search(text):
            return text

        parts: list[str] = []
        rendered = 0
        cursor = 0
        for match in _TOKEN_REFERENCE.finditer(text):
            literal = text[cursor : match.start()]
            rendered += len(literal)
            if rendered > MAX_RENDERED_CHARS:
                raise TextLimitError(
                    f"rendered output exceeds "
                    f"{MAX_RENDERED_CHARS} characters"
                )
            parts.append(literal)
            target = int(match.group(1), 16)
            if target not in options.replacements:
                replacement = match.group(0)
            else:
                if depth >= options.recursion_limit:
                    raise TextLimitError(
                        f"token recursion limit "
                        f"{options.recursion_limit} exceeded"
                    )
                replacement = expand(
                    target,
                    (*stack, current),
                    depth + 1,
                )
            rendered += len(replacement)
            if rendered > MAX_RENDERED_CHARS:
                raise TextLimitError(
                    f"rendered output exceeds "
                    f"{MAX_RENDERED_CHARS} characters"
                )
            parts.append(replacement)
            cursor = match.end()
        suffix = text[cursor:]
        rendered += len(suffix)
        if rendered > MAX_RENDERED_CHARS:
            raise TextLimitError(
                f"rendered output exceeds {MAX_RENDERED_CHARS} characters"
            )
        parts.append(suffix)
        return "".join(parts)

    return expand(value, (), 0)


def _validate_options(
    options: DecodeOptions,
    *,
    validate_length: bool = True,
) -> None:
    if not isinstance(options, DecodeOptions):
        raise RequestError("options must be DecodeOptions")
    if not isinstance(options.encoding, Encoding):
        raise RequestError("encoding is invalid")
    if not isinstance(options.mode, LengthMode):
        raise RequestError("length mode is invalid")
    if not isinstance(options.high_bit, HighBitMode):
        raise RequestError("high_bit is invalid")
    if not isinstance(options.controls, ControlMode):
        raise RequestError("controls is invalid")
    if (
        options.high_bit is HighBitMode.ANNOTATE_REVERSE
        and not options.encoding.is_screen_code
    ):
        raise RequestError(
            "annotate_reverse is valid only for screen-code encodings"
        )
    if not isinstance(options.prefix_includes_self, bool):
        raise RequestError("prefix_includes_self must be a boolean")
    _validate_tokens(options.tokens)
    if validate_length:
        if options.mode is LengthMode.FIXED:
            length = _plain_int(options.length, "length")
            if length <= 0:
                raise RequestError("fixed length must be positive")
            if length > MAX_INPUT_BYTES:
                raise RequestError(
                    f"fixed length must not exceed {MAX_INPUT_BYTES}"
                )
        elif options.mode is LengthMode.TERMINATOR:
            _byte_value(options.terminator, "terminator")
        else:
            prefix_size = _plain_int(
                options.prefix_size, "prefix_size"
            )
            if prefix_size not in {1, 2}:
                raise RequestError("prefix_size must be 1 or 2")


def _validate_tokens(options: TokenOptions) -> None:
    if not isinstance(options, TokenOptions):
        raise RequestError("tokens must be TokenOptions")
    if not isinstance(options.recursive, bool):
        raise RequestError("recursive must be a boolean")
    limit = _plain_int(options.recursion_limit, "recursion_limit")
    if limit <= 0 or limit > 256:
        raise RequestError("recursion_limit must be from 1 to 256")
    total = 0
    for key, value in options.replacements.items():
        _byte_value(key, "token byte")
        if not isinstance(value, str):
            raise RequestError("token replacements must be strings")
        total += len(value)
        if total > MAX_RENDERED_CHARS:
            raise TextLimitError(
                f"rendered output exceeds {MAX_RENDERED_CHARS} characters"
            )


def _plain_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise RequestError(f"{name} must be an integer")
    return value


def _byte_value(value: Any, name: str) -> int:
    converted = _plain_int(value, name)
    if converted < 0 or converted > 255:
        raise RequestError(f"{name} must be from 0 to 255")
    return converted


def _enforce_rendered_limit(*values: str) -> None:
    if sum(len(value) for value in values) > MAX_RENDERED_CHARS:
        raise TextLimitError(
            f"rendered output exceeds {MAX_RENDERED_CHARS} characters"
        )
