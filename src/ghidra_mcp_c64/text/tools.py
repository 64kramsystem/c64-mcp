"""C64 text decode, search, and atomic definition operations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, TypeVar

from ..errors import RequestError, TextLimitError
from .codec import (
    MAX_INPUT_BYTES,
    MAX_RENDERED_CHARS,
    ControlMode,
    DecodeOptions,
    HighBitMode,
    LengthMode,
    TokenOptions,
    decode_c64_bytes,
    render_byte_fragment,
    validate_decode_options,
)
from .tables import Encoding

DEFAULT_MAX_SCAN_BYTES = 65_536
MAX_SCAN_BYTES = 1_048_576
DEFAULT_MAX_RESULTS = 100
MAX_RESULTS = 1_000
EnumValue = TypeVar(
    "EnumValue",
    Encoding,
    HighBitMode,
    ControlMode,
)
_HEX = re.compile(r"^[0-9a-fA-F]*$")
_DECIMAL_TOKEN = re.compile(r"^(0|[1-9][0-9]*)$")
_HEX_TOKEN = re.compile(r"^0x[0-9a-fA-F]{1,2}$")
_ADDRESS_HEX = re.compile(r"^[0-9a-fA-F]+$")

BytesInput = str | list[int]


class TextGhidraClient(Protocol):
    """Public Ghidra calls required by the C64 text subsystem."""

    def read_bytes(self, program: str, start: str, length: int) -> bytes:
        """Read exactly length mapped bytes."""

    def apply_data_regions(
        self,
        program: str,
        regions: list[dict[str, object]],
        *,
        dry_run: bool = True,
    ) -> dict[str, object]:
        """Apply one atomic batch of flat data regions."""


@dataclass(frozen=True, slots=True)
class _Address:
    space_prefix: str
    number_prefix: str
    value: int
    width: int

    def plus(self, offset: int) -> str:
        return (
            f"{self.space_prefix}{self.number_prefix}"
            f"{self.value + offset:0{self.width}x}"
        )


@dataclass(frozen=True, slots=True)
class _Candidate:
    consumed_end: int
    text_start: int
    text_end: int
    terminated: bool


def decode_c64_text(
    ghidra: TextGhidraClient,
    *,
    bytes: BytesInput | None = None,
    program: str | None = None,
    start: str | None = None,
    max_length: int | None = None,
    encoding: str = "petscii_upper",
    length: int | None = None,
    terminator: int | None = None,
    prefix_size: int | None = None,
    prefix_includes_self: bool = False,
    high_bit: str = "exact",
    controls: str = "names",
    tokens: dict[str, str] | None = None,
    recursive_tokens: bool = False,
    token_recursion_limit: int = 8,
) -> dict[str, object]:
    """Decode exactly one inline or named-program byte source."""

    options = _decode_options(
        encoding=encoding,
        length=length,
        terminator=terminator,
        prefix_size=prefix_size,
        prefix_includes_self=prefix_includes_self,
        high_bit=high_bit,
        controls=controls,
        tokens=tokens,
        recursive_tokens=recursive_tokens,
        token_recursion_limit=token_recursion_limit,
    )
    validate_decode_options(options)
    inline = bytes is not None
    remote_fields = (program, start, max_length)
    remote = any(value is not None for value in remote_fields)
    if inline == remote:
        raise RequestError(
            "exactly one byte source is required: inline bytes or "
            "program + start + max_length"
        )
    if inline:
        if any(value is not None for value in remote_fields):
            raise RequestError(
                "exactly one byte source is required: inline bytes or "
                "program + start + max_length"
            )
        data = _parse_bytes_input(bytes, "bytes")
        source: dict[str, object] = {"kind": "inline"}
    else:
        if (
            not isinstance(program, str)
            or not program.strip()
            or not isinstance(start, str)
            or not start
            or max_length is None
        ):
            raise RequestError(
                "program, start, and max_length are required for a "
                "Ghidra byte source"
            )
        read_length = _bounded_positive(
            max_length, "max_length", MAX_INPUT_BYTES
        )
        data = ghidra.read_bytes(program, start, read_length)
        source = {
            "kind": "ghidra",
            "program": program,
            "start": start,
            "max_length": read_length,
        }
    result = decode_c64_bytes(data, options).as_dict()
    result["source"] = source
    result["configuration"] = _configuration(options)
    return result


def search_c64_text(
    ghidra: TextGhidraClient,
    *,
    program: str,
    start: str,
    end: str,
    query: str | list[int],
    query_mode: str = "text",
    encoding: str = "petscii_upper",
    length: int | None = None,
    terminator: int | None = None,
    prefix_size: int | None = None,
    prefix_includes_self: bool = False,
    high_bit: str = "exact",
    controls: str = "names",
    tokens: dict[str, str] | None = None,
    recursive_tokens: bool = False,
    token_recursion_limit: int = 8,
    stride: int = 1,
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    max_results: int = DEFAULT_MAX_RESULTS,
) -> dict[str, object]:
    """Search a bounded inclusive program range by raw bytes or decoded text."""

    _require_program(program)
    needle: bytes | None = None
    text_query: str | None = None
    if query_mode == "bytes":
        needle = _parse_bytes_input(query, "byte query")
        if not needle:
            raise RequestError("byte query must not be empty")
        options = _byte_search_options(
            encoding=encoding,
            length=len(needle),
            high_bit=high_bit,
            controls=controls,
            tokens=tokens,
            recursive_tokens=recursive_tokens,
            token_recursion_limit=token_recursion_limit,
        )
        validate_decode_options(options)
    elif query_mode == "text":
        if not isinstance(query, str) or not query:
            raise RequestError("text query must be a non-empty string")
        text_query = query
        options = _decode_options(
            encoding=encoding,
            length=length,
            terminator=terminator,
            prefix_size=prefix_size,
            prefix_includes_self=prefix_includes_self,
            high_bit=high_bit,
            controls=controls,
            tokens=tokens,
            recursive_tokens=recursive_tokens,
            token_recursion_limit=token_recursion_limit,
        )
        validate_decode_options(options)
    else:
        raise RequestError("query_mode must be 'text' or 'bytes'")

    first = _parse_address(start, "start")
    last = _parse_address(end, "end")
    if first.space_prefix != last.space_prefix:
        raise RequestError("start and end must use the same address space")
    if last.value < first.value:
        raise RequestError("end must not be before start")
    step = _bounded_positive(stride, "stride", MAX_SCAN_BYTES)
    scan_cap = _bounded_positive(
        max_scan_bytes, "max_scan_bytes", MAX_SCAN_BYTES
    )
    result_cap = _bounded_positive(
        max_results, "max_results", MAX_RESULTS
    )
    available = last.value - first.value + 1
    scan_length = min(available, scan_cap)
    data = ghidra.read_bytes(program, start, scan_length)
    truncated_scan = scan_length < available
    warnings: list[str] = []
    if truncated_scan:
        warnings.append(
            f"scan truncated to max_scan_bytes={scan_cap}"
        )

    if needle is not None:
        matches, limit_reached = _search_bytes(
            data,
            needle,
            step,
            result_cap,
            first,
            options,
        )
        configuration = {
            **_configuration(options),
            "query_mode": "bytes",
            "stride": step,
        }
        invalid_candidates = 0
    else:
        assert text_query is not None
        matches, invalid_candidates, limit_reached = _search_text(
            data,
            text_query,
            step,
            result_cap,
            first,
            options,
        )
        configuration = {
            **_configuration(options),
            "query_mode": "text",
            "stride": step,
        }
        if invalid_candidates:
            warnings.append(
                f"{invalid_candidates} invalid length-mode candidates "
                "were skipped"
            )

    return {
        "program": program,
        "start": start,
        "requested_end": end,
        "scanned_end": first.plus(scan_length - 1),
        "scanned_bytes": scan_length,
        "truncated_scan": truncated_scan,
        "matches": matches,
        "max_results": result_cap,
        "result_limit_reached": limit_reached,
        "invalid_candidates": invalid_candidates,
        "configuration": configuration,
        "warnings": warnings,
    }


def define_c64_text(
    ghidra: TextGhidraClient,
    *,
    program: str,
    start: str,
    max_length: int | None = None,
    encoding: str = "petscii_upper",
    length: int | None = None,
    terminator: int | None = None,
    prefix_size: int | None = None,
    prefix_includes_self: bool = False,
    high_bit: str = "exact",
    controls: str = "names",
    tokens: dict[str, str] | None = None,
    recursive_tokens: bool = False,
    token_recursion_limit: int = 8,
    label: str | None = None,
    namespace: str | None = None,
    comment: str | None = None,
    dry_run: bool = True,
) -> dict[str, object]:
    """Decode first, then atomically type and annotate the exact byte range."""

    _require_program(program)
    _parse_address(start, "start")
    if not isinstance(dry_run, bool):
        raise RequestError("dry_run must be a boolean")
    if max_length is None:
        if length is None:
            raise RequestError(
                "max_length is required for terminated or prefixed text"
            )
        read_length = _bounded_positive(
            length, "length", MAX_INPUT_BYTES
        )
    else:
        read_length = _bounded_positive(
            max_length, "max_length", MAX_INPUT_BYTES
        )
    decoded = decode_c64_text(
        ghidra,
        program=program,
        start=start,
        max_length=read_length,
        encoding=encoding,
        length=length,
        terminator=terminator,
        prefix_size=prefix_size,
        prefix_includes_self=prefix_includes_self,
        high_bit=high_bit,
        controls=controls,
        tokens=tokens,
        recursive_tokens=recursive_tokens,
        token_recursion_limit=token_recursion_limit,
    )
    consumed = decoded["consumed_length"]
    if (
        not isinstance(consumed, int)
        or isinstance(consumed, bool)
        or consumed <= 0
    ):
        raise RequestError("zero-byte C64 text definitions are not allowed")
    first = _parse_address(start, "start")
    plate = f"C64 {encoding}: {decoded['lossless']}"
    if comment is not None:
        if not isinstance(comment, str):
            raise RequestError("comment must be a string")
        plate = f"{comment}\n{plate}"
    region: dict[str, object] = {
        "kind": "contiguous",
        "start": start,
        "end": first.plus(consumed - 1),
        "type_name": "byte",
        "clear_conflicts": False,
        "plate_comment": plate,
    }
    if label is not None:
        _nonblank_optional(label, "label")
        region["name"] = label
    if namespace is not None:
        _nonblank_optional(namespace, "namespace")
        region["namespace"] = namespace
    upstream = ghidra.apply_data_regions(
        program,
        [region],
        dry_run=dry_run,
    )
    return {
        "program": program,
        "start": start,
        "end": region["end"],
        "dry_run": dry_run,
        "decoded": decoded,
        "ghidra": upstream,
    }


def _search_bytes(
    data: bytes,
    needle: bytes,
    stride: int,
    max_results: int,
    base: _Address,
    options: DecodeOptions,
) -> tuple[list[dict[str, object]], bool]:
    matches: list[dict[str, object]] = []
    last = len(data) - len(needle)
    decoded = decode_c64_bytes(needle, options).as_dict()
    for offset in range(0, max(last + 1, 0), stride):
        if data[offset : offset + len(needle)] != needle:
            continue
        matches.append(
            _match(base, offset, decoded, options)
        )
        if len(matches) >= max_results:
            return matches, True
    return matches, False


def _search_text(
    data: bytes,
    query: str,
    stride: int,
    max_results: int,
    base: _Address,
    options: DecodeOptions,
) -> tuple[list[dict[str, object]], int, bool]:
    fragments: list[str] = []
    fragment_cache: dict[int, str] = {}
    rendered_chars = 0
    for value in data:
        fragment = fragment_cache.get(value)
        if fragment is None:
            fragment = render_byte_fragment(value, options)[0]
            fragment_cache[value] = fragment
        rendered_chars += len(fragment)
        if rendered_chars > MAX_RENDERED_CHARS:
            raise TextLimitError(
                f"rendered output exceeds "
                f"{MAX_RENDERED_CHARS} characters"
            )
        fragments.append(fragment)
    offsets = [0]
    for fragment in fragments:
        offsets.append(offsets[-1] + len(fragment))
    joined = "".join(fragments)
    next_terminator = _next_occurrences(data, options.terminator)
    matches: list[dict[str, object]] = []
    invalid = 0
    for candidate_start in range(0, len(data), stride):
        candidate = _candidate(
            data,
            candidate_start,
            options,
            next_terminator,
        )
        if candidate is None:
            invalid += 1
            continue
        char_start = offsets[candidate.text_start]
        char_end = offsets[candidate.text_end]
        if char_end - char_start != len(query):
            continue
        if joined[char_start:char_end] != query:
            continue
        raw = data[candidate_start : candidate.consumed_end]
        decoded = decode_c64_bytes(raw, options)
        matches.append(
            _match(base, candidate_start, decoded.as_dict(), options)
        )
        if len(matches) >= max_results:
            return matches, invalid, True
    return matches, invalid, False


def _candidate(
    data: bytes,
    start: int,
    options: DecodeOptions,
    next_terminator: list[int] | None,
) -> _Candidate | None:
    if options.mode is LengthMode.FIXED:
        assert options.length is not None
        end = start + options.length
        if end > len(data):
            return None
        return _Candidate(end, start, end, False)
    if options.mode is LengthMode.TERMINATOR:
        assert next_terminator is not None
        terminator_at = next_terminator[start]
        if terminator_at < 0:
            return _Candidate(len(data), start, len(data), False)
        return _Candidate(
            terminator_at + 1,
            start,
            terminator_at,
            True,
        )
    assert options.prefix_size is not None
    prefix_end = start + options.prefix_size
    if prefix_end > len(data):
        return None
    declared = int.from_bytes(data[start:prefix_end], "little")
    if options.prefix_includes_self:
        if declared < options.prefix_size:
            return None
        total = declared
    else:
        total = options.prefix_size + declared
    consumed_end = start + total
    if consumed_end > len(data):
        return None
    return _Candidate(
        consumed_end,
        prefix_end,
        consumed_end,
        False,
    )


def _next_occurrences(
    data: bytes,
    terminator: int | None,
) -> list[int] | None:
    if terminator is None:
        return None
    result = [-1] * len(data)
    nearest = -1
    for index in range(len(data) - 1, -1, -1):
        if data[index] == terminator:
            nearest = index
        result[index] = nearest
    return result


def _match(
    base: _Address,
    offset: int,
    decoded: dict[str, object],
    options: DecodeOptions,
) -> dict[str, object]:
    return {
        "address": base.plus(offset),
        "byte_length": decoded["consumed_length"],
        "raw_bytes": decoded["consumed_bytes"],
        "raw_hex": decoded["consumed_hex"],
        "decoded_text": decoded["plain_text"],
        "lossless": decoded["lossless"],
        "terminated": decoded["terminated"],
        "warnings": decoded["warnings"],
        "configuration": _configuration(options),
    }


def _decode_options(
    *,
    encoding: str,
    length: int | None,
    terminator: int | None,
    prefix_size: int | None,
    prefix_includes_self: bool,
    high_bit: str,
    controls: str,
    tokens: dict[str, str] | None,
    recursive_tokens: bool,
    token_recursion_limit: int,
) -> DecodeOptions:
    modes = sum(
        value is not None for value in (length, terminator, prefix_size)
    )
    if modes != 1:
        raise RequestError(
            "exactly one length mode is required: length, terminator, "
            "or prefix_size"
        )
    if length is not None:
        mode = LengthMode.FIXED
    elif terminator is not None:
        mode = LengthMode.TERMINATOR
    else:
        mode = LengthMode.PREFIX
    return DecodeOptions(
        encoding=_enum(Encoding, encoding, "encoding"),
        mode=mode,
        length=length,
        terminator=terminator,
        prefix_size=prefix_size,
        prefix_includes_self=prefix_includes_self,
        high_bit=_enum(HighBitMode, high_bit, "high_bit"),
        controls=_enum(ControlMode, controls, "controls"),
        tokens=TokenOptions(
            replacements=_parse_tokens(tokens),
            recursive=recursive_tokens,
            recursion_limit=token_recursion_limit,
        ),
    )


def _byte_search_options(
    *,
    encoding: str,
    length: int,
    high_bit: str,
    controls: str,
    tokens: dict[str, str] | None,
    recursive_tokens: bool,
    token_recursion_limit: int,
) -> DecodeOptions:
    return DecodeOptions(
        encoding=_enum(Encoding, encoding, "encoding"),
        mode=LengthMode.FIXED,
        length=length,
        high_bit=_enum(HighBitMode, high_bit, "high_bit"),
        controls=_enum(ControlMode, controls, "controls"),
        tokens=TokenOptions(
            replacements=_parse_tokens(tokens),
            recursive=recursive_tokens,
            recursion_limit=token_recursion_limit,
        ),
    )


def _parse_tokens(tokens: dict[str, str] | None) -> dict[int, str]:
    if tokens is None:
        return {}
    if not isinstance(tokens, dict):
        raise RequestError("tokens must be an object")
    result: dict[int, str] = {}
    for raw_key, value in tokens.items():
        if not isinstance(raw_key, str):
            raise RequestError("token keys must be strings")
        if _DECIMAL_TOKEN.fullmatch(raw_key):
            key = int(raw_key, 10)
        elif _HEX_TOKEN.fullmatch(raw_key):
            key = int(raw_key, 16)
        else:
            raise RequestError(
                "token keys must be decimal bytes or 0x-prefixed hex"
            )
        if key > 255:
            raise RequestError("token keys must be from 0 to 255")
        if not isinstance(value, str):
            raise RequestError("token replacements must be strings")
        if key in result:
            raise RequestError(f"duplicate normalized token byte {key}")
        result[key] = value
    return result


def _parse_bytes_input(value: object, name: str) -> bytes:
    if isinstance(value, str):
        compact = "".join(value.split())
        if len(compact) % 2 or not _HEX.fullmatch(compact):
            raise RequestError(
                f"{name} must contain an even number of hexadecimal digits"
            )
        result = bytes.fromhex(compact)
    elif isinstance(value, list):
        converted = bytearray()
        for item in value:
            if (
                not isinstance(item, int)
                or isinstance(item, bool)
                or item < 0
                or item > 255
            ):
                raise RequestError(
                    f"{name} array values must be integers from 0 to 255"
                )
            converted.append(item)
        result = bytes(converted)
    else:
        raise RequestError(f"{name} must be hex text or a byte array")
    if len(result) > MAX_INPUT_BYTES:
        raise TextLimitError(
            f"{name} exceeds the {MAX_INPUT_BYTES}-byte hard maximum"
        )
    return result


def _parse_address(value: object, name: str) -> _Address:
    if not isinstance(value, str) or not value:
        raise RequestError(f"{name} must be a non-empty address")
    colon = value.rfind(":")
    if colon < 0:
        prefix = ""
        digits = value
    else:
        prefix = value[: colon + 1]
        digits = value[colon + 1 :]
    number_prefix = ""
    if digits.startswith(("0x", "0X")):
        number_prefix = digits[:2]
        digits = digits[2:]
    if not digits or not _ADDRESS_HEX.fullmatch(digits):
        raise RequestError(
            f"{name} must end in a hexadecimal offset"
        )
    return _Address(
        prefix,
        number_prefix,
        int(digits, 16),
        len(digits),
    )


def _configuration(options: DecodeOptions) -> dict[str, object]:
    return {
        "encoding": options.encoding.value,
        "length_mode": options.mode.value,
        "length": options.length,
        "terminator": options.terminator,
        "prefix_size": options.prefix_size,
        "prefix_includes_self": options.prefix_includes_self,
        "high_bit": options.high_bit.value,
        "controls": options.controls.value,
        "tokens": {
            str(key): value
            for key, value in sorted(options.tokens.replacements.items())
        },
        "recursive_tokens": options.tokens.recursive,
        "token_recursion_limit": options.tokens.recursion_limit,
    }


def _enum(
    enum_type: type[EnumValue],
    value: str,
    name: str,
) -> EnumValue:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        allowed = ", ".join(item.value for item in enum_type)
        raise RequestError(f"{name} must be one of: {allowed}") from None


def _bounded_positive(value: object, name: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise RequestError(f"{name} must be a positive integer")
    if value > maximum:
        raise RequestError(f"{name} must not exceed {maximum}")
    return value


def _require_program(program: object) -> None:
    if not isinstance(program, str) or not program.strip():
        raise RequestError("program must not be blank")


def _nonblank_optional(value: object, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RequestError(f"{name} must not be blank")
