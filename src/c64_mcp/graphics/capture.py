"""Turn one chunked live VICE frame into an indexed PNG.

The connector owns the emulator: it traps VICE into the monitor, reads the
composited display buffer and the palette that goes with it. Nothing is
rendered there, so everything below happens here — bounded retrieval, envelope
validation, cropping to the inner screen rectangle, and indexed-PNG encoding.

Two properties of the connector contract shape this module:

- The buffer is the **debug** frame, larger than the visible screen. It carries
  border and blanking around an inner rectangle whose offsets and size the
  connector reports; `crop=True` renders only that rectangle.
- The connector refuses a frame whose highest index its palette does not cover,
  so an unmapped index cannot reach this path. `PLTE` extension stays a concern
  of static decodes with a caller-supplied palette.

The result mirrors the decoders: one `ImageContent`, one textual JSON summary,
and `structuredContent` holding only that summary, so the ~140 KB of base64
never appears twice and never lands in structured output.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast

from mcp.types import CallToolResult, ImageContent, TextContent

from ..errors import RequestError, ViceError
from ..vice import MAX_DISPLAY_CAPTURE_CHUNK_BYTES
from .palette import MAX_PALETTE_ENTRIES, Rgb
from .png import encode_indexed_png
from .tools import output_target, write_atomically

CAPTURE_SUMMARY_FIELDS = (
    "mode",
    "width",
    "height",
    "cropped",
    "inner",
    "palette_size",
    "used_indices",
    "distinct_index_count",
    "output_path",
)
CAPTURE_MODE = "vice_capture"
BITS_PER_PIXEL = 8
DEFAULT_TIMEOUT_MS = 10_000
_INNER_FIELDS = ("x_offset", "y_offset", "width", "height")
_LOWER_HEX = re.compile(r"^[0-9a-f]*$")


class CaptureViceSession(Protocol):
    """The bounded connector calls a screen capture needs."""

    def capture_display(
        self,
        *,
        use_vic: bool = True,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        """Capture one composited frame and its palette."""

    def read_display_capture(
        self,
        *,
        capture_id: str,
        offset: int,
        max_bytes: int = MAX_DISPLAY_CAPTURE_CHUNK_BYTES,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        """Read one bounded part of an opaque display capture."""

    def discard_display_capture(
        self,
        *,
        capture_id: str,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        """Discard one opaque display capture."""


def vice_capture_screen(
    vice: CaptureViceSession,
    *,
    crop: bool = True,
    use_vic: bool = True,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    output_path: str | None = None,
    overwrite: bool = False,
) -> CallToolResult:
    """Capture the current VICE frame and return it as an indexed PNG.

    Requires a connector at surface revision 3 and, because capture traps the
    emulator into the monitor, a stopped target; the connector enforces both.
    """

    if not isinstance(crop, bool):
        raise RequestError("crop must be a boolean")
    if not isinstance(use_vic, bool):
        raise RequestError("use_vic must be a boolean")
    # Checked before the capture, so a doomed write costs no frame.
    target = output_target(output_path, overwrite)

    envelope = vice.capture_display(use_vic=use_vic, timeout_ms=timeout_ms)
    capture_id = _available_capture_id(envelope)
    if capture_id is None:
        capture_id = _metadata(envelope).capture_id
    primary: ViceError | None = None
    try:
        metadata = _metadata(envelope)
        frame = _frame(metadata, _read_buffer(vice, metadata, timeout_ms))
    except ViceError as error:
        primary = error
    try:
        _discard(vice, capture_id, timeout_ms)
    except ViceError as error:
        if primary is None:
            raise
        primary.details["discard_error"] = error.as_result()["error"]
    if primary is not None:
        raise primary

    rows: Sequence[Sequence[int]]
    if crop:
        rows = [
            frame.buffer[
                (frame.inner_y + row) * frame.width
                + frame.inner_x : (frame.inner_y + row) * frame.width
                + frame.inner_x
                + frame.inner_width
            ]
            for row in range(frame.inner_height)
        ]
    else:
        rows = [
            frame.buffer[row * frame.width : (row + 1) * frame.width]
            for row in range(frame.height)
        ]

    encoded = encode_indexed_png(rows, frame.palette)
    if target is not None:
        write_atomically(target, encoded.data, overwrite)
    summary: dict[str, Any] = {
        "mode": CAPTURE_MODE,
        "width": encoded.width,
        "height": encoded.height,
        "cropped": crop,
        "inner": {
            "x_offset": frame.inner_x,
            "y_offset": frame.inner_y,
            "width": frame.inner_width,
            "height": frame.inner_height,
        },
        "palette_size": encoded.palette_size,
        "used_indices": list(encoded.used_indices),
        "distinct_index_count": len(encoded.used_indices),
        "output_path": None if target is None else str(target),
    }
    return CallToolResult(
        content=[
            ImageContent(
                type="image",
                data=base64.b64encode(encoded.data).decode("ascii"),
                mimeType="image/png",
            ),
            TextContent(
                type="text",
                text=json.dumps(summary, indent=2, sort_keys=True),
            ),
        ],
        structuredContent=summary,
    )


@dataclass(frozen=True, slots=True)
class _Frame:
    """One validated capture envelope, ready to render."""

    width: int
    height: int
    inner_x: int
    inner_y: int
    inner_width: int
    inner_height: int
    buffer: bytes
    palette: list[Rgb]


@dataclass(frozen=True, slots=True)
class _Metadata:
    capture_id: str
    width: int
    height: int
    inner_x: int
    inner_y: int
    inner_width: int
    inner_height: int
    buffer_length: int
    buffer_sha256: str
    palette_records: object


def _available_capture_id(
    envelope: Mapping[str, object],
) -> str | None:
    result = envelope.get("result")
    if not isinstance(result, Mapping):
        return None
    capture_id = result.get("capture_id")
    return capture_id if isinstance(capture_id, str) and capture_id else None


def _metadata(envelope: Mapping[str, object]) -> _Metadata:
    """Validate capture metadata before requesting any buffer chunks."""

    if envelope.get("ok") is False:
        error = envelope.get("error")
        if isinstance(error, Mapping):
            raise ViceError.from_mapping(
                error,
                fallback_code="vice_capture_failed",
                fallback_message="the VICE display capture failed",
            )
        raise ViceError(
            "vice_capture_failed", "the VICE display capture failed"
        )
    result = envelope.get("result")
    if not isinstance(result, Mapping):
        raise _incompatible("the capture returned no result object")
    record = cast(Mapping[str, object], result)
    capture_id = record.get("capture_id")
    if not isinstance(capture_id, str) or not capture_id:
        raise _incompatible("capture_id must be a nonblank string")
    width = _positive(record.get("width"), "width")
    height = _positive(record.get("height"), "height")
    inner_x, inner_y, inner_width, inner_height = _inner(
        record.get("inner"), width, height
    )
    bits = record.get("bits_per_pixel")
    if bits != BITS_PER_PIXEL:
        raise _incompatible(
            f"bits_per_pixel is {bits!r}; only {BITS_PER_PIXEL} is "
            "renderable, one palette index per byte"
        )
    buffer_length = _nonnegative(record.get("buffer_length"), "buffer_length")
    if buffer_length != width * height:
        raise _incompatible(
            f"buffer_length {buffer_length} does not equal width * height "
            f"({width} * {height} = {width * height})"
        )
    buffer_sha256 = record.get("buffer_sha256")
    if (
        not isinstance(buffer_sha256, str)
        or len(buffer_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in buffer_sha256
        )
    ):
        raise _incompatible(
            "buffer_sha256 must be a lowercase SHA-256 digest"
        )
    return _Metadata(
        capture_id=capture_id,
        width=width,
        height=height,
        inner_x=inner_x,
        inner_y=inner_y,
        inner_width=inner_width,
        inner_height=inner_height,
        buffer_length=buffer_length,
        buffer_sha256=buffer_sha256,
        palette_records=record.get("palette"),
    )


def _read_buffer(
    vice: CaptureViceSession,
    metadata: _Metadata,
    timeout_ms: int,
) -> bytes:
    parts: list[bytes] = []
    offset = 0
    while offset < metadata.buffer_length:
        requested = min(
            MAX_DISPLAY_CAPTURE_CHUNK_BYTES,
            metadata.buffer_length - offset,
        )
        envelope = vice.read_display_capture(
            capture_id=metadata.capture_id,
            offset=offset,
            max_bytes=requested,
            timeout_ms=timeout_ms,
        )
        result = _success_result(envelope, "display capture read")
        raw = result.get("bytes")
        byte_count = result.get("byte_count")
        if (
            result.get("capture_id") != metadata.capture_id
            or result.get("offset") != offset
            or result.get("buffer_length") != metadata.buffer_length
            or result.get("buffer_sha256") != metadata.buffer_sha256
            or not isinstance(byte_count, int)
            or isinstance(byte_count, bool)
            or not 1 <= byte_count <= requested
            or not isinstance(raw, str)
            or len(raw) != byte_count * 2
            or _LOWER_HEX.fullmatch(raw) is None
        ):
            raise _incompatible(
                f"display capture chunk at offset {offset} is inconsistent"
            )
        expected_next = offset + byte_count
        complete = result.get("complete")
        next_offset = result.get("next_offset")
        if (
            not isinstance(complete, bool)
            or (
                complete is True
                and (
                    expected_next != metadata.buffer_length
                    or next_offset is not None
                )
            )
            or (
                complete is False
                and (
                    expected_next >= metadata.buffer_length
                    or next_offset != expected_next
                )
            )
        ):
            raise _incompatible(
                f"display capture continuation at offset {offset} is "
                "inconsistent"
            )
        parts.append(bytes.fromhex(raw))
        offset = expected_next
    buffer = b"".join(parts)
    if hashlib.sha256(buffer).hexdigest() != metadata.buffer_sha256:
        raise _incompatible(
            "assembled display buffer does not match buffer_sha256"
        )
    return buffer


def _discard(
    vice: CaptureViceSession,
    capture_id: str,
    timeout_ms: int,
) -> None:
    result = _success_result(
        vice.discard_display_capture(
            capture_id=capture_id, timeout_ms=timeout_ms
        ),
        "display capture discard",
    )
    if (
        result.get("capture_id") != capture_id
        or result.get("discarded") is not True
    ):
        raise _incompatible("display capture discard result is inconsistent")


def _frame(metadata: _Metadata, buffer: bytes) -> _Frame:
    palette = _palette(metadata.palette_records, buffer)
    return _Frame(
        width=metadata.width,
        height=metadata.height,
        inner_x=metadata.inner_x,
        inner_y=metadata.inner_y,
        inner_width=metadata.inner_width,
        inner_height=metadata.inner_height,
        buffer=buffer,
        palette=palette,
    )


def _success_result(
    envelope: Mapping[str, object], operation: str
) -> Mapping[str, object]:
    if envelope.get("ok") is False:
        error = envelope.get("error")
        if isinstance(error, Mapping):
            raise ViceError.from_mapping(
                error,
                fallback_code="vice_capture_failed",
                fallback_message=f"the VICE {operation} failed",
            )
        raise ViceError(
            "vice_capture_failed", f"the VICE {operation} failed"
        )
    result = envelope.get("result")
    if not isinstance(result, Mapping):
        raise _incompatible(f"the {operation} returned no result object")
    return cast(Mapping[str, object], result)


def _inner(
    value: object, width: int, height: int
) -> tuple[int, int, int, int]:
    if not isinstance(value, Mapping):
        raise _incompatible("inner must be an object")
    numbers: list[int] = []
    for field in _INNER_FIELDS:
        numbers.append(_nonnegative(value.get(field), f"inner.{field}"))
    x_offset, y_offset, inner_width, inner_height = numbers
    if inner_width == 0 or inner_height == 0:
        raise _incompatible(
            f"inner rectangle {inner_width}x{inner_height} is empty"
        )
    if x_offset + inner_width > width or y_offset + inner_height > height:
        raise _incompatible(
            f"inner rectangle {inner_width}x{inner_height} at "
            f"({x_offset}, {y_offset}) does not fit the {width}x{height} "
            "debug buffer"
        )
    return x_offset, y_offset, inner_width, inner_height


def _palette(value: object, buffer: bytes) -> list[Rgb]:
    if not isinstance(value, Sequence) or isinstance(
        value, (str, bytes, bytearray)
    ):
        raise _incompatible("palette must be an array")
    entries = list(cast(Sequence[object], value))
    if not entries or len(entries) > MAX_PALETTE_ENTRIES:
        raise _incompatible(
            f"palette holds {len(entries)} entries; 1 to "
            f"{MAX_PALETTE_ENTRIES} are renderable"
        )
    colours: list[Rgb] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise _incompatible(
                f"palette entry {index} must be an object with r, g, and b"
            )
        channels: list[int] = []
        for channel in ("r", "g", "b"):
            number = entry.get(channel)
            if (
                not isinstance(number, int)
                or isinstance(number, bool)
                or number < 0
                or number > 255
            ):
                raise _incompatible(
                    f"palette entry {index} channel {channel} must be an "
                    "integer from 0 to 255"
                )
            channels.append(number)
        colours.append((channels[0], channels[1], channels[2]))
    # The connector already refuses an uncovered buffer; confirming it here
    # keeps a malformed pairing from reaching the encoder as a black pixel.
    highest = max(buffer) if buffer else 0
    if highest >= len(colours):
        raise _incompatible(
            f"palette holds {len(colours)} entries but the buffer uses index "
            f"{highest}"
        )
    return colours


def _positive(value: object, field: str) -> int:
    number = _integer(value, field)
    if number <= 0:
        raise _incompatible(f"{field} must be positive, not {number}")
    return number


def _nonnegative(value: object, field: str) -> int:
    number = _integer(value, field)
    if number < 0:
        raise _incompatible(f"{field} must not be negative, not {number}")
    return number


def _integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise _incompatible(f"{field} must be an integer")
    return value


def _incompatible(message: str) -> ViceError:
    return ViceError("vice_connector_incompatible", message)


__all__ = [
    "CAPTURE_SUMMARY_FIELDS",
    "CaptureViceSession",
    "vice_capture_screen",
]
