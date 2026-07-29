"""Turn one live VICE frame into an indexed PNG.

The connector owns the emulator: it traps VICE into the monitor, reads the
composited display buffer and the palette that goes with it, and returns one
byte per pixel plus the RGB table those bytes index. Nothing is rendered there,
so everything below happens here — envelope validation, cropping to the inner
screen rectangle, and encoding with the same indexed-PNG writer the static
decoders use.

Two properties of the connector output shape this module:

- The buffer is the **debug** frame, larger than the visible screen. It carries
  border and blanking around an inner rectangle whose offsets and size the
  connector reports; `crop=True` renders only that rectangle.
- The connector refuses a frame whose highest index its palette does not cover,
  so an unmapped index cannot reach this path.

The result mirrors the decoders: one `ImageContent`, one textual JSON summary,
and `structuredContent` holding only that summary, so the ~140 KB of base64
never appears twice and never lands in structured output.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast

from mcp.types import CallToolResult, ImageContent, TextContent

from ..errors import RequestError, ViceError
from ..vice import MAX_DISPLAY_CAPTURE_CHUNK_BYTES
from .palette import MAX_PALETTE_ENTRIES, Rgb
from .png import encode_indexed_png
from .tools import output_target, write_atomically

CAPTURE_MODE = "vice_capture"
BITS_PER_PIXEL = 8
DEFAULT_TIMEOUT_MS = 10_000
_INNER_FIELDS = ("x_offset", "y_offset", "width", "height")


class CaptureViceSession(Protocol):
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
    ) -> dict[str, object]: ...

    def discard_display_capture(self, *, capture_id: str) -> dict[str, object]: ...


def vice_capture_screen(
    vice: CaptureViceSession,
    *,
    crop: bool = True,
    use_vic: bool = True,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    output_path: str | None = None,
    overwrite: bool = False,
) -> CallToolResult:
    """Capture the current VICE frame and return it as an indexed PNG."""

    if not isinstance(crop, bool):
        raise RequestError("crop must be a boolean")
    if not isinstance(use_vic, bool):
        raise RequestError("use_vic must be a boolean")
    # Checked before the capture, so a doomed write costs no frame.
    target = output_target(output_path, overwrite)

    envelope = vice.capture_display(use_vic=use_vic, timeout_ms=timeout_ms)
    result = _result(envelope)
    capture_id = result.get("capture_id")
    if not isinstance(capture_id, str) or not capture_id:
        raise _incompatible("capture_id must be a nonblank string")
    buffer_length = _nonnegative(result.get("buffer_length"), "buffer_length")
    try:
        dimensions = _dimensions(result)
        buffer = _read_buffer(vice, capture_id, buffer_length)
        frame = _frame(result, dimensions, buffer)
    finally:
        vice.discard_display_capture(capture_id=capture_id)

    rows: Sequence[Sequence[int]]
    if crop:
        rows = [
            frame.buffer[
                (frame.inner_y + row) * frame.width + frame.inner_x : (
                    frame.inner_y + row
                )
                * frame.width
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


def _frame(
    record: Mapping[str, object],
    dimensions: tuple[int, int, int, int, int, int, int],
    buffer: bytes,
) -> _Frame:
    """Validate the connector envelope completely before anything renders."""

    width, height, inner_x, inner_y, inner_width, inner_height, buffer_length = (
        dimensions
    )
    if len(buffer) != buffer_length:
        raise _incompatible("display chunks did not match buffer_length")
    palette = _palette(record.get("palette"), buffer)
    return _Frame(
        width=width,
        height=height,
        inner_x=inner_x,
        inner_y=inner_y,
        inner_width=inner_width,
        inner_height=inner_height,
        buffer=buffer,
        palette=palette,
    )


def _dimensions(
    record: Mapping[str, object],
) -> tuple[int, int, int, int, int, int, int]:
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
    return (
        width,
        height,
        inner_x,
        inner_y,
        inner_width,
        inner_height,
        buffer_length,
    )


def _inner(value: object, width: int, height: int) -> tuple[int, int, int, int]:
    if not isinstance(value, Mapping):
        raise _incompatible("inner must be an object")
    numbers: list[int] = []
    for field in _INNER_FIELDS:
        numbers.append(_nonnegative(value.get(field), f"inner.{field}"))
    x_offset, y_offset, inner_width, inner_height = numbers
    if inner_width == 0 or inner_height == 0:
        raise _incompatible(f"inner rectangle {inner_width}x{inner_height} is empty")
    if x_offset + inner_width > width or y_offset + inner_height > height:
        raise _incompatible(
            f"inner rectangle {inner_width}x{inner_height} at "
            f"({x_offset}, {y_offset}) does not fit the {width}x{height} "
            "debug buffer"
        )
    return x_offset, y_offset, inner_width, inner_height


def _read_buffer(
    vice: CaptureViceSession, capture_id: str, buffer_length: int
) -> bytes:
    data = bytearray()
    while len(data) < buffer_length:
        envelope = vice.read_display_capture(
            capture_id=capture_id,
            offset=len(data),
            max_bytes=min(
                MAX_DISPLAY_CAPTURE_CHUNK_BYTES,
                buffer_length - len(data),
            ),
        )
        record = _result(envelope)
        if record.get("capture_id") != capture_id:
            raise _incompatible("display chunk belongs to another capture")
        encoded = record.get("buffer_base64")
        if not isinstance(encoded, str):
            raise _incompatible("display chunk omitted buffer_base64")
        try:
            chunk = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise _incompatible("display chunk is not valid base64") from error
        if not chunk or len(chunk) > buffer_length - len(data):
            raise _incompatible("display chunk has an invalid length")
        data.extend(chunk)
    return bytes(data)


def _result(envelope: Mapping[str, object]) -> Mapping[str, object]:
    if envelope.get("ok") is False:
        error = envelope.get("error")
        if isinstance(error, Mapping):
            raise ViceError.from_mapping(
                error,
                fallback_code="vice_capture_failed",
                fallback_message="the VICE display capture failed",
            )
        raise ViceError("vice_capture_failed", "the VICE display capture failed")
    result = envelope.get("result")
    if not isinstance(result, Mapping):
        raise _incompatible("the capture returned no result object")
    return cast(Mapping[str, object], result)


def _palette(value: object, buffer: bytes) -> list[Rgb]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
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
            f"palette holds {len(colours)} entries but the buffer uses index {highest}"
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
    "CaptureViceSession",
    "vice_capture_screen",
]
