from __future__ import annotations

import base64
import inspect
import io
import json
from pathlib import Path
from typing import Any

import pytest
from mcp.types import CallToolResult, ImageContent, TextContent
from PIL import Image

from c64_mcp.errors import RequestError, ViceError
from c64_mcp.graphics.capture import (
    CAPTURE_SUMMARY_FIELDS,
    vice_capture_screen,
)
from c64_mcp.graphics.png import PNG_SIGNATURE

WIDTH = 6
HEIGHT = 5
INNER = {"x_offset": 1, "y_offset": 2, "width": 3, "height": 2}
# One distinct index per pixel, so a crop that is off by one pixel in any
# direction changes the rendered matrix.
BUFFER = bytes(range(WIDTH * HEIGHT))
PALETTE = [
    {"r": index, "g": 2 * index, "b": 3 * index}
    for index in range(WIDTH * HEIGHT)
]


def capture_result(**overrides: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "width": WIDTH,
        "height": HEIGHT,
        "inner": dict(INNER),
        "bits_per_pixel": 8,
        "buffer_length": len(BUFFER),
        "buffer_base64": base64.b64encode(BUFFER).decode("ascii"),
        "palette": [dict(entry) for entry in PALETTE],
        "vice_version": "3.11.0.0",
        "vice_revision": None,
    }
    result.update(overrides)
    return result


class FakeCaptureSession:
    """A connector that answers one capture call from a canned envelope."""

    def __init__(self, envelope: dict[str, object] | None = None) -> None:
        self.envelope: dict[str, object] = (
            envelope
            if envelope is not None
            else {
                "api": "c64.vice/1",
                "ok": True,
                "command_sequence": 1,
                "instance_id": "12345678-1234-1234-1234-123456789abc",
                "connection_state": "connected",
                "execution_state": "stopped",
                "result": capture_result(),
            }
        )
        self.calls: list[dict[str, object]] = []

    def capture_display(
        self, *, use_vic: bool = True, timeout_ms: int = 10_000
    ) -> dict[str, object]:
        self.calls.append({"use_vic": use_vic, "timeout_ms": timeout_ms})
        return self.envelope


def session_returning(**overrides: Any) -> FakeCaptureSession:
    return FakeCaptureSession(
        {
            "api": "c64.vice/1",
            "ok": True,
            "command_sequence": 1,
            "instance_id": "12345678-1234-1234-1234-123456789abc",
            "connection_state": "connected",
            "execution_state": "stopped",
            "result": capture_result(**overrides),
        }
    )


def summary(result: CallToolResult) -> dict[str, Any]:
    assert result.structuredContent is not None
    return dict(result.structuredContent)


def image_bytes(result: CallToolResult) -> bytes:
    block = result.content[0]
    assert isinstance(block, ImageContent)
    assert block.mimeType == "image/png"
    return base64.b64decode(block.data, validate=True)


def pixels(result: CallToolResult) -> list[list[int]]:
    image = Image.open(io.BytesIO(image_bytes(result)))
    image.load()
    assert image.mode == "P"
    return [
        [image.getpixel((x, y)) for x in range(image.width)]
        for y in range(image.height)
    ]


def test_the_signature_carries_the_specified_defaults() -> None:
    parameters = inspect.signature(vice_capture_screen).parameters

    assert list(parameters) == [
        "vice",
        "crop",
        "use_vic",
        "timeout_ms",
        "output_path",
        "overwrite",
    ]
    assert parameters["crop"].default is True
    assert parameters["use_vic"].default is True
    assert parameters["timeout_ms"].default == 10_000
    assert parameters["output_path"].default is None
    assert parameters["overwrite"].default is False
    assert all(
        parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
        for name in ("crop", "use_vic", "timeout_ms", "output_path", "overwrite")
    )


def test_the_defaults_are_passed_through_to_the_connector() -> None:
    session = FakeCaptureSession()

    vice_capture_screen(session)

    assert session.calls == [{"use_vic": True, "timeout_ms": 10_000}]


def test_connector_arguments_are_forwarded() -> None:
    session = FakeCaptureSession()

    vice_capture_screen(session, use_vic=False, timeout_ms=2_500)

    assert session.calls == [{"use_vic": False, "timeout_ms": 2_500}]


def test_the_default_crop_returns_only_the_inner_screen_rectangle() -> None:
    result = vice_capture_screen(FakeCaptureSession())

    fields = summary(result)
    assert (fields["width"], fields["height"]) == (3, 2)
    assert fields["cropped"] is True
    assert fields["inner"] == INNER
    # Rows 2 and 3, columns 1 through 3, of a six-wide debug buffer.
    assert pixels(result) == [[13, 14, 15], [19, 20, 21]]


def test_crop_false_returns_the_whole_debug_buffer() -> None:
    result = vice_capture_screen(FakeCaptureSession(), crop=False)

    fields = summary(result)
    assert (fields["width"], fields["height"]) == (WIDTH, HEIGHT)
    assert fields["cropped"] is False
    assert fields["inner"] == INNER
    assert pixels(result) == [
        list(range(row * WIDTH, row * WIDTH + WIDTH))
        for row in range(HEIGHT)
    ]


def test_a_real_frame_geometry_crops_to_the_visible_screen() -> None:
    # The shape VICE actually returns for a PAL C64: a 384x272 debug frame
    # with the 320x200 display window inside it.
    width, height = 384, 272
    inner = {"x_offset": 32, "y_offset": 35, "width": 320, "height": 200}
    buffer = bytes(
        (x + y) % 16 for y in range(height) for x in range(width)
    )
    session = FakeCaptureSession(
        {
            "api": "c64.vice/1",
            "ok": True,
            "command_sequence": 1,
            "instance_id": "12345678-1234-1234-1234-123456789abc",
            "connection_state": "connected",
            "execution_state": "stopped",
            "result": {
                "width": width,
                "height": height,
                "inner": inner,
                "bits_per_pixel": 8,
                "buffer_length": width * height,
                "buffer_base64": base64.b64encode(buffer).decode("ascii"),
                "palette": [
                    {"r": index, "g": index, "b": index}
                    for index in range(16)
                ],
                "vice_version": "3.11.0.0",
                "vice_revision": None,
            },
        }
    )

    result = vice_capture_screen(session)

    fields = summary(result)
    assert (fields["width"], fields["height"]) == (320, 200)
    matrix = pixels(result)
    assert matrix[0][0] == (32 + 35) % 16
    assert matrix[199][319] == (32 + 319 + 35 + 199) % 16


def test_the_palette_is_the_one_vice_returned_not_the_static_default() -> None:
    result = vice_capture_screen(FakeCaptureSession(), crop=False)

    image = Image.open(io.BytesIO(image_bytes(result)))
    table = image.getpalette()
    assert table is not None
    expected: list[int] = []
    for entry in PALETTE:
        expected.extend((entry["r"], entry["g"], entry["b"]))
    assert table[: len(expected)] == expected
    # Pepto white would be the second entry of the static default palette.
    assert table[3:6] != [0xFF, 0xFF, 0xFF]
    assert summary(result)["palette_size"] == len(PALETTE)


def test_the_result_holds_one_image_and_one_json_summary() -> None:
    result = vice_capture_screen(FakeCaptureSession())

    assert isinstance(result, CallToolResult)
    assert len(result.content) == 2
    assert isinstance(result.content[0], ImageContent)
    assert isinstance(result.content[1], TextContent)
    assert image_bytes(result).startswith(PNG_SIGNATURE)
    assert json.loads(result.content[1].text) == summary(result)
    block = result.content[0]
    assert isinstance(block, ImageContent)
    assert result.model_dump_json().count(block.data) == 1


def test_structured_content_carries_no_base64() -> None:
    result = vice_capture_screen(FakeCaptureSession())

    block = result.content[0]
    assert isinstance(block, ImageContent)
    structured = json.dumps(summary(result))
    assert block.data not in structured
    assert "buffer_base64" not in structured
    assert base64.b64encode(BUFFER).decode("ascii") not in structured


def test_the_summary_field_set_is_exact() -> None:
    result = vice_capture_screen(FakeCaptureSession())

    fields = summary(result)
    assert set(fields) == set(CAPTURE_SUMMARY_FIELDS)
    assert set(CAPTURE_SUMMARY_FIELDS) == {
        "mode",
        "width",
        "height",
        "cropped",
        "inner",
        "palette_size",
        "used_indices",
        "distinct_index_count",
        "output_path",
    }
    assert fields["mode"] == "vice_capture"
    assert fields["used_indices"] == [13, 14, 15, 19, 20, 21]
    assert fields["distinct_index_count"] == 6
    assert fields["output_path"] is None


@pytest.mark.parametrize(
    ("overrides", "field"),
    [
        ({"bits_per_pixel": 4}, "bits_per_pixel"),
        ({"buffer_length": WIDTH * HEIGHT + 1}, "buffer_length"),
        (
            {
                "buffer_base64": base64.b64encode(BUFFER[:-1]).decode(
                    "ascii"
                )
            },
            "buffer_base64",
        ),
        ({"buffer_base64": "not base64!!"}, "buffer_base64"),
        (
            {"inner": {**INNER, "x_offset": 4}},
            "inner",
        ),
        (
            {"inner": {**INNER, "y_offset": 4}},
            "inner",
        ),
        ({"palette": [dict(entry) for entry in PALETTE[:20]]}, "palette"),
        ({"width": 0}, "width"),
        ({"height": -1}, "height"),
    ],
)
def test_each_envelope_rule_surfaces_vice_connector_incompatible(
    overrides: dict[str, Any], field: str
) -> None:
    session = session_returning(**overrides)

    with pytest.raises(ViceError) as caught:
        vice_capture_screen(session)

    assert caught.value.code == "vice_connector_incompatible"
    assert field in str(caught.value)


def test_a_missing_result_object_is_incompatible() -> None:
    session = FakeCaptureSession(
        {
            "api": "c64.vice/1",
            "ok": True,
            "command_sequence": 1,
            "instance_id": "12345678-1234-1234-1234-123456789abc",
            "connection_state": "connected",
            "execution_state": "stopped",
            "result": "not an object",
        }
    )

    with pytest.raises(ViceError) as caught:
        vice_capture_screen(session)

    assert caught.value.code == "vice_connector_incompatible"


def test_a_connector_failure_is_reraised_with_its_own_code() -> None:
    session = FakeCaptureSession(
        {
            "ok": False,
            "error": {
                "code": "vice_target_not_stopped",
                "message": "interrupt before capturing",
            },
        }
    )

    with pytest.raises(ViceError) as caught:
        vice_capture_screen(session)

    assert caught.value.code == "vice_target_not_stopped"
    assert "interrupt" in str(caught.value)


def test_a_non_boolean_crop_is_rejected_before_the_connector_is_called() -> None:
    session = FakeCaptureSession()

    with pytest.raises(RequestError, match="crop"):
        vice_capture_screen(session, crop="yes")  # type: ignore[arg-type]

    assert session.calls == []


def test_output_path_writes_the_png_and_leaves_no_temporary_files(
    tmp_path: Path,
) -> None:
    target = tmp_path / "frame.png"

    result = vice_capture_screen(
        FakeCaptureSession(), output_path=str(target)
    )

    assert summary(result)["output_path"] == str(target)
    assert target.read_bytes() == image_bytes(result)
    assert list(tmp_path.iterdir()) == [target]


def test_an_existing_output_path_is_refused_without_overwrite(
    tmp_path: Path,
) -> None:
    target = tmp_path / "frame.png"
    target.write_bytes(b"keep me")
    session = FakeCaptureSession()

    with pytest.raises(RequestError, match="overwrite"):
        vice_capture_screen(session, output_path=str(target))

    assert target.read_bytes() == b"keep me"
    # The refusal costs no capture: the path is checked before the call.
    assert session.calls == []


def test_overwrite_replaces_an_existing_output_path(tmp_path: Path) -> None:
    target = tmp_path / "frame.png"
    target.write_bytes(b"replace me")

    result = vice_capture_screen(
        FakeCaptureSession(), output_path=str(target), overwrite=True
    )

    assert target.read_bytes() == image_bytes(result)
    assert list(tmp_path.iterdir()) == [target]
