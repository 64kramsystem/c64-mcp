import base64

import pytest
from mcp.types import ImageContent

from c64_mcp.errors import ViceError
from c64_mcp.graphics.capture import vice_capture_screen
from c64_mcp.graphics.png import PNG_SIGNATURE


def envelope():
    return {
        "ok": True,
        "result": {
            "capture_id": "frame",
            "width": 3,
            "height": 2,
            "inner": {
                "x_offset": 1,
                "y_offset": 0,
                "width": 2,
                "height": 2,
            },
            "bits_per_pixel": 8,
            "buffer_length": 6,
            "palette": [
                {"r": 0, "g": 0, "b": 0},
                {"r": 255, "g": 255, "b": 255},
            ],
        },
    }


class FakeVice:
    def __init__(self, chunks=(b"\x00\x01", b"\x00\x01\x00\x01")):
        self.chunks = iter(chunks)
        self.discarded = []
        self.reads = []

    def capture_display(self, **_kwargs):
        return envelope()

    def read_display_capture(self, **kwargs):
        self.reads.append(kwargs)
        chunk = next(self.chunks)
        return {
            "ok": True,
            "result": {
                "capture_id": kwargs["capture_id"],
                "buffer_base64": base64.b64encode(chunk).decode(),
            },
        }

    def discard_display_capture(self, *, capture_id):
        self.discarded.append(capture_id)
        return {"ok": True}


def test_capture_streams_chunks_crops_and_discards():
    vice = FakeVice()
    result = vice_capture_screen(vice)

    image = result.content[0]
    assert isinstance(image, ImageContent)
    assert base64.b64decode(image.data).startswith(PNG_SIGNATURE)
    assert (result.structuredContent["width"], result.structuredContent["height"]) == (
        2,
        2,
    )
    assert vice.discarded == ["frame"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("bits_per_pixel", 4, "bits_per_pixel"),
        ("buffer_length", 5, "width \\* height"),
    ],
)
def test_invalid_frame_metadata_is_rejected_before_chunk_read(field, value, message):
    class InvalidVice(FakeVice):
        def capture_display(self, **_kwargs):
            result = envelope()
            result["result"][field] = value
            return result

    vice = InvalidVice()
    with pytest.raises(ViceError, match=message):
        vice_capture_screen(vice)

    assert vice.reads == []
    assert vice.discarded == ["frame"]


def test_capture_is_discarded_when_a_chunk_is_invalid():
    vice = FakeVice(chunks=(b"",))

    with pytest.raises(ViceError, match="invalid length"):
        vice_capture_screen(vice)

    assert vice.discarded == ["frame"]
