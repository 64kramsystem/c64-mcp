import pytest

from c64_mcp.errors import RequestError
from c64_mcp.graphics.sources import SourcePlan, parse_source


class FakeGhidra:
    def __init__(self):
        self.calls = []

    def read_bytes(self, program, start, length):
        self.calls.append((program, start, length))
        return bytes(range(length))


def test_inline_and_ghidra_sources_supply_exact_requested_bytes():
    ghidra = FakeGhidra()
    inline = parse_source({"kind": "inline", "bytes": "00 01 02"}, "bitmap")
    remote = parse_source(
        {"kind": "ghidra", "program": "game", "start": "RAM:2000"},
        "screen",
    )
    plan = SourcePlan(ghidra)
    assert plan.load(inline, 2) == b"\x00\x01\x02"
    assert plan.load(remote, 3) == b"\x00\x01\x02"
    assert ghidra.calls == [("game", "RAM:2000", 3)]


@pytest.mark.parametrize(
    "value",
    [
        {"kind": "vice", "start": 0},
        {"kind": "inline", "bytes": "00", "extra": True},
        {"kind": "ghidra", "program": "", "start": "RAM:1000"},
    ],
)
def test_only_small_inline_or_ghidra_sources_are_accepted(value):
    with pytest.raises(RequestError):
        parse_source(value, "source")
