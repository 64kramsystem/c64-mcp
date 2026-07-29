import pytest

from c64_mcp.errors import RequestError
from c64_mcp.symbols import apply_c64_symbols, load_c64_symbols


class FakeGhidra:
    def __init__(self):
        self.calls = []

    def create_labels(self, program, labels):
        self.calls.append((program, labels))
        return {
            "labels_created": len(labels),
            "labels_skipped": 0,
            "labels_failed": 0,
        }


def test_bundled_symbols_are_applied_once():
    ghidra = FakeGhidra()
    symbols = load_c64_symbols()

    result = apply_c64_symbols(ghidra, program="game")

    assert symbols
    assert result == {
        "labels_created": len(symbols),
        "labels_skipped": 0,
        "labels_failed": 0,
    }
    assert ghidra.calls[0][0] == "game"
    assert ghidra.calls[0][1][0]["namespace"] == "C64::CPU"


def test_symbols_reject_blank_programs():
    with pytest.raises(RequestError, match="program"):
        apply_c64_symbols(FakeGhidra(), program="")
