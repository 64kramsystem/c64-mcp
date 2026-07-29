from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from c64_mcp.errors import GhidraError
from c64_mcp.reversing import (
    capture_transition,
    find_split_pointer_partners,
    import_vice_phase,
    search_6502_indexed_operands,
)


class PhaseVice:
    def __init__(self, banks: list[dict[str, object]] | None = None) -> None:
        self.banks = banks or [
            {"name": "default", "id": 0},
            {"name": "cpu", "id": 0},
            {"name": "ram", "id": 1},
            {"name": "rom", "id": 2},
            {"name": "io", "id": 3},
        ]
        self.command_sequence = 1
        self.event_sequence = 10
        self.list_calls = 0
        self.capture_calls: list[dict[str, object]] = []

    def list_banks(
        self, *, timeout_ms: int = 10_000
    ) -> dict[str, object]:
        self.list_calls += 1
        return {
            "ok": True,
            "command_sequence": self.command_sequence,
            "result": {"banks": self.banks},
        }

    def status(self) -> dict[str, object]:
        return {
            "state": "stopped",
            "max_command_sequence": self.command_sequence,
            "last_event_sequence": self.event_sequence,
        }

    def capture_state(self, **kwargs: object) -> dict[str, object]:
        assert kwargs["expected_command_sequence"] == self.command_sequence
        assert kwargs["expected_event_sequence"] == self.event_sequence
        ranges = kwargs["ranges"]
        assert isinstance(ranges, list) and len(ranges) == 1
        item = ranges[0]
        assert isinstance(item, dict)
        self.capture_calls.append(dict(kwargs))
        self.command_sequence += 1
        start = item["start"]
        end = item["end"]
        bank_id = item["bank_id"]
        assert isinstance(start, int)
        assert isinstance(end, int)
        assert isinstance(bank_id, int)
        data = bytes([bank_id]) * (end - start + 1)
        return {
            "ok": True,
            "command_sequence": self.command_sequence,
            "result": {
                "event_sequence": self.event_sequence,
                "registers": [{"name": "PC", "value": 0xC000}],
                "checkpoints": [],
                "ranges": [
                    {
                        **item,
                        "memspace": item.get("memspace", 0),
                        "byte_count": len(data),
                        "bytes": data.hex(),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                ],
            },
        }


class ReversingGhidra:
    def __init__(self) -> None:
        self.images: list[dict[str, object]] = []
        self.searches: list[dict[str, object]] = []
        self.split_searches: list[dict[str, object]] = []

    def apply_memory_image(
        self,
        program: str,
        blocks: list[Mapping[str, object]],
        metadata: Mapping[str, object],
        *,
        conflict_policy: str = "error",
        dry_run: bool = True,
        timeout_ms: int = 30_000,
    ) -> dict[str, object]:
        self.images.append(
            {
                "program": program,
                "blocks": blocks,
                "metadata": metadata,
                "conflict_policy": conflict_policy,
                "dry_run": dry_run,
                "timeout_ms": timeout_ms,
            }
        )
        return {"committed": not dry_run, "blocks": [], "changed": True}

    def search_6502_indexed_operands(
        self, program: str, **kwargs: object
    ) -> dict[str, object]:
        self.searches.append({"program": program, **kwargs})
        return {"operands": [{"instruction_address": "RAM:1000"}]}

    def find_split_pointer_partners(
        self, program: str, **kwargs: object
    ) -> dict[str, object]:
        self.split_searches.append({"program": program, **kwargs})
        return {"proposals": [{"first_start": "RAM:2000"}]}

def test_import_phase_chains_bounded_captures_and_applies_once(
    tmp_path: Path,
) -> None:
    vice = PhaseVice()
    ghidra = ReversingGhidra()

    result = import_vice_phase(
        vice,
        ghidra,
        program="game",
        phase="race",
        output_dir=str(tmp_path),
        overwrite=True,
    )

    assert result["ok"] is True
    assert len(vice.capture_calls) == 13
    for previous, current in zip(
        vice.capture_calls, vice.capture_calls[1:], strict=False
    ):
        assert (
            current["expected_command_sequence"]
            == previous["expected_command_sequence"] + 1  # type: ignore[operator]
        )
        assert (
            current["expected_event_sequence"]
            == previous["expected_event_sequence"]
        )
    assert all(
        item["ranges"][0]["end"] - item["ranges"][0]["start"] + 1  # type: ignore[index,operator]
        <= 16_384
        for item in vice.capture_calls
    )

    expected_sizes = {
        "RACE_CPU.bin": 65_536,
        "RACE_RAM.bin": 65_536,
        "RACE_ROM.bin": 65_536,
        "RACE_IO.bin": 4_096,
    }
    assert {
        path.name: path.stat().st_size
        for path in tmp_path.glob("*.bin")
    } == expected_sizes
    manifest = json.loads(
        (tmp_path / "RACE_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["phase"] == "RACE"
    assert len(manifest["captures"]) == 13

    assert len(ghidra.images) == 1
    image = ghidra.images[0]
    assert image["conflict_policy"] == "replace_exact"
    blocks = image["blocks"]
    assert isinstance(blocks, list)
    assert [block["name"] for block in blocks] == [
        "RACE_CPU",
        "RACE_RAM",
        "RACE_ROM",
        "RACE_IO",
    ]
    assert [block["start"] for block in blocks] == [
        "RAM:0000",
        "RAM:0000",
        "RAM:0000",
        "RAM:D000",
    ]
    assert all(block["overlay"] is True for block in blocks)
    metadata = image["metadata"]
    assert isinstance(metadata, dict)
    assert all(isinstance(value, str) for value in metadata.values())
    assert image["dry_run"] is True
    assert image["timeout_ms"] == 30_000


def test_import_phase_prepares_output_before_contacting_vice(
    tmp_path: Path,
) -> None:
    output = tmp_path / "new" / "evidence"

    class PreparedPhaseVice(PhaseVice):
        def list_banks(
            self, *, timeout_ms: int = 10_000
        ) -> dict[str, object]:
            assert output.is_dir()
            return super().list_banks(timeout_ms=timeout_ms)

    result = import_vice_phase(
        PreparedPhaseVice(),
        ReversingGhidra(),
        program="game",
        phase="prepared",
        output_dir=str(output),
    )

    assert result["ok"] is True
    assert not list(output.glob("*.part"))


def test_import_phase_refuses_existing_artifact_before_vice(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "INTRO_CPU.bin"
    existing.write_bytes(b"keep")
    vice = PhaseVice()

    result = import_vice_phase(
        vice,
        ReversingGhidra(),
        program="game",
        phase="intro",
        output_dir=str(tmp_path),
    )

    assert result["error"]["code"] == "artifact_exists"  # type: ignore[index]
    assert vice.list_calls == 0
    assert existing.read_bytes() == b"keep"


def test_import_phase_refuses_non_directory_output_before_vice(
    tmp_path: Path,
) -> None:
    output = tmp_path / "not-a-directory"
    output.write_bytes(b"x")
    vice = PhaseVice()

    result = import_vice_phase(
        vice,
        ReversingGhidra(),
        program="game",
        phase="intro",
        output_dir=str(output),
    )

    assert result["error"]["code"] == "artifact_io_error"  # type: ignore[index]
    assert vice.list_calls == 0


def test_import_phase_rejects_invalid_ghidra_timeout_before_artifacts(
    tmp_path: Path,
) -> None:
    output = tmp_path / "new"
    vice = PhaseVice()

    result = import_vice_phase(
        vice,
        ReversingGhidra(),
        program="game",
        phase="intro",
        output_dir=str(output),
        ghidra_timeout_ms=0,
    )

    assert result["error"]["code"] == "vice_invalid_argument"  # type: ignore[index]
    assert vice.list_calls == 0
    assert not output.exists()


def test_import_phase_writes_only_final_manifest_after_ghidra(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "FINAL_manifest.json"

    class InspectingGhidra(ReversingGhidra):
        def apply_memory_image(
            self,
            program: str,
            blocks: list[Mapping[str, object]],
            metadata: Mapping[str, object],
            *,
            conflict_policy: str = "error",
            dry_run: bool = True,
            timeout_ms: int = 30_000,
        ) -> dict[str, object]:
            assert not manifest.exists()
            assert not list(tmp_path.glob("*.part"))
            return super().apply_memory_image(
                program,
                blocks,
                metadata,
                conflict_policy=conflict_policy,
                dry_run=dry_run,
                timeout_ms=timeout_ms,
            )

    result = import_vice_phase(
        PhaseVice(),
        InspectingGhidra(),
        program="game",
        phase="final",
        output_dir=str(tmp_path),
    )

    assert result["ok"] is True
    assert json.loads(manifest.read_text(encoding="utf-8"))["ghidra"]["ok"]
    assert not list(tmp_path.glob("*.part"))


def test_import_phase_classifies_status_race_as_state_change(
    tmp_path: Path,
) -> None:
    class RacingPhaseVice(PhaseVice):
        def status(self) -> dict[str, object]:
            status = super().status()
            status["max_command_sequence"] = self.command_sequence + 1
            return status

    result = import_vice_phase(
        RacingPhaseVice(),
        ReversingGhidra(),
        program="game",
        phase="race",
        output_dir=str(tmp_path),
    )

    assert result["error"]["code"] == "vice_state_changed"  # type: ignore[index]


def test_import_phase_classifies_chunk_drift_as_state_change(
    tmp_path: Path,
) -> None:
    class DriftingPhaseVice(PhaseVice):
        def capture_state(self, **kwargs: object) -> dict[str, object]:
            envelope = super().capture_state(**kwargs)
            if len(self.capture_calls) == 2:
                result = envelope["result"]
                assert isinstance(result, dict)
                result["registers"] = [{"name": "PC", "value": 0xC001}]
            return envelope

    result = import_vice_phase(
        DriftingPhaseVice(),
        ReversingGhidra(),
        program="game",
        phase="drift",
        output_dir=str(tmp_path),
    )

    assert result["error"]["code"] == "vice_state_changed"  # type: ignore[index]


def test_import_phase_refuses_missing_semantic_bank_without_capture(
    tmp_path: Path,
) -> None:
    vice = PhaseVice(
        [
            {"name": "cpu", "id": 0},
            {"name": "ram", "id": 1},
            {"name": "rom", "id": 2},
        ]
    )
    ghidra = ReversingGhidra()

    result = import_vice_phase(
        vice,
        ghidra,
        program="game",
        phase="intro",
        output_dir=str(tmp_path),
    )

    assert result["error"]["code"] == "vice_bank_mapping_ambiguous"  # type: ignore[index]
    assert vice.capture_calls == []
    assert ghidra.images == []
    assert list(tmp_path.iterdir()) == []


def test_import_phase_prefers_exact_default_over_distinct_cpu_alias(
    tmp_path: Path,
) -> None:
    vice = PhaseVice(
        [
            {"name": "default", "id": 4},
            {"name": "cpu", "id": 5},
            {"name": "ram", "id": 1},
            {"name": "rom", "id": 2},
            {"name": "io", "id": 3},
        ]
    )

    result = import_vice_phase(
        vice,
        ReversingGhidra(),
        program="game",
        phase="default_bank",
        output_dir=str(tmp_path),
    )

    assert result["ok"] is True
    assert result["banks"]["CPU"]["id"] == 4  # type: ignore[index]
    assert (tmp_path / "DEFAULT_BANK_CPU.bin").read_bytes()[:1] == b"\x04"


def test_import_phase_records_ghidra_failure_with_persisted_evidence(
    tmp_path: Path,
) -> None:
    class FailedGhidra(ReversingGhidra):
        def apply_memory_image(
            self,
            program: str,
            blocks: list[Mapping[str, object]],
            metadata: Mapping[str, object],
            *,
            conflict_policy: str = "error",
            dry_run: bool = True,
            timeout_ms: int = 30_000,
        ) -> dict[str, object]:
            del conflict_policy, timeout_ms
            raise GhidraError("endpoint unavailable")

    result = import_vice_phase(
        PhaseVice(),
        FailedGhidra(),
        program="game",
        phase="failed",
        output_dir=str(tmp_path),
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "ghidra_response_error"  # type: ignore[index]
    assert len(result["artifacts"]) == 4  # type: ignore[arg-type]
    manifest_path = Path(result["manifest_path"])  # type: ignore[arg-type]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["ghidra"]["ok"] is False
    assert manifest["ghidra"]["error"]["message"] == "endpoint unavailable"


def test_import_phase_overwrite_refreshes_exact_ghidra_blocks(
    tmp_path: Path,
) -> None:
    ghidra = ReversingGhidra()

    result = import_vice_phase(
        PhaseVice(),
        ghidra,
        program="game",
        phase="refresh",
        output_dir=str(tmp_path),
        overwrite=True,
    )

    assert result["ok"] is True
    assert ghidra.images[0]["conflict_policy"] == "replace_exact"


class TransitionVice:
    def __init__(
        self, *, exact_hit: bool = True, release_ok: bool = True
    ) -> None:
        self.exact_hit = exact_hit
        self.release_ok = release_ok
        self.after = False
        self.calls: list[tuple[str, dict[str, object]]] = []

    def status(self) -> dict[str, object]:
        return {
            "state": "stopped",
            "max_command_sequence": 0,
            "last_event_sequence": 1,
        }

    def capture_state(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("capture", dict(kwargs)))
        command = 7 if self.after else 1
        event = 3 if self.after else 1
        data = b"\x00\x05\x06\x03" if self.after else b"\x00\x01\x02\x03"
        return {
            "ok": True,
            "command_sequence": command,
            "result": {
                "event_sequence": event,
                "registers": [
                    {"name": "A", "value": 2 if self.after else 1}
                ],
                "checkpoints": [],
                "ranges": [
                    {
                        "name": "state",
                        "bank_id": 1,
                        "memspace": 0,
                        "start": 0x2000,
                        "end": 0x2003,
                        "byte_count": len(data),
                        "bytes": data.hex(),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                ],
            },
        }

    def set_checkpoint(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("checkpoint", dict(kwargs)))
        return {
            "ok": True,
            "command_sequence": 2,
            "result": {"checkpoint": {"number": 9}},
        }

    def feed_keyboard(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("keyboard", dict(kwargs)))
        return {"ok": True, "command_sequence": 3, "result": {}}

    def set_joyport(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("joyport", dict(kwargs)))
        command = 8 if kwargs["value"] == 0xFF else 4
        if kwargs["value"] == 0xFF and not self.release_ok:
            return {
                "ok": False,
                "error": {
                    "code": "vice_timeout",
                    "message": "release timed out",
                },
            }
        return {"ok": True, "command_sequence": command, "result": {}}

    def resume(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("resume", dict(kwargs)))
        return {
            "ok": True,
            "command_sequence": 5,
            "result": {"event": {"sequence": 2, "kind": "resumed"}},
        }

    def wait_for_stop(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("wait", dict(kwargs)))
        self.after = True
        checkpoints = [{"number": 9}] if self.exact_hit else []
        return {
            "ok": True,
            "command_sequence": 6,
            "result": {
                "event": {
                    "sequence": 3,
                    "kind": "stopped",
                    "checkpoints": checkpoints,
                    "checkpoint": None,
                }
            },
        }

    def delete_checkpoint(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("delete", dict(kwargs)))
        return {"ok": True, "command_sequence": 9, "result": {}}


def test_transition_hits_exact_checkpoint_diffs_and_cleans_up(
    tmp_path: Path,
) -> None:
    vice = TransitionVice()
    manifest = tmp_path / "transition.json"

    result = capture_transition(
        vice,
        ranges=[
            {
                "name": "state",
                "bank_id": 1,
                "start": 0x2000,
                "end": 0x2003,
            }
        ],
        checkpoint_start=0xC000,
        checkpoint_end=0xC000,
        petscii="0d",
        joyport_port=2,
        joyport_value=0xEF,
        manifest_path=str(manifest),
    )

    assert result["ok"] is True
    assert result["changed_byte_count"] == 2
    assert result["changes"] == [
        {
            "name": "state",
            "start": 0x2001,
            "end": 0x2002,
            "byte_count": 2,
            "before": "0102",
            "after": "0506",
        }
    ]
    assert [name for name, _ in vice.calls] == [
        "capture",
        "checkpoint",
        "keyboard",
        "joyport",
        "resume",
        "wait",
        "capture",
        "joyport",
        "delete",
    ]
    assert vice.calls[1][1]["temporary"] is False
    assert vice.calls[-2][1]["value"] == 0xFF
    assert result["cleanup"]["checkpoint_delete"]["ok"] is True  # type: ignore[index]
    assert json.loads(manifest.read_text(encoding="utf-8"))["ok"] is True


def test_transition_uses_pre_resume_watermark_when_event_is_absent() -> None:
    class EventlessResumeVice(TransitionVice):
        def resume(self, **kwargs: object) -> dict[str, object]:
            self.calls.append(("resume", dict(kwargs)))
            return {
                "ok": True,
                "command_sequence": 5,
                "result": {},
            }

    vice = EventlessResumeVice()
    result = capture_transition(
        vice,
        ranges=[
            {
                "name": "state",
                "bank_id": 1,
                "start": 0x2000,
                "end": 0x2003,
            }
        ],
        checkpoint_start=0xC000,
        checkpoint_end=0xC000,
    )

    assert result["ok"] is True
    wait = next(arguments for name, arguments in vice.calls if name == "wait")
    assert wait["after_sequence"] == 1
    assert result["provenance"]["resumed_event"] is None  # type: ignore[index]


def test_transition_refuses_existing_manifest_before_vice(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "transition.json"
    manifest.write_text("keep", encoding="utf-8")
    vice = TransitionVice()

    result = capture_transition(
        vice,
        ranges=[],
        checkpoint_start=0xC000,
        checkpoint_end=0xC000,
        manifest_path=str(manifest),
    )

    assert result["error"]["code"] == "artifact_exists"  # type: ignore[index]
    assert vice.calls == []
    assert manifest.read_text(encoding="utf-8") == "keep"


def test_transition_refuses_missing_manifest_parent_before_vice(
    tmp_path: Path,
) -> None:
    vice = TransitionVice()

    result = capture_transition(
        vice,
        ranges=[],
        checkpoint_start=0xC000,
        checkpoint_end=0xC000,
        manifest_path=str(tmp_path / "missing" / "transition.json"),
    )

    assert result["error"]["code"] == "artifact_io_error"  # type: ignore[index]
    assert vice.calls == []


def test_transition_expands_home_in_manifest_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    result = capture_transition(
        TransitionVice(),
        ranges=[
            {
                "name": "state",
                "bank_id": 1,
                "start": 0x2000,
                "end": 0x2003,
            }
        ],
        checkpoint_start=0xC000,
        checkpoint_end=0xC000,
        manifest_path="~/transition.json",
    )

    assert result["ok"] is True
    assert result["manifest_path"] == str(tmp_path / "transition.json")


def test_transition_manifest_write_failure_is_top_level_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_write(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("c64_mcp.reversing.write_atomically", fail_write)
    result = capture_transition(
        TransitionVice(),
        ranges=[
            {
                "name": "state",
                "bank_id": 1,
                "start": 0x2000,
                "end": 0x2003,
            }
        ],
        checkpoint_start=0xC000,
        checkpoint_end=0xC000,
        manifest_path=str(tmp_path / "transition.json"),
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "artifact_io_error"  # type: ignore[index]


def test_transition_refuses_unrelated_stop_but_still_cleans_up() -> None:
    vice = TransitionVice(exact_hit=False)

    result = capture_transition(
        vice,
        ranges=[
            {
                "name": "state",
                "bank_id": 1,
                "start": 0x2000,
                "end": 0x2003,
            }
        ],
        checkpoint_start=0xC000,
        checkpoint_end=0xC000,
        joyport_port=1,
        joyport_value=0xFE,
    )

    assert result["error"]["code"] == "vice_unexpected_stop"  # type: ignore[index]
    assert [name for name, _ in vice.calls][-2:] == [
        "joyport",
        "delete",
    ]


def test_transition_reports_failed_input_cleanup() -> None:
    vice = TransitionVice(release_ok=False)

    result = capture_transition(
        vice,
        ranges=[
            {
                "name": "state",
                "bank_id": 1,
                "start": 0x2000,
                "end": 0x2003,
            }
        ],
        checkpoint_start=0xC000,
        checkpoint_end=0xC000,
        joyport_port=1,
        joyport_value=0xFE,
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "vice_cleanup_failed"  # type: ignore[index]
    assert result["error"]["operations"] == ["joyport_release"]  # type: ignore[index]


def test_transition_rejects_mutated_range_envelope() -> None:
    class MutatedRangeVice(TransitionVice):
        def capture_state(self, **kwargs: object) -> dict[str, object]:
            envelope = super().capture_state(**kwargs)
            result = envelope["result"]
            assert isinstance(result, dict)
            ranges = result["ranges"]
            assert isinstance(ranges, list)
            item = ranges[0]
            assert isinstance(item, dict)
            item["end"] = 0x2004
            return envelope

    result = capture_transition(
        MutatedRangeVice(),
        ranges=[
            {
                "name": "state",
                "bank_id": 1,
                "start": 0x2000,
                "end": 0x2003,
            }
        ],
        checkpoint_start=0xC000,
        checkpoint_end=0xC000,
    )

    assert result["error"]["code"] == "vice_connector_incompatible"  # type: ignore[index]


def test_thin_ghidra_reversing_tools_are_search_only() -> None:
    ghidra = ReversingGhidra()

    indexed = search_6502_indexed_operands(
        ghidra,
        program="game",
        target_start="RAM:2000",
        target_end="RAM:2FFF",
        source_start="RAM:1000",
        source_end="RAM:1FFF",
    )
    split = find_split_pointer_partners(
        ghidra,
        program="game",
        first_start="RAM:3000",
        count=16,
        partner_start="RAM:3100",
        partner_end="RAM:31FF",
        target_start="RAM:8000",
        target_end="RAM:8FFF",
    )

    assert indexed == {
        "operands": [{"instruction_address": "RAM:1000"}]
    }
    assert split == {
        "proposals": [{"first_start": "RAM:2000"}]
    }
