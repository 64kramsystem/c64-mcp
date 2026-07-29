"""Bounded C64 reversing workflows over public VICE and Ghidra contracts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast

from .errors import (
    GhidraError,
    GhidraTransportError,
    RequestError,
    ViceError,
)
from .graphics.tools import write_atomically
from .vice import (
    DEFAULT_TIMEOUT_MS,
    MAX_STATE_CAPTURE_BYTES,
    MAX_TIMEOUT_MS,
    BytesInput,
)

_PHASE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_HEX = re.compile(r"^[0-9a-f]*$")
_ROLE_RANGES = {
    "CPU": (0x0000, 0xFFFF),
    "RAM": (0x0000, 0xFFFF),
    "ROM": (0x0000, 0xFFFF),
    "IO": (0xD000, 0xDFFF),
}


class ReversingGhidraClient(Protocol):
    """Generic Ghidra operations used by the reversing workflows."""

    def apply_memory_image(
        self,
        program: str,
        blocks: list[dict[str, object]],
        metadata: Mapping[str, object],
        *,
        conflict_policy: str = "error",
        dry_run: bool = True,
        timeout_ms: int = 30_000,
    ) -> dict[str, object]: ...

    def search_6502_indexed_operands(
        self,
        program: str,
        *,
        target_start: str,
        target_end: str,
        source_start: str,
        source_end: str,
        limit: int = 1_000,
        offset: int = 0,
    ) -> dict[str, object]: ...

    def find_split_pointer_partners(
        self,
        program: str,
        *,
        first_start: str,
        count: int,
        partner_start: str,
        partner_end: str,
        target_start: str,
        target_end: str,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, object]: ...


class StateCaptureViceSession(Protocol):
    """Shared sequence-guarded VICE state capture operations."""

    def status(self) -> dict[str, object]: ...

    def capture_state(
        self,
        *,
        expected_event_sequence: int,
        expected_command_sequence: int,
        ranges: list[dict[str, object]],
        register_names: list[str] | None = None,
        include_checkpoints: bool = True,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]: ...


class PhaseViceSession(StateCaptureViceSession, Protocol):
    """VICE operations used by phase import."""

    def list_banks(
        self, *, timeout_ms: int = DEFAULT_TIMEOUT_MS
    ) -> dict[str, object]: ...


class TransitionViceSession(StateCaptureViceSession, Protocol):
    """VICE operations used by deterministic transition capture."""

    def set_checkpoint(
        self,
        *,
        start: int,
        end: int,
        stop_on_hit: bool = True,
        enabled: bool = True,
        operations: int = 4,
        temporary: bool = False,
        memspace: int = 0,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]: ...

    def feed_keyboard(
        self,
        *,
        data: BytesInput,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]: ...

    def set_joyport(
        self,
        *,
        port: int,
        value: int,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]: ...

    def resume(
        self, *, timeout_ms: int = DEFAULT_TIMEOUT_MS
    ) -> dict[str, object]: ...

    def wait_for_stop(
        self,
        *,
        after_sequence: int,
        timeout_ms: int,
    ) -> dict[str, object]: ...

    def delete_checkpoint(
        self,
        *,
        number: int,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]: ...


def search_6502_indexed_operands(
    ghidra: ReversingGhidraClient,
    *,
    program: str,
    target_start: str,
    target_end: str,
    source_start: str,
    source_end: str,
    limit: int = 1_000,
    offset: int = 0,
) -> dict[str, object]:
    """Search indexed operands without mutating the Ghidra program."""

    return ghidra.search_6502_indexed_operands(
        program,
        target_start=target_start,
        target_end=target_end,
        source_start=source_start,
        source_end=source_end,
        limit=limit,
        offset=offset,
    )


def find_split_pointer_partners(
    ghidra: ReversingGhidraClient,
    *,
    program: str,
    first_start: str,
    count: int,
    partner_start: str,
    partner_end: str,
    target_start: str,
    target_end: str,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, object]:
    """Find split-pointer partners without mutating the Ghidra program."""

    return ghidra.find_split_pointer_partners(
        program,
        first_start=first_start,
        count=count,
        partner_start=partner_start,
        partner_end=partner_end,
        target_start=target_start,
        target_end=target_end,
        limit=limit,
        offset=offset,
    )


def import_vice_phase(
    vice: PhaseViceSession,
    ghidra: ReversingGhidraClient,
    *,
    program: str,
    phase: str,
    output_dir: str,
    dry_run: bool = True,
    overwrite: bool = False,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ghidra_timeout_ms: int = 30_000,
) -> dict[str, object]:
    """Capture named C64 banks, persist evidence, and apply one Ghidra image."""

    try:
        program_name = _nonblank(program, "program")
        phase_name = _phase_name(phase)
        _require_boolean(dry_run, "dry_run")
        _require_boolean(overwrite, "overwrite")
        ghidra_timeout = _timeout_ms(
            ghidra_timeout_ms, "ghidra_timeout_ms"
        )
        directory = _prepare_output_directory(output_dir)
        artifact_paths = {
            role: directory / f"{phase_name}_{role}.bin"
            for role in _ROLE_RANGES
        }
        manifest_path = directory / f"{phase_name}_manifest.json"
        _preflight_outputs(
            [*artifact_paths.values(), manifest_path],
            overwrite=overwrite,
        )

        bank_envelope = _success(vice.list_banks(timeout_ms=timeout_ms))
        banks = _resolve_banks(bank_envelope)
        bank_command = _sequence(bank_envelope, "command_sequence")
        status = vice.status()
        if (
            status.get("state") != "stopped"
            or status.get("max_command_sequence") != bank_command
        ):
            raise ViceError(
                "vice_state_changed",
                "VICE state changed after bank discovery; retry the import",
            )
        event_sequence = _sequence(status, "last_event_sequence")
        command_sequence = bank_command

        captured: dict[str, bytes] = {}
        first_registers: list[object] | None = None
        first_checkpoints: list[object] | None = None
        capture_records: list[dict[str, object]] = []
        for role, (start, end) in _ROLE_RANGES.items():
            parts: list[bytes] = []
            bank = banks[role]
            for chunk_start in range(
                start, end + 1, MAX_STATE_CAPTURE_BYTES
            ):
                chunk_end = min(
                    end, chunk_start + MAX_STATE_CAPTURE_BYTES - 1
                )
                range_name = (
                    f"{role}_{chunk_start:04X}_{chunk_end:04X}"
                )
                capture = _success(
                    vice.capture_state(
                        expected_event_sequence=event_sequence,
                        expected_command_sequence=command_sequence,
                        ranges=[
                            {
                                "name": range_name,
                                "bank_id": bank["id"],
                                "memspace": 0,
                                "start": chunk_start,
                                "end": chunk_end,
                            }
                        ],
                        register_names=[],
                        include_checkpoints=True,
                        timeout_ms=timeout_ms,
                    )
                )
                result = _result(capture)
                command_sequence = _sequence(
                    capture, "command_sequence"
                )
                event_sequence = _sequence(result, "event_sequence")
                registers = _array(result, "registers")
                checkpoints = _array(result, "checkpoints")
                if first_registers is None:
                    first_registers = list(registers)
                    first_checkpoints = list(checkpoints)
                elif (
                    registers != first_registers
                    or checkpoints != first_checkpoints
                ):
                    raise ViceError(
                        "vice_state_changed",
                        "registers or checkpoints changed within a stopped "
                        "phase capture; retry the import",
                    )
                item, data = _captured_range(
                    result,
                    name=range_name,
                    bank_id=cast(int, bank["id"]),
                    start=chunk_start,
                    end=chunk_end,
                )
                parts.append(data)
                capture_records.append(
                    {
                        "role": role,
                        "name": range_name,
                        "start": chunk_start,
                        "end": chunk_end,
                        "byte_count": len(data),
                        "sha256": item["sha256"],
                        "command_sequence": command_sequence,
                        "event_sequence": event_sequence,
                    }
                )
            captured[role] = b"".join(parts)

        artifacts: list[dict[str, object]] = []
        for role, path in artifact_paths.items():
            data = captured[role]
            write_atomically(path, data, overwrite)
            artifacts.append(
                {
                    "role": role,
                    "filename": path.name,
                    "byte_count": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )

        provenance = {
            "schema": "c64-mcp/vice-phase-1",
            "phase": phase_name,
            "banks": banks,
            "registers": first_registers or [],
            "checkpoints": first_checkpoints or [],
            "captures": capture_records,
            "final_command_sequence": command_sequence,
            "final_event_sequence": event_sequence,
            "artifacts": artifacts,
        }
        blocks = [
            _memory_block(phase_name, role, captured[role])
            for role in _ROLE_RANGES
        ]
        ghidra_metadata = {
            "schema": "c64-mcp/vice-phase-1",
            "phase": phase_name,
            "manifest": manifest_path.name,
            "capture": json.dumps(
                provenance, sort_keys=True, separators=(",", ":")
            ),
        }
        try:
            apply_result = ghidra.apply_memory_image(
                program_name,
                blocks,
                ghidra_metadata,
                conflict_policy=(
                    "replace_exact" if overwrite else "error"
                ),
                dry_run=dry_run,
                timeout_ms=ghidra_timeout,
            )
            ghidra_record: dict[str, object] = {
                "ok": True,
                "result": apply_result,
            }
        except GhidraTransportError as error:
            ghidra_record = {
                "ok": False,
                "error": {
                    "code": error.code,
                    "message": str(error),
                    "timeout_layer": error.timeout_layer,
                    "outcome_unknown": error.outcome_unknown,
                    "request_committed": error.request_committed,
                },
            }
        except GhidraError as error:
            ghidra_record = {
                "ok": False,
                "error": {
                    "code": "ghidra_response_error",
                    "message": str(error),
                },
            }
        manifest = {
            **provenance,
            "program": program_name,
            "dry_run": dry_run,
            "overwrite": overwrite,
            "ghidra": ghidra_record,
        }
        write_atomically(
            manifest_path,
            (
                json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8"),
            overwrite,
        )
        summary = {
            "ok": ghidra_record["ok"],
            "phase": phase_name,
            "program": program_name,
            "manifest_path": str(manifest_path),
            "artifacts": artifacts,
            "banks": banks,
            "final_command_sequence": command_sequence,
            "final_event_sequence": event_sequence,
            "ghidra": ghidra_record,
        }
        if ghidra_record["ok"] is False:
            summary["error"] = ghidra_record["error"]
        return summary
    except ViceError as error:
        return error.as_result()
    except (OSError, RequestError) as error:
        return {
            "ok": False,
            "error": {
                "code": "artifact_io_error",
                "message": str(error),
            },
        }


def capture_transition(
    vice: TransitionViceSession,
    *,
    ranges: list[dict[str, object]],
    checkpoint_start: int,
    checkpoint_end: int,
    checkpoint_operations: int = 4,
    checkpoint_memspace: int = 0,
    petscii: BytesInput | None = None,
    joyport_port: int | None = None,
    joyport_value: int | None = None,
    register_names: list[str] | None = None,
    manifest_path: str | None = None,
    overwrite: bool = False,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> dict[str, object]:
    """Capture a deterministic before/after transition around one checkpoint."""

    checkpoint_number: int | None = None
    joystick_armed = False
    cleanup: dict[str, object] = {
        "joyport_release": None,
        "checkpoint_delete": None,
    }
    provenance: dict[str, object] = {}
    manifest_target: Path | None = None
    vice_touched = False
    try:
        _require_boolean(overwrite, "overwrite")
        if manifest_path is not None:
            candidate = Path(
                _nonblank(manifest_path, "manifest_path")
            ).expanduser()
            _require_existing_writable_parent(candidate)
            _preflight_outputs([candidate], overwrite=overwrite)
            manifest_target = candidate
        if (joyport_port is None) != (joyport_value is None):
            raise ViceError(
                "vice_invalid_argument",
                "joyport_port and joyport_value must be provided together",
            )
        vice_touched = True
        status = vice.status()
        if status.get("state") != "stopped":
            raise ViceError(
                "vice_not_stopped",
                "VICE must be stopped before transition capture",
            )
        command_sequence = _sequence(status, "max_command_sequence")
        event_sequence = _sequence(status, "last_event_sequence")

        before = _success(
            vice.capture_state(
                expected_event_sequence=event_sequence,
                expected_command_sequence=command_sequence,
                ranges=ranges,
                register_names=register_names,
                include_checkpoints=True,
                timeout_ms=timeout_ms,
            )
        )
        before_result = _result(before)
        command_sequence = _sequence(
            before, "command_sequence"
        )
        event_sequence = _sequence(before_result, "event_sequence")

        checkpoint = _success(
            vice.set_checkpoint(
                start=checkpoint_start,
                end=checkpoint_end,
                stop_on_hit=True,
                enabled=True,
                operations=checkpoint_operations,
                temporary=False,
                memspace=checkpoint_memspace,
                timeout_ms=timeout_ms,
            )
        )
        checkpoint_result = _result(checkpoint)
        checkpoint_record = checkpoint_result.get("checkpoint")
        if not isinstance(checkpoint_record, Mapping):
            raise _incompatible("checkpoint creation omitted checkpoint")
        checkpoint_number = _sequence(
            checkpoint_record, "number"
        )
        command_sequence = _sequence(checkpoint, "command_sequence")

        if petscii is not None:
            fed = _success(
                vice.feed_keyboard(data=petscii, timeout_ms=timeout_ms)
            )
            command_sequence = _sequence(fed, "command_sequence")
        if joyport_port is not None and joyport_value is not None:
            armed = _success(
                vice.set_joyport(
                    port=joyport_port,
                    value=joyport_value,
                    timeout_ms=timeout_ms,
                )
            )
            command_sequence = _sequence(armed, "command_sequence")
            joystick_armed = True

        resumed = _success(vice.resume(timeout_ms=timeout_ms))
        command_sequence = _sequence(resumed, "command_sequence")
        resumed_event = _optional_event(_result(resumed))
        resumed_sequence = (
            event_sequence
            if resumed_event is None
            else _sequence(resumed_event, "sequence")
        )
        stopped = _success(
            vice.wait_for_stop(
                after_sequence=resumed_sequence,
                timeout_ms=timeout_ms,
            )
        )
        command_sequence = _sequence(stopped, "command_sequence")
        stopped_event = _event(_result(stopped))
        event_sequence = _sequence(stopped_event, "sequence")
        if checkpoint_number not in _checkpoint_numbers(stopped_event):
            raise ViceError(
                "vice_unexpected_stop",
                "VICE stopped without hitting the transition checkpoint",
                expected_checkpoint=checkpoint_number,
                event=stopped_event,
            )
        after = _success(
            vice.capture_state(
                expected_event_sequence=event_sequence,
                expected_command_sequence=command_sequence,
                ranges=ranges,
                register_names=register_names,
                include_checkpoints=True,
                timeout_ms=timeout_ms,
            )
        )
        after_result = _result(after)
        provenance = {
            "checkpoint": checkpoint_record,
            "resumed_event": resumed_event,
            "stopped_event": stopped_event,
            "before_command_sequence": _sequence(
                before, "command_sequence"
            ),
            "after_command_sequence": _sequence(
                after, "command_sequence"
            ),
            "before_event_sequence": _sequence(
                before_result, "event_sequence"
            ),
            "after_event_sequence": _sequence(
                after_result, "event_sequence"
            ),
        }
        summary = _transition_summary(before_result, after_result)
    except ViceError as error:
        failure = error.as_result()
        summary = failure
    finally:
        if joystick_armed and joyport_port is not None:
            cleanup["joyport_release"] = vice.set_joyport(
                port=joyport_port,
                value=0xFF,
                timeout_ms=timeout_ms,
            )
        if checkpoint_number is not None:
            cleanup["checkpoint_delete"] = vice.delete_checkpoint(
                number=checkpoint_number,
                timeout_ms=timeout_ms,
            )

    if vice_touched:
        cleanup["final_status"] = vice.status()
    summary["cleanup"] = cleanup
    summary["provenance"] = provenance
    failed_cleanup = [
        name
        for name, value in cleanup.items()
        if isinstance(value, Mapping) and value.get("ok") is False
    ]
    if summary.get("ok") is True and failed_cleanup:
        summary["ok"] = False
        summary["error"] = {
            "code": "vice_cleanup_failed",
            "message": "transition captured but cleanup failed",
            "operations": failed_cleanup,
        }
    if manifest_target is not None:
        try:
            write_atomically(
                manifest_target,
                (
                    json.dumps(summary, indent=2, sort_keys=True) + "\n"
                ).encode("utf-8"),
                overwrite,
            )
            summary["manifest_path"] = str(manifest_target)
        except (OSError, RequestError) as error:
            prior_error = summary.get("error")
            summary["ok"] = False
            artifact_error: dict[str, object] = {
                "code": "artifact_io_error",
                "message": str(error),
            }
            if prior_error is not None:
                artifact_error["prior_error"] = prior_error
            summary["error"] = artifact_error
    return summary


def _resolve_banks(envelope: Mapping[str, object]) -> dict[str, dict[str, object]]:
    records = _array(_result(envelope), "banks")
    by_name: dict[str, list[dict[str, object]]] = {}
    for item in records:
        if not isinstance(item, Mapping):
            raise _incompatible("bank list contains a non-object")
        name = item.get("name")
        bank_id = item.get("id")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(bank_id, int)
            or isinstance(bank_id, bool)
            or bank_id < 0
        ):
            raise _incompatible("bank list contains an invalid bank record")
        by_name.setdefault(name, []).append({"name": name, "id": bank_id})

    resolved: dict[str, dict[str, object]] = {}
    defaults = by_name.get("default", [])
    cpus = by_name.get("cpu", [])
    if len(defaults) == 1:
        selected = defaults[0]
    elif not defaults and len(cpus) == 1:
        selected = cpus[0]
    else:
        raise ViceError(
            "vice_bank_mapping_ambiguous",
            "CPU bank requires one exact default name, or one cpu fallback",
            default_candidates=defaults,
            cpu_candidates=cpus,
        )
    resolved["CPU"] = {
        **selected,
        "aliases": [
            item["name"] for item in [*defaults, *cpus]
        ],
    }
    for role, name in (("RAM", "ram"), ("ROM", "rom"), ("IO", "io")):
        candidates = by_name.get(name, [])
        if len(candidates) != 1:
            raise ViceError(
                "vice_bank_mapping_ambiguous",
                f"{role} bank requires exactly one bank named {name}",
                role=role,
                name=name,
                candidates=candidates,
            )
        resolved[role] = candidates[0]
    return resolved


def _memory_block(
    phase: str, role: str, data: bytes
) -> dict[str, object]:
    start, _ = _ROLE_RANGES[role]
    writable = role != "ROM"
    executable = role != "IO"
    return {
        "name": f"{phase}_{role}",
        "start": f"RAM:{start:04X}",
        "overlay": True,
        "bytes": data.hex(),
        "read": True,
        "write": writable,
        "execute": executable,
        "volatile": role == "IO",
        "comment": f"{phase} VICE {role} capture",
    }


def _captured_range(
    result: Mapping[str, object],
    *,
    name: str,
    bank_id: int,
    start: int,
    end: int,
) -> tuple[Mapping[str, object], bytes]:
    ranges = _array(result, "ranges")
    if len(ranges) != 1 or not isinstance(ranges[0], Mapping):
        raise _incompatible("capture returned the wrong range count")
    item = cast(Mapping[str, object], ranges[0])
    raw = item.get("bytes")
    expected_length = end - start + 1
    if (
        item.get("name") != name
        or item.get("bank_id") != bank_id
        or item.get("memspace") != 0
        or item.get("start") != start
        or item.get("end") != end
        or item.get("byte_count") != expected_length
        or not isinstance(raw, str)
        or len(raw) != expected_length * 2
        or _HEX.fullmatch(raw) is None
    ):
        raise _incompatible("capture range metadata or bytes are inconsistent")
    data = bytes.fromhex(raw)
    digest = hashlib.sha256(data).hexdigest()
    if item.get("sha256") != digest:
        raise _incompatible("capture range SHA-256 does not match its bytes")
    return item, data


def _transition_summary(
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> dict[str, object]:
    before_registers = _array(before, "registers")
    after_registers = _array(after, "registers")
    before_by_name = _capture_range_map(before)
    after_by_name = _capture_range_map(after)
    if before_by_name.keys() != after_by_name.keys():
        raise _incompatible("before/after capture range names disagree")
    ranges: list[dict[str, object]] = []
    changes: list[dict[str, object]] = []
    for name in before_by_name:
        before_item, before_data = before_by_name[name]
        after_item, after_data = after_by_name[name]
        if (
            before_item.get("start") != after_item.get("start")
            or before_item.get("end") != after_item.get("end")
            or before_item.get("bank_id") != after_item.get("bank_id")
            or before_item.get("memspace") != after_item.get("memspace")
        ):
            raise _incompatible(
                f"before/after metadata disagrees for range {name}"
            )
        ranges.append(
            {
                "name": name,
                "bank_id": before_item["bank_id"],
                "memspace": before_item["memspace"],
                "start": before_item["start"],
                "end": before_item["end"],
                "before_sha256": before_item["sha256"],
                "after_sha256": after_item["sha256"],
                "changed": before_data != after_data,
            }
        )
        base = cast(int, before_item["start"])
        changes.extend(
            _coalesced_changes(name, base, before_data, after_data)
        )
    return {
        "ok": True,
        "registers": {
            "before_sha256": _json_sha256(before_registers),
            "after_sha256": _json_sha256(after_registers),
            "changed": before_registers != after_registers,
            "before": before_registers,
            "after": after_registers,
        },
        "ranges": ranges,
        "changes": changes,
        "changed_byte_count": sum(
            cast(int, item["byte_count"]) for item in changes
        ),
    }


def _capture_range_map(
    result: Mapping[str, object],
) -> dict[str, tuple[Mapping[str, object], bytes]]:
    found: dict[str, tuple[Mapping[str, object], bytes]] = {}
    for raw_item in _array(result, "ranges"):
        if not isinstance(raw_item, Mapping):
            raise _incompatible("capture range is not an object")
        item = cast(Mapping[str, object], raw_item)
        name = item.get("name")
        raw = item.get("bytes")
        digest = item.get("sha256")
        bank_id = item.get("bank_id")
        memspace = item.get("memspace")
        start = item.get("start")
        end = item.get("end")
        if (
            not isinstance(name, str)
            or not name
            or name in found
            or not isinstance(bank_id, int)
            or isinstance(bank_id, bool)
            or bank_id < 0
            or not isinstance(memspace, int)
            or isinstance(memspace, bool)
            or memspace < 0
            or not isinstance(start, int)
            or isinstance(start, bool)
            or not 0 <= start <= 0xFFFF
            or not isinstance(end, int)
            or isinstance(end, bool)
            or not start <= end <= 0xFFFF
            or not isinstance(raw, str)
            or len(raw) % 2
            or _HEX.fullmatch(raw) is None
            or not isinstance(digest, str)
            or len(digest) != 64
            or _HEX.fullmatch(digest) is None
        ):
            raise _incompatible("capture range envelope is invalid")
        data = bytes.fromhex(raw)
        if (
            item.get("byte_count") != len(data)
            or len(data) != end - start + 1
            or digest != hashlib.sha256(data).hexdigest()
        ):
            raise _incompatible("capture range byte count or digest is invalid")
        found[name] = (item, data)
    return found


def _coalesced_changes(
    name: str, base: int, before: bytes, after: bytes
) -> list[dict[str, object]]:
    if len(before) != len(after):
        raise _incompatible(f"before/after lengths disagree for range {name}")
    result: list[dict[str, object]] = []
    index = 0
    while index < len(before):
        if before[index] == after[index]:
            index += 1
            continue
        start = index
        while index < len(before) and before[index] != after[index]:
            index += 1
        result.append(
            {
                "name": name,
                "start": base + start,
                "end": base + index - 1,
                "byte_count": index - start,
                "before": before[start:index].hex(),
                "after": after[start:index].hex(),
            }
        )
    return result


def _success(value: Mapping[str, object]) -> Mapping[str, object]:
    if value.get("ok") is True:
        return value
    error = value.get("error")
    if isinstance(error, Mapping):
        raise ViceError.from_mapping(
            error,
            fallback_code="vice_operation_failed",
            fallback_message="VICE operation failed",
        )
    raise ViceError("vice_operation_failed", "VICE operation failed")


def _result(value: Mapping[str, object]) -> Mapping[str, object]:
    result = value.get("result")
    if not isinstance(result, Mapping):
        raise _incompatible("connector result must be an object")
    return cast(Mapping[str, object], result)


def _event(value: Mapping[str, object]) -> Mapping[str, object]:
    event = value.get("event")
    if not isinstance(event, Mapping):
        raise _incompatible("execution result omitted its event")
    return cast(Mapping[str, object], event)


def _optional_event(
    value: Mapping[str, object],
) -> Mapping[str, object] | None:
    event = value.get("event")
    if event is None:
        return None
    if not isinstance(event, Mapping):
        raise _incompatible("execution result event must be an object")
    return cast(Mapping[str, object], event)


def _checkpoint_numbers(event: Mapping[str, object]) -> set[int]:
    values: set[int] = set()
    checkpoint = event.get("checkpoint")
    if isinstance(checkpoint, Mapping):
        number = checkpoint.get("number")
        if isinstance(number, int) and not isinstance(number, bool):
            values.add(number)
    checkpoints = event.get("checkpoints")
    if isinstance(checkpoints, list):
        for item in checkpoints:
            if isinstance(item, Mapping):
                number = item.get("number")
                if isinstance(number, int) and not isinstance(number, bool):
                    values.add(number)
    return values


def _array(value: Mapping[str, object], field: str) -> list[object]:
    found = value.get(field)
    if not isinstance(found, list):
        raise _incompatible(f"connector result omitted {field} array")
    return found


def _sequence(value: Mapping[str, object], field: str) -> int:
    found = value.get(field)
    if (
        not isinstance(found, int)
        or isinstance(found, bool)
        or found < 0
    ):
        raise _incompatible(f"connector result omitted integer {field}")
    return found


def _phase_name(value: object) -> str:
    if not isinstance(value, str) or _PHASE.fullmatch(value) is None:
        raise ViceError(
            "vice_invalid_argument",
            "phase must start with a letter and contain at most 64 ASCII "
            "letters, digits, or underscores",
        )
    return value.upper()


def _nonblank(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ViceError(
            "vice_invalid_argument", f"{field} must not be blank"
        )
    return value


def _timeout_ms(value: object, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= MAX_TIMEOUT_MS
    ):
        raise ViceError(
            "vice_invalid_argument",
            f"{field} must be from 1 to {MAX_TIMEOUT_MS}",
        )
    return value


def _prepare_output_directory(value: object) -> Path:
    directory = Path(_nonblank(value, "output_dir")).expanduser()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        if not directory.is_dir():
            raise OSError(f"output_dir {directory} is not a directory")
        _probe_writable_directory(directory)
    except OSError as error:
        raise ViceError(
            "artifact_io_error",
            f"cannot prepare output_dir {directory}: {error}",
        ) from error
    return directory


def _require_existing_writable_parent(target: Path) -> None:
    parent = target.parent
    if not parent.is_dir():
        raise ViceError(
            "artifact_io_error",
            f"manifest directory {parent} does not exist",
        )
    try:
        _probe_writable_directory(parent)
    except OSError as error:
        raise ViceError(
            "artifact_io_error",
            f"manifest directory {parent} is not writable: {error}",
        ) from error


def _probe_writable_directory(directory: Path) -> None:
    descriptor, temporary = tempfile.mkstemp(
        dir=str(directory), prefix=".c64-mcp-write-", suffix=".part"
    )
    os.close(descriptor)
    os.unlink(temporary)


def _require_boolean(value: object, field: str) -> None:
    if not isinstance(value, bool):
        raise ViceError(
            "vice_invalid_argument", f"{field} must be a boolean"
        )


def _preflight_outputs(
    paths: list[Path], *, overwrite: bool
) -> None:
    if len(set(paths)) != len(paths):
        raise ViceError(
            "artifact_path_conflict", "output paths must be distinct"
        )
    directories = [str(path) for path in paths if path.is_dir()]
    if directories:
        raise ViceError(
            "artifact_io_error",
            "output artifact path is a directory",
            paths=directories,
        )
    if not overwrite:
        existing = [str(path) for path in paths if path.exists()]
        if existing:
            raise ViceError(
                "artifact_exists",
                "output artifact already exists",
                paths=existing,
            )


def _json_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _incompatible(message: str) -> ViceError:
    return ViceError("vice_connector_incompatible", message)
