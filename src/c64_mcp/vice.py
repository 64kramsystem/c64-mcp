"""Public C64 orchestration over the connector-owned VICE session."""

from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from .errors import GhidraError, GhidraTransportError, ViceError
from .vice_contract import (
    CapabilityInfo,
    parse_connector_envelope,
    parse_handshake_envelope,
    validate_capabilities,
    validate_discovery,
)

PROCESS_ARGUMENT = {"object_path": "C64"}
DEFAULT_TIMEOUT_MS = 10_000
MAX_TIMEOUT_MS = 55_000
MAX_MEMORY_BYTES = 16_384
MAX_COPY_BYTES = 65_536
MAX_KEYBOARD_BYTES = 255
MAX_DISPLAY_CAPTURE_CHUNK_BYTES = 16_384
_LOWER_HEX = re.compile(r"^[0-9a-f]*$")

BytesInput = str | list[int]


class ViceGhidraClient(Protocol):
    """Only the public generic-Ghidra operations used by this module."""

    def target_methods(self) -> dict[str, object]: ...

    def invoke_target_method(
        self,
        target_token: str,
        method: str,
        arguments: Mapping[str, object],
        *,
        connector_timeout_ms: int,
    ) -> dict[str, object]: ...

    def write_memory_bytes_result(
        self,
        program: str,
        start: str,
        data: str,
        *,
        dry_run: bool = True,
        conflict_policy: str = "error",
    ) -> dict[str, object]: ...


@dataclass
class _Binding:
    token: str
    instance_id: str
    connector_name: str
    connector_version: str
    vice_version: str
    connection_state: str
    execution_state: str
    stop_count: int = 0
    last_pc: int | None = None


@dataclass(frozen=True)
class _Capture:
    token: str
    instance_id: str


class ViceSession:
    """Race-safe binding to one active connector target and instance."""

    def __init__(self, ghidra: ViceGhidraClient) -> None:
        self._ghidra = ghidra
        self._lock = threading.RLock()
        self._connect_lock = threading.Lock()
        self._binding: _Binding | None = None

    def connect(self) -> dict[str, object]:
        """Validate and bind; never launch VICE or open a monitor socket."""

        try:
            return self._connect()
        except GhidraTransportError as error:
            return _transport_error(error, mutation_flag=None).as_result()
        except GhidraError as error:
            return _ghidra_response_error(error, mutation_flag=None).as_result()
        except ViceError as error:
            return error.as_result()

    def _connect(self) -> dict[str, object]:
        with self._connect_lock:
            with self._lock:
                if self._binding is not None:
                    return self._status_locked(idempotent=True)
            discovery = self._ghidra.target_methods()
            token = validate_discovery(discovery)
            capabilities_invocation = self._ghidra.invoke_target_method(
                token,
                "c64_vice_v1_capabilities",
                {"process": dict(PROCESS_ARGUMENT)},
                connector_timeout_ms=DEFAULT_TIMEOUT_MS,
            )
            capabilities_envelope = parse_handshake_envelope(capabilities_invocation)
            info = validate_capabilities(capabilities_envelope)

            status_invocation = self._ghidra.invoke_target_method(
                token,
                "c64_vice_v1_status",
                {"process": dict(PROCESS_ARGUMENT)},
                connector_timeout_ms=DEFAULT_TIMEOUT_MS,
            )
            status_envelope = parse_connector_envelope(
                status_invocation,
                expected_instance=info.instance_id,
            )
            candidate = _binding_from_handshake(token, info, status_envelope)

            with self._lock:
                self._binding = candidate
                return self._status_locked(idempotent=False)

    def disconnect(self) -> dict[str, object]:
        """Release only this process's binding, leaving connector ownership alone."""

        with self._connect_lock, self._lock:
            had_binding = self._binding is not None
            self._binding = None
            return {
                "ok": True,
                "state": "unbound",
                "released": had_binding,
                "connector_externally_owned": True,
            }

    def status(self) -> dict[str, object]:
        """Return cached local state without discovery, binding, or HTTP."""

        with self._lock:
            return self._status_locked(idempotent=None)

    def get_registers(
        self,
        *,
        names: list[str] | None = None,
        memspace: int = 0,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        try:
            selected = [] if names is None else _string_list(names, "names")
            return self._operation_result(
                "c64_vice_v1_get_registers",
                {
                    "names": selected,
                    "memspace": _nonnegative(memspace, "memspace"),
                },
                timeout_ms=timeout_ms,
                mutation_flag=None,
            )
        except ViceError as error:
            return error.as_result()

    def set_registers(
        self,
        *,
        values: Mapping[str, int],
        memspace: int = 0,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        try:
            if not isinstance(values, Mapping) or not values:
                raise _invalid("values must be a non-empty name-to-integer map")
            names: list[str] = []
            numbers: list[int] = []
            for name, value in values.items():
                if not isinstance(name, str) or not name:
                    raise _invalid("register names must be nonblank strings")
                names.append(name)
                numbers.append(_integer(value, f"register {name}"))
            return self._operation_result(
                "c64_vice_v1_set_registers",
                {
                    "names": names,
                    "values": numbers,
                    "memspace": _nonnegative(memspace, "memspace"),
                },
                timeout_ms=timeout_ms,
                mutation_flag="vice_registers_may_have_changed",
            )
        except ViceError as error:
            return error.as_result()

    def list_banks(self, *, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict[str, object]:
        return self._public_operation(
            "c64_vice_v1_list_banks", {}, timeout_ms=timeout_ms
        )

    def read_memory(
        self,
        *,
        bank_id: int,
        start: int,
        end: int,
        side_effects: bool = False,
        max_bytes: int = 4096,
        memspace: int = 0,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        try:
            begin, finish = _address_range(start, end)
            maximum = _bounded(
                max_bytes, "max_bytes", minimum=1, maximum=MAX_MEMORY_BYTES
            )
            return self._operation_result(
                "c64_vice_v1_read_memory",
                {
                    "bank_id": _nonnegative(bank_id, "bank_id"),
                    "start": begin,
                    "end": finish,
                    "side_effects": _boolean(side_effects, "side_effects"),
                    "max_bytes": maximum,
                    "memspace": _nonnegative(memspace, "memspace"),
                },
                timeout_ms=timeout_ms,
                mutation_flag=("vice_state_may_have_changed" if side_effects else None),
            )
        except ViceError as error:
            return error.as_result()

    def write_memory(
        self,
        *,
        bank_id: int,
        start: int,
        bytes: BytesInput,
        side_effects: bool = False,
        memspace: int = 0,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        try:
            begin = _address(start, "start")
            data = _bytes(bytes)
            if not data:
                raise _invalid("bytes must not be empty")
            if len(data) > MAX_MEMORY_BYTES or begin + len(data) > 0x10000:
                raise _invalid(
                    "bytes must fit a non-wrapping 16-bit range of at most 16384"
                )
            return self._operation_result(
                "c64_vice_v1_write_memory",
                {
                    "bank_id": _nonnegative(bank_id, "bank_id"),
                    "start": begin,
                    "data": {"encoding": "hex", "data": data.hex()},
                    "side_effects": _boolean(side_effects, "side_effects"),
                    "memspace": _nonnegative(memspace, "memspace"),
                },
                timeout_ms=timeout_ms,
                mutation_flag="vice_memory_may_be_modified",
            )
        except ViceError as error:
            return error.as_result()

    def list_checkpoints(
        self, *, timeout_ms: int = DEFAULT_TIMEOUT_MS
    ) -> dict[str, object]:
        return self._public_operation(
            "c64_vice_v1_list_checkpoints", {}, timeout_ms=timeout_ms
        )

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
    ) -> dict[str, object]:
        try:
            begin, finish = _address_range(start, end)
            return self._operation_result(
                "c64_vice_v1_set_checkpoint",
                {
                    "start": begin,
                    "end": finish,
                    "stop_on_hit": _boolean(stop_on_hit, "stop_on_hit"),
                    "enabled": _boolean(enabled, "enabled"),
                    "operations": _bounded(
                        operations,
                        "operations",
                        minimum=1,
                        maximum=7,
                    ),
                    "temporary": _boolean(temporary, "temporary"),
                    "memspace": _nonnegative(memspace, "memspace"),
                },
                timeout_ms=timeout_ms,
                mutation_flag="vice_checkpoints_may_have_changed",
            )
        except ViceError as error:
            return error.as_result()

    def delete_checkpoint(
        self,
        *,
        number: int,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        try:
            return self._operation_result(
                "c64_vice_v1_delete_checkpoint",
                {"number": _nonnegative(number, "number")},
                timeout_ms=timeout_ms,
                mutation_flag="vice_checkpoints_may_have_changed",
            )
        except ViceError as error:
            return error.as_result()

    def toggle_checkpoint(
        self,
        *,
        number: int,
        enabled: bool,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        try:
            return self._operation_result(
                "c64_vice_v1_toggle_checkpoint",
                {
                    "number": _nonnegative(number, "number"),
                    "enabled": _boolean(enabled, "enabled"),
                },
                timeout_ms=timeout_ms,
                mutation_flag="vice_checkpoints_may_have_changed",
            )
        except ViceError as error:
            return error.as_result()

    def step(
        self, *, count: int = 1, timeout_ms: int = DEFAULT_TIMEOUT_MS
    ) -> dict[str, object]:
        return self._counted_execution("c64_vice_v1_step", count, timeout_ms)

    def next(
        self, *, count: int = 1, timeout_ms: int = DEFAULT_TIMEOUT_MS
    ) -> dict[str, object]:
        return self._counted_execution("c64_vice_v1_next", count, timeout_ms)

    def finish(self, *, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict[str, object]:
        return self._public_operation(
            "c64_vice_v1_finish",
            {},
            timeout_ms=timeout_ms,
            mutation_flag="vice_state_may_have_changed",
        )

    def resume(self, *, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict[str, object]:
        return self._public_operation(
            "c64_vice_v1_resume",
            {},
            timeout_ms=timeout_ms,
            mutation_flag="vice_state_may_have_changed",
        )

    def interrupt(self, *, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict[str, object]:
        return self._public_operation(
            "c64_vice_v1_interrupt",
            {},
            timeout_ms=timeout_ms,
            mutation_flag="vice_state_may_have_changed",
        )

    def wait_for_stop(
        self,
        *,
        after_stop_count: int,
        timeout_ms: int,
    ) -> dict[str, object]:
        try:
            return self._operation_result(
                "c64_vice_v1_wait_for_stop",
                {
                    "after_stop_count": _nonnegative(
                        after_stop_count, "after_stop_count"
                    )
                },
                timeout_ms=timeout_ms,
                mutation_flag=None,
            )
        except ViceError as error:
            return error.as_result()

    def reset(
        self,
        *,
        kind: str = "soft",
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        if kind not in {"soft", "hard"}:
            return _invalid("kind must be soft or hard").as_result()
        return self._public_operation(
            "c64_vice_v1_reset",
            {"kind": kind},
            timeout_ms=timeout_ms,
            mutation_flag="vice_state_may_have_changed",
        )

    def capture_display(
        self,
        *,
        use_vic: bool = True,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        """Capture one composited frame and its palette from the connector.

        The connector requires a stopped target and returns the raw indexed
        buffer; nothing here decodes or renders it.
        """

        try:
            return self._operation_result(
                "c64_vice_v1_capture_display",
                {"use_vic": _boolean(use_vic, "use_vic")},
                timeout_ms=timeout_ms,
                mutation_flag=None,
            )
        except ViceError as error:
            return error.as_result()

    def read_display_capture(
        self,
        *,
        capture_id: str,
        offset: int,
        max_bytes: int = MAX_DISPLAY_CAPTURE_CHUNK_BYTES,
    ) -> dict[str, object]:
        try:
            return self._operation_result(
                "c64_vice_v1_read_display_capture",
                {
                    "capture_id": _nonblank(capture_id, "capture_id"),
                    "offset": _nonnegative(offset, "offset"),
                    "max_bytes": _bounded(
                        max_bytes,
                        "max_bytes",
                        minimum=1,
                        maximum=MAX_DISPLAY_CAPTURE_CHUNK_BYTES,
                    ),
                },
                timeout_ms=DEFAULT_TIMEOUT_MS,
                mutation_flag=None,
                include_timeout_argument=False,
            )
        except ViceError as error:
            return error.as_result()

    def discard_display_capture(self, *, capture_id: str) -> dict[str, object]:
        try:
            return self._operation_result(
                "c64_vice_v1_discard_display_capture",
                {"capture_id": _nonblank(capture_id, "capture_id")},
                timeout_ms=DEFAULT_TIMEOUT_MS,
                mutation_flag="vice_display_capture_may_have_changed",
                include_timeout_argument=False,
            )
        except ViceError as error:
            return error.as_result()

    def feed_keyboard(
        self,
        *,
        data: BytesInput,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        try:
            payload = _bytes(data)
            if not 1 <= len(payload) <= MAX_KEYBOARD_BYTES:
                raise _invalid("data must contain 1 to 255 bytes")
            return self._operation_result(
                "c64_vice_v1_feed_keyboard",
                {"data": {"encoding": "hex", "data": payload.hex()}},
                timeout_ms=timeout_ms,
                mutation_flag="vice_input_may_have_changed",
            )
        except ViceError as error:
            return error.as_result()

    def set_joyport(
        self,
        *,
        port: int,
        value: int,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        try:
            return self._operation_result(
                "c64_vice_v1_set_joyport",
                {
                    "port": _bounded(port, "port", minimum=1, maximum=2),
                    "value": _bounded(value, "value", minimum=0, maximum=255),
                },
                timeout_ms=timeout_ms,
                mutation_flag="vice_input_may_have_changed",
            )
        except ViceError as error:
            return error.as_result()

    def save_snapshot(
        self,
        *,
        filename: str,
        save_roms: bool = False,
        save_disks: bool = True,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        try:
            return self._operation_result(
                "c64_vice_v1_save_snapshot",
                {
                    "filename": _nonblank(filename, "filename"),
                    "save_roms": _boolean(save_roms, "save_roms"),
                    "save_disks": _boolean(save_disks, "save_disks"),
                },
                timeout_ms=timeout_ms,
                mutation_flag="vice_snapshot_file_may_have_changed",
            )
        except ViceError as error:
            return error.as_result()

    def load_snapshot(
        self,
        *,
        filename: str,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        try:
            return self._operation_result(
                "c64_vice_v1_load_snapshot",
                {"filename": _nonblank(filename, "filename")},
                timeout_ms=timeout_ms,
                mutation_flag="vice_state_may_have_changed",
            )
        except ViceError as error:
            return error.as_result()

    def copy_memory_to_ghidra(
        self,
        *,
        bank_id: int,
        start: int,
        end: int,
        program: str,
        destination: str,
        dry_run: bool = True,
        memspace: int = 0,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        """Read stable stopped RAM in chunks, then write it once to Ghidra."""

        try:
            begin, finish = _address_range(start, end)
            length = finish - begin + 1
            if length > MAX_COPY_BYTES:
                raise _invalid("copy range must contain at most 65536 bytes")
            if not isinstance(program, str) or not program.strip():
                raise _invalid("program must not be blank")
            if not isinstance(destination, str) or not destination.strip():
                raise _invalid("destination must not be blank")
            if not isinstance(dry_run, bool):
                raise _invalid("dry_run must be a boolean")
            data = bytearray()
            cursor = begin
            observed_stop_count: int | None = None
            while cursor <= finish:
                source = self._invoke(
                    "c64_vice_v1_read_memory",
                    {
                        "bank_id": _nonnegative(bank_id, "bank_id"),
                        "start": cursor,
                        "end": finish,
                        "side_effects": False,
                        "max_bytes": min(MAX_MEMORY_BYTES, finish - cursor + 1),
                        "memspace": _nonnegative(memspace, "memspace"),
                    },
                    timeout_ms=timeout_ms,
                    mutation_flag=None,
                )
                if source.get("execution_state") != "stopped":
                    raise _incompatible_read(
                        "VICE changed execution state during the copy"
                    )
                stop_count = _nonnegative(source.get("stop_count"), "stop_count")
                if observed_stop_count is None:
                    observed_stop_count = stop_count
                elif stop_count != observed_stop_count:
                    raise _incompatible_read(
                        "VICE stopped again during the copy; retry from a "
                        "stable checkpoint"
                    )
                result = _result_mapping(source)
                raw = result.get("bytes")
                if (
                    not isinstance(raw, str)
                    or len(raw) % 2
                    or _LOWER_HEX.fullmatch(raw) is None
                ):
                    raise _incompatible_read("memory read omitted hexadecimal bytes")
                chunk = bytes.fromhex(raw)
                if not chunk or len(chunk) > finish - cursor + 1:
                    raise _incompatible_read(
                        "memory read returned an invalid chunk length"
                    )
                data.extend(chunk)
                cursor += len(chunk)
            if len(data) != length:
                raise _incompatible_read("memory copy length changed")
            copied = bytes(data)
            digest = hashlib.sha256(copied).hexdigest()
            try:
                write = self._ghidra.write_memory_bytes_result(
                    program,
                    destination,
                    copied.hex(),
                    dry_run=dry_run,
                    conflict_policy="overwrite_bytes",
                )
            except GhidraTransportError as error:
                translated = _transport_error(
                    error,
                    mutation_flag="ghidra_program_may_have_changed",
                    mutating=not dry_run,
                ).as_result()
                translated.update(
                    _copy_summary(begin, finish, destination, copied, digest)
                )
                return translated
            except GhidraError as error:
                translated = _ghidra_response_error(
                    error,
                    mutation_flag="ghidra_program_may_have_changed",
                    mutating=not dry_run,
                ).as_result()
                translated.update(
                    _copy_summary(begin, finish, destination, copied, digest)
                )
                return translated
            summary = _copy_summary(begin, finish, destination, copied, digest)
            summary["write_result"] = write
            summary["committed"] = write.get("committed", False)
            summary["differing_ranges"] = write.get("differing_ranges", [])
            if "error" in write or write.get("ok") is False:
                summary["ok"] = False
                summary["error"] = write.get("error", "Ghidra destination write failed")
                return summary
            summary["ok"] = True
            return summary
        except GhidraTransportError as error:
            return _transport_error(error, mutation_flag=None).as_result()
        except GhidraError as error:
            return _ghidra_response_error(error, mutation_flag=None).as_result()
        except ViceError as error:
            return error.as_result()

    def _counted_execution(
        self, method: str, count: int, timeout_ms: int
    ) -> dict[str, object]:
        try:
            return self._operation_result(
                method,
                {"count": _bounded(count, "count", minimum=1, maximum=65_535)},
                timeout_ms=timeout_ms,
                mutation_flag="vice_state_may_have_changed",
            )
        except ViceError as error:
            return error.as_result()

    def _public_operation(
        self,
        method: str,
        arguments: Mapping[str, object],
        *,
        timeout_ms: int,
        mutation_flag: str | None = None,
    ) -> dict[str, object]:
        try:
            return self._operation_result(
                method,
                arguments,
                timeout_ms=timeout_ms,
                mutation_flag=mutation_flag,
            )
        except ViceError as error:
            return error.as_result()

    def _operation_result(
        self,
        method: str,
        arguments: Mapping[str, object],
        *,
        timeout_ms: int,
        mutation_flag: str | None,
        include_timeout_argument: bool = True,
    ) -> dict[str, object]:
        try:
            return self._invoke(
                method,
                arguments,
                timeout_ms=timeout_ms,
                mutation_flag=mutation_flag,
                include_timeout_argument=include_timeout_argument,
            )
        except GhidraTransportError as error:
            raise _transport_error(
                error,
                mutation_flag=mutation_flag,
                mutating=mutation_flag is not None,
            ) from error
        except GhidraError as error:
            raise _ghidra_response_error(
                error,
                mutation_flag=mutation_flag,
                mutating=mutation_flag is not None,
            ) from error

    def _invoke(
        self,
        method: str,
        arguments: Mapping[str, object],
        *,
        timeout_ms: int,
        mutation_flag: str | None,
        include_timeout_argument: bool = True,
    ) -> dict[str, object]:
        timeout = _bounded(
            timeout_ms,
            "timeout_ms",
            minimum=1,
            maximum=MAX_TIMEOUT_MS,
        )
        capture = self._capture()
        values = {"process": dict(PROCESS_ARGUMENT), **dict(arguments)}
        if include_timeout_argument:
            values["timeout_ms"] = timeout
        try:
            invocation = self._ghidra.invoke_target_method(
                capture.token,
                method,
                values,
                connector_timeout_ms=timeout,
            )
            envelope = parse_connector_envelope(
                invocation,
                expected_instance=capture.instance_id,
            )
        except ViceError as error:
            translated = _risk_error(error, mutation_flag)
            self._apply_failure(capture, translated)
            raise translated from error
        self._apply_success(capture, envelope)
        return envelope

    def _capture(self) -> _Capture:
        with self._lock:
            binding = self._binding
            if binding is None:
                raise ViceError(
                    "vice_not_connected",
                    "run vice_connect before using VICE tools",
                )
            return _Capture(
                token=binding.token,
                instance_id=binding.instance_id,
            )

    def _apply_success(
        self,
        capture: _Capture,
        envelope: Mapping[str, object],
    ) -> None:
        with self._lock:
            binding = self._matching_binding(capture)
            if binding is None:
                return
            _refresh_binding(binding, envelope)

    def _apply_failure(self, capture: _Capture, error: ViceError) -> None:
        with self._lock:
            if self._matching_binding(capture) is not None and error.code in {
                "vice_connector_changed",
                "vice_connection_lost",
                "vice_protocol_error",
            }:
                self._binding = None

    def _matching_binding(self, capture: _Capture) -> _Binding | None:
        binding = self._binding
        if (
            binding is None
            or binding.token != capture.token
            or binding.instance_id != capture.instance_id
        ):
            return None
        return binding

    def _status_locked(self, *, idempotent: bool | None) -> dict[str, object]:
        binding = self._binding
        if binding is None:
            result: dict[str, object] = {
                "ok": True,
                "state": "unbound",
            }
        else:
            state = (
                binding.execution_state
                if binding.connection_state == "connected"
                and binding.execution_state in {"running", "stopped"}
                else binding.connection_state
            )
            result = {
                "ok": True,
                "state": state,
                "target_token": binding.token,
                "instance_id": binding.instance_id,
                "connector_name": binding.connector_name,
                "connector_version": binding.connector_version,
                "vice_version": binding.vice_version,
                "connection_state": binding.connection_state,
                "execution_state": binding.execution_state,
                "stop_count": binding.stop_count,
                "last_pc": binding.last_pc,
            }
        if idempotent is not None:
            result["idempotent"] = idempotent
        return result


def _binding_from_handshake(
    token: str,
    info: CapabilityInfo,
    status: Mapping[str, object],
) -> _Binding:
    return _Binding(
        token=token,
        instance_id=info.instance_id,
        connector_name=info.connector_name,
        connector_version=info.connector_version,
        vice_version=info.vice_version,
        connection_state=_state(status.get("connection_state"), "connection"),
        execution_state=_state(status.get("execution_state"), "execution"),
        stop_count=_nonnegative(status.get("stop_count"), "stop_count"),
        last_pc=_optional_address(status.get("pc")),
    )


def _refresh_binding(binding: _Binding, envelope: Mapping[str, object]) -> None:
    connection_state = _state(envelope.get("connection_state"), "connection")
    execution_state = _state(envelope.get("execution_state"), "execution")
    binding.connection_state = connection_state
    binding.execution_state = execution_state
    binding.stop_count = _nonnegative(envelope.get("stop_count"), "stop_count")
    observed_pc = _optional_address(envelope.get("pc"))
    if observed_pc is not None:
        binding.last_pc = observed_pc


def _result_mapping(envelope: Mapping[str, object]) -> Mapping[str, object]:
    result = envelope.get("result")
    if not isinstance(result, Mapping):
        raise ViceError(
            "vice_connector_incompatible",
            "connector success result must be an object",
        )
    return cast(Mapping[str, object], result)


def _risk_error(error: ViceError, mutation_flag: str | None) -> ViceError:
    if mutation_flag is None and error.code not in {
        "vice_timeout",
        "vice_target_method_timeout",
    }:
        return error
    details = dict(error.details)
    if mutation_flag is not None:
        risk = details.get("state_may_have_changed")
        if mutation_flag == "vice_memory_may_be_modified":
            risk = details.get("memory_may_be_modified", risk)
        if risk is None:
            risk = details.get("vice_action_applied")
        if risk is None:
            risk = details.get("outcome_unknown", False)
        details.setdefault(mutation_flag, bool(risk))
    if error.code in {"vice_timeout", "vice_target_method_timeout"}:
        details.setdefault("outcome_unknown", True)
    return ViceError(error.code, str(error), **details)


def _transport_error(
    error: GhidraTransportError,
    *,
    mutation_flag: str | None,
    mutating: bool = False,
) -> ViceError:
    details: dict[str, object] = {
        "timeout_layer": error.timeout_layer,
        "outcome_unknown": error.outcome_unknown,
        "request_committed": error.request_committed,
    }
    if mutation_flag is not None:
        details[mutation_flag] = bool(mutating and error.request_committed)
    return ViceError(error.code, str(error), **details)


def _ghidra_response_error(
    error: GhidraError,
    *,
    mutation_flag: str | None,
    mutating: bool = False,
) -> ViceError:
    details: dict[str, object] = {"outcome_unknown": bool(mutating)}
    if mutation_flag is not None:
        details[mutation_flag] = bool(mutating)
    return ViceError("ghidra_response_error", str(error), **details)


def _copy_summary(
    start: int,
    end: int,
    destination: str,
    data: bytes,
    digest: str,
) -> dict[str, object]:
    return {
        "source_range": {
            "start": start,
            "start_display": f"${start:04X}",
            "end": end,
            "end_display": f"${end:04X}",
        },
        "destination": destination,
        "byte_count": len(data),
        "sha256": digest,
    }


def _bytes(value: BytesInput) -> bytes:
    if isinstance(value, str):
        compact = "".join(value.split())
        if compact.startswith(("0x", "0X")):
            compact = compact[2:]
        if len(compact) % 2:
            raise _invalid("hex bytes must contain an even number of digits")
        try:
            return bytes.fromhex(compact)
        except ValueError as error:
            raise _invalid("bytes must be hexadecimal") from error
    if isinstance(value, list):
        result = bytearray()
        for index, item in enumerate(value):
            result.append(_bounded(item, f"bytes[{index}]", minimum=0, maximum=255))
        return bytes(result)
    raise _invalid("bytes must be a hexadecimal string or integer array")


def _string_list(value: object, field: str) -> list[str]:
    if not isinstance(value, list):
        raise _invalid(f"{field} must be an array")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise _invalid(f"{field} must contain nonblank strings")
        if item in result:
            raise _invalid(f"{field} must not contain duplicates")
        result.append(item)
    return result


def _nonblank(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise _invalid(f"{field} must be a nonblank string")
    return value


def _address_range(start: object, end: object) -> tuple[int, int]:
    begin = _address(start, "start")
    finish = _address(end, "end")
    if finish < begin:
        raise _invalid("start/end must form a non-wrapping 16-bit range")
    return begin, finish


def _address(value: object, field: str) -> int:
    return _bounded(value, field, minimum=0, maximum=0xFFFF)


def _state(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ViceError(
            "vice_connector_incompatible",
            f"connector omitted {field} state",
        )
    return value


def _integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise _invalid(f"{field} must be an integer")
    return value


def _nonnegative(value: object, field: str) -> int:
    return _bounded(value, field, minimum=0, maximum=(1 << 63) - 1)


def _bounded(
    value: object,
    field: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    number = _integer(value, field)
    if not minimum <= number <= maximum:
        raise _invalid(f"{field} must be from {minimum} to {maximum}")
    return number


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise _invalid(f"{field} must be a boolean")
    return value


def _optional_nonnegative(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _optional_address(value: object) -> int | None:
    number = _optional_nonnegative(value)
    return number if number is not None and number <= 0xFFFF else None


def _invalid(message: str) -> ViceError:
    return ViceError("vice_invalid_argument", message)


def _incompatible_read(message: str) -> ViceError:
    return ViceError("vice_connector_incompatible", message)
