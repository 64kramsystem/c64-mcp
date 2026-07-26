from __future__ import annotations

import copy
import hashlib
import json
import threading
from collections.abc import Mapping
from typing import Any

import pytest

from c64_mcp.errors import GhidraError, GhidraTransportError
from c64_mcp.vice import ViceSession
from c64_mcp.vice_contract import load_contract

INSTANCE = "12345678-1234-1234-1234-123456789abc"


def discovery(token: str = "target-1") -> dict[str, object]:
    methods: list[dict[str, object]] = []
    for source in load_contract()["methods"]:  # type: ignore[index,union-attr]
        method = copy.deepcopy(source)
        for parameter in method["parameters"]:
            required = parameter["required"]
            parameter["default_available"] = not required
            parameter["default"] = (
                None if required else parameter["default"]
            )
        methods.append(method)
    return {"ok": True, "target_token": token, "methods": methods}


def envelope(
    result: object,
    *,
    sequence: int = 0,
    instance: str = INSTANCE,
    ok: bool = True,
    connection: str = "connected",
    execution: str = "stopped",
) -> dict[str, object]:
    value: dict[str, object] = {
        "api": "c64.vice/1",
        "ok": ok,
        "command_sequence": sequence,
        "instance_id": instance,
        "connection_state": connection,
        "execution_state": execution,
    }
    value["result" if ok else "error"] = result
    return value


def invocation(value: dict[str, object]) -> dict[str, object]:
    return {"ok": True, "result": json.dumps(value)}


def capabilities(
    instance: str = INSTANCE, *, surface_revision: int = 2
) -> dict[str, object]:
    contract = load_contract()
    return envelope(
        {
            "protocol": "c64.vice",
            "api_major": 1,
            "api_minor": 0,
            "connector_name": "ghidra-vice-connector",
            "connector_version": "1.0.0",
            "instance_id": instance,
            "machine": "c64",
            "vice_version": "3.10.0",
            "binary_monitor_api": 2,
            "capabilities": contract["capabilities"],
            "method_namespace": "c64_vice_v1_",
            "surface_revision": surface_revision,
            "limits": contract["limits"],
        },
        instance=instance,
    )


def status(
    *,
    sequence: int = 0,
    instance: str = INSTANCE,
) -> dict[str, object]:
    return envelope(
        {
            "event_sequence": 3,
            "pc": 0xC000,
            "connector_version": "1.0.0",
            "vice_version": "3.10.0",
            "binary_monitor_api": 2,
        },
        sequence=sequence,
        instance=instance,
    )


class FakeGhidra:
    def __init__(self) -> None:
        self.token = "target-1"
        self.instance = INSTANCE
        self.surface_revision = 2
        self.calls: list[tuple[str, dict[str, object], int]] = []
        self.writes: list[dict[str, object]] = []
        self.replies: dict[str, dict[str, object]] = {}

    def target_methods(self) -> dict[str, object]:
        return discovery(self.token)

    def invoke_target_method(
        self,
        target_token: str,
        method: str,
        arguments: Mapping[str, object],
        *,
        connector_timeout_ms: int,
    ) -> dict[str, object]:
        assert target_token == self.token
        self.calls.append(
            (method, dict(arguments), connector_timeout_ms)
        )
        if method == "c64_vice_v1_capabilities":
            return invocation(
                capabilities(
                    self.instance, surface_revision=self.surface_revision
                )
            )
        if method == "c64_vice_v1_status":
            return invocation(status(instance=self.instance))
        value = self.replies.get(method, envelope({}, sequence=1))
        return invocation(value)

    def write_memory_bytes_result(
        self,
        program: str,
        start: str,
        data: str,
        *,
        dry_run: bool = True,
        conflict_policy: str = "error",
    ) -> dict[str, object]:
        self.writes.append(
            {
                "program": program,
                "start": start,
                "data": data,
                "dry_run": dry_run,
                "conflict_policy": conflict_policy,
            }
        )
        return {
            "ok": True,
            "committed": not dry_run,
            "differing_ranges": [{"start": start, "length": len(data) // 2}],
        }


def connected() -> tuple[FakeGhidra, ViceSession]:
    fake = FakeGhidra()
    session = ViceSession(fake)
    assert session.connect()["ok"] is True
    fake.calls.clear()
    return fake, session


def test_connect_validates_complete_handshake_and_is_idempotent() -> None:
    fake = FakeGhidra()
    session = ViceSession(fake)

    first = session.connect()
    second = session.connect()

    assert first["state"] == "stopped"
    assert first["idempotent"] is False
    assert second["idempotent"] is True
    assert second["instance_id"] == INSTANCE
    assert [call[0] for call in fake.calls] == [
        "c64_vice_v1_capabilities",
        "c64_vice_v1_status",
        "c64_vice_v1_capabilities",
        "c64_vice_v1_status",
    ]


def test_connect_transport_timeout_is_structured_and_non_mutating() -> None:
    fake = FakeGhidra()

    def timed_out(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise GhidraTransportError(
            "late",
            code="ghidra_http_timeout",
            timeout_layer="http",
            outcome_unknown=True,
            request_committed=True,
        )

    fake.invoke_target_method = timed_out  # type: ignore[method-assign]

    result = ViceSession(fake).connect()

    error = result["error"]
    assert error["code"] == "ghidra_http_timeout"  # type: ignore[index]
    assert error["timeout_layer"] == "http"  # type: ignore[index]
    assert error["outcome_unknown"] is True  # type: ignore[index]
    assert "vice_state_may_have_changed" not in error  # type: ignore[operator]


def test_non_timeout_ghidra_response_failure_is_structured() -> None:
    fake, session = connected()

    def malformed(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise GhidraError("response is not valid UTF-8 JSON")

    fake.invoke_target_method = malformed  # type: ignore[method-assign]

    result = session.set_registers(values={"A": 1})

    error = result["error"]
    assert error["code"] == "ghidra_response_error"  # type: ignore[index]
    assert error["outcome_unknown"] is True  # type: ignore[index]
    assert error["vice_registers_may_have_changed"] is True  # type: ignore[index]


def test_status_and_disconnect_never_contact_ghidra() -> None:
    fake, session = connected()

    observed = session.status()
    released = session.disconnect()
    after = session.status()

    assert observed["last_event_sequence"] == 3
    assert observed["last_pc"] == 0xC000
    assert released["connector_externally_owned"] is True
    assert after["state"] == "unbound"
    assert fake.calls == []


def test_disconnect_during_connect_prevents_binding_resurrection() -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingFake(FakeGhidra):
        def invoke_target_method(
            self,
            target_token: str,
            method: str,
            arguments: Mapping[str, object],
            *,
            connector_timeout_ms: int,
        ) -> dict[str, object]:
            if method == "c64_vice_v1_capabilities":
                entered.set()
                assert release.wait(2)
            return super().invoke_target_method(
                target_token,
                method,
                arguments,
                connector_timeout_ms=connector_timeout_ms,
            )

    fake = BlockingFake()
    session = ViceSession(fake)
    result: list[dict[str, object]] = []
    thread = threading.Thread(target=lambda: result.append(session.connect()))
    thread.start()
    assert entered.wait(2)
    session.disconnect()
    release.set()
    thread.join(2)

    assert result[0]["ok"] is False
    assert result[0]["error"]["code"] == "vice_connector_changed"  # type: ignore[index]
    assert session.status()["state"] == "unbound"


def test_late_lower_sequence_does_not_regress_watermark() -> None:
    fake, session = connected()
    fake.replies["c64_vice_v1_list_banks"] = envelope(
        {"banks": []}, sequence=9, execution="running"
    )
    assert session.list_banks()["ok"] is True
    fake.replies["c64_vice_v1_get_registers"] = envelope(
        {"registers": [], "event": {"sequence": 2, "pc": 0xDEAD}},
        sequence=4,
    )

    assert session.get_registers()["ok"] is True
    assert session.status()["max_command_sequence"] == 9
    assert session.status()["last_event_sequence"] == 3
    assert session.status()["last_pc"] == 0xC000
    assert session.status()["execution_state"] == "running"


def test_failure_sequences_advance_watermark_but_late_errors_do_not_regress() -> None:
    fake, session = connected()
    fake.replies["c64_vice_v1_list_banks"] = envelope(
        {"banks": []}, sequence=6
    )
    assert session.list_banks()["ok"] is True

    fake.replies["c64_vice_v1_list_banks"] = envelope(
        {
            "code": "vice_timeout",
            "message": "old timeout",
            "outcome_unknown": True,
        },
        sequence=5,
        ok=False,
    )
    assert session.list_banks()["ok"] is False
    assert session.status()["max_command_sequence"] == 6
    assert session.status()["last_error"] is None

    fake.replies["c64_vice_v1_list_banks"] = envelope(
        {
            "code": "vice_timeout",
            "message": "new timeout",
            "outcome_unknown": True,
        },
        sequence=7,
        ok=False,
    )
    assert session.list_banks()["ok"] is False
    observed = session.status()
    assert observed["max_command_sequence"] == 7
    assert observed["last_error"]["message"] == "new timeout"  # type: ignore[index]


def test_old_generation_response_cannot_update_reconnected_binding() -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingFake(FakeGhidra):
        block = False

        def invoke_target_method(
            self,
            target_token: str,
            method: str,
            arguments: Mapping[str, object],
            *,
            connector_timeout_ms: int,
        ) -> dict[str, object]:
            if method == "c64_vice_v1_step" and self.block:
                entered.set()
                assert release.wait(2)
                return invocation(
                    envelope(
                        {"event": {"sequence": 99, "pc": 0xDEAD}},
                        sequence=99,
                    )
                )
            return super().invoke_target_method(
                target_token,
                method,
                arguments,
                connector_timeout_ms=connector_timeout_ms,
            )

    fake = BlockingFake()
    session = ViceSession(fake)
    assert session.connect()["ok"] is True
    fake.block = True
    result: list[dict[str, object]] = []
    thread = threading.Thread(target=lambda: result.append(session.step()))
    thread.start()
    assert entered.wait(2)
    session.disconnect()
    fake.block = False
    assert session.connect()["ok"] is True
    release.set()
    thread.join(2)

    assert result[0]["ok"] is True
    assert session.status()["max_command_sequence"] == 0
    assert session.status()["last_pc"] == 0xC000


@pytest.mark.parametrize(
    ("call", "method"),
    [
        (lambda value: value.get_registers(), "c64_vice_v1_get_registers"),
        (
            lambda value: value.set_registers(values={"A": 1}),
            "c64_vice_v1_set_registers",
        ),
        (lambda value: value.list_banks(), "c64_vice_v1_list_banks"),
        (
            lambda value: value.read_memory(
                bank_id=0, start=0x1000, end=0x1001
            ),
            "c64_vice_v1_read_memory",
        ),
        (
            lambda value: value.write_memory(
                bank_id=0, start=0x1000, bytes="aabb"
            ),
            "c64_vice_v1_write_memory",
        ),
        (
            lambda value: value.list_checkpoints(),
            "c64_vice_v1_list_checkpoints",
        ),
        (
            lambda value: value.set_checkpoint(start=1, end=2),
            "c64_vice_v1_set_checkpoint",
        ),
        (
            lambda value: value.delete_checkpoint(number=1),
            "c64_vice_v1_delete_checkpoint",
        ),
        (
            lambda value: value.toggle_checkpoint(number=1, enabled=False),
            "c64_vice_v1_toggle_checkpoint",
        ),
        (lambda value: value.step(), "c64_vice_v1_step"),
        (lambda value: value.next(), "c64_vice_v1_next"),
        (lambda value: value.finish(), "c64_vice_v1_finish"),
        (lambda value: value.resume(), "c64_vice_v1_resume"),
        (lambda value: value.interrupt(), "c64_vice_v1_interrupt"),
        (
            lambda value: value.wait_for_stop(
                after_sequence=0, timeout_ms=100
            ),
            "c64_vice_v1_wait_for_stop",
        ),
        (lambda value: value.reset(), "c64_vice_v1_reset"),
        (
            lambda value: value.capture_display(),
            "c64_vice_v1_capture_display",
        ),
    ],
)
def test_public_tools_map_to_exactly_one_versioned_connector_method(
    call: Any, method: str
) -> None:
    fake, session = connected()

    result = call(session)

    assert result["ok"] is True
    assert [item[0] for item in fake.calls] == [method]
    assert fake.calls[0][1]["process"] == {"object_path": "C64"}
    assert fake.calls[0][1]["timeout_ms"] == fake.calls[0][2]


def test_capture_display_sends_only_the_declared_arguments() -> None:
    fake, session = connected()

    assert session.capture_display(use_vic=False, timeout_ms=2_500)["ok"] is True

    method, arguments, connector_timeout = fake.calls[0]
    assert method == "c64_vice_v1_capture_display"
    assert arguments == {
        "process": {"object_path": "C64"},
        "use_vic": False,
        "timeout_ms": 2_500,
    }
    assert connector_timeout == 2_500


def test_capture_display_rejects_a_non_boolean_use_vic() -> None:
    fake, session = connected()

    result = session.capture_display(use_vic="yes")  # type: ignore[arg-type]

    assert result["error"]["code"] == "vice_invalid_argument"  # type: ignore[index]
    assert fake.calls == []


def test_a_revision_one_connector_is_rejected_during_the_handshake() -> None:
    fake = FakeGhidra()
    fake.surface_revision = 1

    result = ViceSession(fake).connect()

    error = result["error"]
    assert error["code"] == "vice_connector_incompatible"  # type: ignore[index]
    message = error["message"]  # type: ignore[index]
    assert "surface revision" in message
    assert "2" in message


def test_a_connector_without_the_capture_method_names_it() -> None:
    class OldFake(FakeGhidra):
        def target_methods(self) -> dict[str, object]:
            found = discovery(self.token)
            found["methods"] = [
                method
                for method in found["methods"]  # type: ignore[union-attr]
                if method["name"] != "c64_vice_v1_capture_display"
            ]
            return found

    result = ViceSession(OldFake()).connect()

    error = result["error"]
    assert error["code"] == "vice_connector_incompatible"  # type: ignore[index]
    assert "c64_vice_v1_capture_display" in error["message"]  # type: ignore[index]


def test_register_read_always_sends_required_names_array() -> None:
    fake, session = connected()

    session.get_registers()

    assert fake.calls[0][1]["names"] == []


def test_mutating_generic_timeout_has_exact_layer_and_risk() -> None:
    class TimeoutFake(FakeGhidra):
        def invoke_target_method(
            self,
            target_token: str,
            method: str,
            arguments: Mapping[str, object],
            *,
            connector_timeout_ms: int,
        ) -> dict[str, object]:
            if method == "c64_vice_v1_set_registers":
                return {
                    "ok": False,
                    "error": {
                        "code": "target_method_timeout",
                        "message": "late",
                    },
                    "outcome_unknown": True,
                }
            return super().invoke_target_method(
                target_token,
                method,
                arguments,
                connector_timeout_ms=connector_timeout_ms,
            )

    fake = TimeoutFake()
    session = ViceSession(fake)
    session.connect()

    result = session.set_registers(values={"A": 1})

    error = result["error"]
    assert error["code"] == "vice_target_method_timeout"  # type: ignore[index]
    assert error["timeout_layer"] == "generic"  # type: ignore[index]
    assert error["vice_registers_may_have_changed"] is True  # type: ignore[index]


def test_http_timeout_reports_request_commit_and_no_retry() -> None:
    fake, session = connected()

    def timed_out(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise GhidraTransportError(
            "late",
            code="ghidra_http_timeout",
            timeout_layer="http",
            outcome_unknown=True,
            request_committed=True,
        )

    fake.invoke_target_method = timed_out  # type: ignore[method-assign]
    result = session.write_memory(bank_id=0, start=0x1000, bytes="aa")

    error = result["error"]
    assert error["code"] == "ghidra_http_timeout"  # type: ignore[index]
    assert error["request_committed"] is True  # type: ignore[index]
    assert error["vice_memory_may_be_modified"] is True  # type: ignore[index]


def test_copy_reads_once_then_writes_once_without_returning_payload() -> None:
    fake, session = connected()
    data = bytes(range(16))
    fake.replies["c64_vice_v1_read_memory"] = envelope(
        {
            "bank_id": 0,
            "start": 0x2000,
            "end": 0x200F,
            "bytes": data.hex(),
            "byte_count": len(data),
            "complete": True,
            "next_address": None,
        },
        sequence=8,
    )

    result = session.copy_memory_to_ghidra(
        bank_id=0,
        start=0x2000,
        end=0x200F,
        program="snapshot",
        destination="RAM:4000",
        conflict_policy="overwrite_bytes",
        dry_run=False,
    )

    assert [item[0] for item in fake.calls] == [
        "c64_vice_v1_read_memory"
    ]
    assert fake.calls[0][1]["max_bytes"] == 16
    assert fake.writes == [
        {
            "program": "snapshot",
            "start": "RAM:4000",
            "data": data.hex(),
            "dry_run": False,
            "conflict_policy": "overwrite_bytes",
        }
    ]
    assert result["ok"] is True
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["byte_count"] == 16
    assert "bytes" not in result


def test_copy_rejects_incomplete_source_before_any_write() -> None:
    fake, session = connected()
    fake.replies["c64_vice_v1_read_memory"] = envelope(
        {
            "bytes": "aa",
            "byte_count": 1,
            "complete": False,
            "next_address": 0x1001,
        }
    )

    result = session.copy_memory_to_ghidra(
        bank_id=0,
        start=0x1000,
        end=0x1001,
        program="snapshot",
        destination="RAM:2000",
    )

    assert result["ok"] is False
    assert fake.writes == []


@pytest.mark.parametrize(
    ("raw", "byte_count"),
    [("AA", 1), ("a a", 1), ("aa", True)],
)
def test_copy_rejects_noncanonical_or_mistyped_payload_metadata(
    raw: str, byte_count: object
) -> None:
    fake, session = connected()
    fake.replies["c64_vice_v1_read_memory"] = envelope(
        {
            "bytes": raw,
            "byte_count": byte_count,
            "complete": True,
            "next_address": None,
        }
    )

    result = session.copy_memory_to_ghidra(
        bank_id=0,
        start=0x1000,
        end=0x1000,
        program="snapshot",
        destination="RAM:2000",
    )

    assert result["ok"] is False
    assert fake.writes == []


def test_copy_read_response_failure_is_structured_and_never_writes() -> None:
    fake, session = connected()

    def malformed(
        target_token: str,
        method: str,
        arguments: Mapping[str, object],
        *,
        connector_timeout_ms: int,
    ) -> dict[str, object]:
        del target_token, arguments, connector_timeout_ms
        assert method == "c64_vice_v1_read_memory"
        raise GhidraError("response is not valid UTF-8 JSON")

    fake.invoke_target_method = malformed  # type: ignore[method-assign]
    result = session.copy_memory_to_ghidra(
        bank_id=0,
        start=0x1000,
        end=0x1000,
        program="snapshot",
        destination="RAM:2000",
    )

    error = result["error"]
    assert error["code"] == "ghidra_response_error"  # type: ignore[index]
    assert error["outcome_unknown"] is False  # type: ignore[index]
    assert fake.writes == []


def test_copy_committed_http_timeout_is_never_retried_and_reports_risk() -> None:
    fake, session = connected()
    fake.replies["c64_vice_v1_read_memory"] = envelope(
        {
            "bytes": "aa",
            "byte_count": 1,
            "complete": True,
            "next_address": None,
        }
    )

    def timed_out(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise GhidraTransportError(
            "late",
            code="ghidra_http_timeout",
            timeout_layer="http",
            outcome_unknown=True,
            request_committed=True,
        )

    fake.write_memory_bytes_result = timed_out  # type: ignore[method-assign]
    result = session.copy_memory_to_ghidra(
        bank_id=0,
        start=0x1000,
        end=0x1000,
        program="snapshot",
        destination="RAM:2000",
        dry_run=False,
    )

    error = result["error"]
    assert error["ghidra_program_may_have_changed"] is True  # type: ignore[index]
    assert result["sha256"] == hashlib.sha256(b"\xaa").hexdigest()
