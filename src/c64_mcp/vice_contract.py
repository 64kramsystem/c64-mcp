"""Minimal validation for the connector-owned C64 VICE surface."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast

from .errors import ViceError

REQUIRED_METHOD_ARGS = {
    "c64_vice_v1_capabilities": {"process"},
    "c64_vice_v1_status": {"process"},
    "c64_vice_v1_get_registers": {"process", "names", "memspace", "timeout_ms"},
    "c64_vice_v1_set_registers": {
        "process",
        "names",
        "values",
        "memspace",
        "timeout_ms",
    },
    "c64_vice_v1_list_banks": {"process", "timeout_ms"},
    "c64_vice_v1_read_memory": {
        "process",
        "bank_id",
        "start",
        "end",
        "side_effects",
        "max_bytes",
        "memspace",
        "timeout_ms",
    },
    "c64_vice_v1_write_memory": {
        "process",
        "bank_id",
        "start",
        "data",
        "side_effects",
        "memspace",
        "timeout_ms",
    },
    "c64_vice_v1_list_checkpoints": {"process", "timeout_ms"},
    "c64_vice_v1_set_checkpoint": {
        "process",
        "start",
        "end",
        "stop_on_hit",
        "enabled",
        "operations",
        "temporary",
        "memspace",
        "timeout_ms",
    },
    "c64_vice_v1_delete_checkpoint": {"process", "number", "timeout_ms"},
    "c64_vice_v1_toggle_checkpoint": {
        "process",
        "number",
        "enabled",
        "timeout_ms",
    },
    "c64_vice_v1_step": {"process", "count", "timeout_ms"},
    "c64_vice_v1_next": {"process", "count", "timeout_ms"},
    "c64_vice_v1_finish": {"process", "timeout_ms"},
    "c64_vice_v1_resume": {"process", "timeout_ms"},
    "c64_vice_v1_interrupt": {"process", "timeout_ms"},
    "c64_vice_v1_wait_for_stop": {
        "process",
        "after_stop_count",
        "timeout_ms",
    },
    "c64_vice_v1_feed_keyboard": {"process", "data", "timeout_ms"},
    "c64_vice_v1_set_joyport": {
        "process",
        "port",
        "value",
        "timeout_ms",
    },
    "c64_vice_v1_save_snapshot": {
        "process",
        "filename",
        "save_roms",
        "save_disks",
        "timeout_ms",
    },
    "c64_vice_v1_load_snapshot": {"process", "filename", "timeout_ms"},
    "c64_vice_v1_reset": {"process", "kind", "timeout_ms"},
}

REQUIRED_LIMITS = {
    "keyboard_feed_bytes": 255,
    "memory_chunk_bytes": 16_384,
}


@dataclass(frozen=True)
class CapabilityInfo:
    instance_id: str
    connector_name: str
    connector_version: str
    vice_version: str


def validate_discovery(discovery: Mapping[str, object]) -> str:
    if discovery.get("ok") is not True:
        raise _upstream_discovery_error(discovery)
    token = _nonblank(discovery.get("target_token"), "target_token")
    methods = _method_map(discovery.get("methods"))
    for name, expected in REQUIRED_METHOD_ARGS.items():
        method = methods.get(name)
        if method is None:
            raise _incompatible(f"required method {name} is missing")
        observed = {
            _nonblank(item.get("name"), f"parameter for {name}")
            for item in _mappings(method.get("parameters"), f"parameters for {name}")
        }
        missing = expected - observed
        if missing:
            raise _incompatible(
                f"method {name} is missing parameters: " + ", ".join(sorted(missing))
            )
    return token


def validate_capabilities(
    envelope: Mapping[str, object],
) -> CapabilityInfo:
    _require_envelope(envelope, expected_instance=None)
    result = _mapping(envelope.get("result"), "capabilities result")
    if result.get("protocol") != "c64.vice":
        raise _incompatible("connector protocol must be c64.vice")
    if _integer(result.get("api_major"), "api_major") != 1:
        raise _incompatible("connector API major must be 1")
    if result.get("machine") != "c64":
        raise _incompatible("connector machine must be c64")
    instance_id = _nonblank(result.get("instance_id"), "instance_id")
    if envelope.get("instance_id") != instance_id:
        raise _incompatible("capability result and envelope instance IDs disagree")
    observed_limits = _mapping(result.get("limits"), "limits")
    for name, minimum in REQUIRED_LIMITS.items():
        value = _integer(observed_limits.get(name), f"limit {name}")
        if value < minimum:
            raise _incompatible(f"connector limit {name} is too small")
    return CapabilityInfo(
        instance_id=instance_id,
        connector_name=_nonblank(result.get("connector_name"), "connector_name"),
        connector_version=_nonblank(
            result.get("connector_version"), "connector_version"
        ),
        vice_version=_nonblank(result.get("vice_version"), "vice_version"),
    )


def parse_connector_envelope(
    invocation: Mapping[str, object],
    *,
    expected_instance: str,
) -> dict[str, object]:
    envelope = _decode_invocation(invocation, "connector")
    _require_envelope(envelope, expected_instance=expected_instance)
    return envelope


def parse_handshake_envelope(
    invocation: Mapping[str, object],
) -> dict[str, object]:
    return _decode_invocation(invocation, "capability")


def _decode_invocation(
    invocation: Mapping[str, object], label: str
) -> dict[str, object]:
    if invocation.get("ok") is not True:
        error = invocation.get("error")
        if isinstance(error, Mapping):
            code = error.get("code")
            if code in {
                "stale_target_token",
                "target_owner_changed",
                "target_not_current",
            }:
                raise ViceError(
                    "vice_connector_changed",
                    "the active Ghidra VICE target changed; run vice_connect again",
                    upstream_error=dict(error),
                )
            if code == "target_method_timeout":
                raise ViceError(
                    "vice_target_method_timeout",
                    "the Ghidra target-method invocation timed out",
                    timeout_layer="generic",
                    outcome_unknown=True,
                    upstream_error=dict(error),
                )
            raise ViceError.from_mapping(
                error,
                fallback_code="vice_target_method_failed",
                fallback_message="Ghidra could not invoke the VICE connector",
            )
        raise ViceError(
            "vice_target_method_failed",
            "Ghidra returned a malformed target-method failure",
        )
    raw = invocation.get("result")
    if not isinstance(raw, str):
        raise _incompatible(f"{label} method did not return JSON")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise _incompatible(f"{label} method returned malformed JSON") from error
    if not isinstance(value, dict):
        raise _incompatible(f"{label} envelope must be an object")
    return cast(dict[str, object], value)


def _require_envelope(
    envelope: Mapping[str, object],
    *,
    expected_instance: str | None,
) -> None:
    if envelope.get("api") != "c64.vice/1":
        raise _incompatible("connector envelope has the wrong API")
    instance = _nonblank(envelope.get("instance_id"), "instance_id")
    if expected_instance is not None and instance != expected_instance:
        raise ViceError(
            "vice_connector_changed",
            "the connector instance changed; run vice_connect again",
            expected_instance_id=expected_instance,
            observed_instance_id=instance,
        )
    command_sequence = _integer(envelope.get("command_sequence"), "command_sequence")
    stop_count = _integer(envelope.get("stop_count"), "stop_count")
    _nonblank(envelope.get("connection_state"), "connection_state")
    _nonblank(envelope.get("execution_state"), "execution_state")
    pc = envelope.get("pc")
    if pc is not None and (
        isinstance(pc, bool) or not isinstance(pc, int) or not 0 <= pc <= 0xFFFF
    ):
        raise _incompatible("pc must be null or a 16-bit integer")
    if envelope.get("ok") is True and "result" in envelope:
        return
    if envelope.get("ok") is False:
        error = _mapping(envelope.get("error"), "connector error")
        failure = ViceError.from_mapping(
            error,
            fallback_code="vice_connector_error",
            fallback_message="VICE connector operation failed",
        )
        failure.details.update(
            command_sequence=command_sequence,
            stop_count=stop_count,
            connection_state=envelope["connection_state"],
            execution_state=envelope["execution_state"],
            pc=pc,
        )
        raise failure
    raise _incompatible("connector envelope has no valid result")


def _method_map(value: object) -> dict[str, Mapping[str, object]]:
    result: dict[str, Mapping[str, object]] = {}
    for method in _mappings(value, "methods"):
        name = _nonblank(method.get("name"), "method name")
        if name in result:
            raise _incompatible(f"target discovery duplicates method {name}")
        result[name] = method
    return result


def _mappings(value: object, field: str) -> list[Mapping[str, object]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise _incompatible(f"{field} must be an array")
    if not all(isinstance(item, Mapping) for item in value):
        raise _incompatible(f"{field} must contain objects")
    return [cast(Mapping[str, object], item) for item in value]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _incompatible(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _nonblank(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise _incompatible(f"{field} must be a nonblank string")
    return value


def _integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _incompatible(f"{field} must be a non-negative integer")
    return value


def _upstream_discovery_error(discovery: Mapping[str, object]) -> ViceError:
    return ViceError(
        "vice_connector_unavailable",
        "no compatible active VICE connector target is available",
        upstream_error=discovery.get("error"),
    )


def _incompatible(message: str) -> ViceError:
    return ViceError("vice_connector_incompatible", message)
