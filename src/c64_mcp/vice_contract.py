"""Strict validation for the versioned Ghidra VICE automation surface."""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib.resources import files
from typing import cast

from .errors import ViceError

_CONTRACT_PACKAGE = "c64_mcp.contracts"
_CONTRACT_NAME = "c64-vice-api-v1.json"

# Revision 2 introduced the display.capture capability and the
# c64_vice_v1_capture_display method that vice_capture_screen calls. Refusing
# an older connector here, in the handshake, reports one clear cause instead of
# a missing-method failure at the first capture.
REQUIRED_SURFACE_REVISION = 2


@dataclass(frozen=True)
class CapabilityInfo:
    """Validated identity and limits of one connector instance."""

    instance_id: str
    connector_name: str
    connector_version: str
    vice_version: str
    api_major: int
    api_minor: int
    limits: dict[str, int]


def load_contract() -> dict[str, object]:
    """Load the installed contract fixture, independent of sibling repos."""

    raw = files(_CONTRACT_PACKAGE).joinpath(_CONTRACT_NAME).read_text(
        encoding="utf-8"
    )
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("packaged C64 VICE contract is not an object")
    return cast(dict[str, object], value)


def validate_discovery(discovery: Mapping[str, object]) -> str:
    """Validate the target token and every required remote-method schema."""

    if discovery.get("ok") is not True:
        raise _upstream_discovery_error(discovery)
    token = discovery.get("target_token")
    if not isinstance(token, str) or not token:
        raise _incompatible("target discovery omitted target_token")
    advertised = _method_map(discovery.get("methods"))
    required = _method_map(load_contract().get("methods"), contract=True)
    for name, expected in required.items():
        actual = advertised.get(name)
        if actual is None:
            raise _incompatible(f"required method {name} is missing")
        _validate_method(name, actual, expected)
    return token


def validate_capabilities(
    envelope: Mapping[str, object],
) -> CapabilityInfo:
    """Validate the connector success envelope and capability payload."""

    _require_success_envelope(envelope, expected_instance=None)
    result = _mapping(envelope.get("result"), "capabilities result")
    contract = load_contract()
    protocol = result.get("protocol")
    if protocol != "c64.vice":
        raise _incompatible("connector protocol must be c64.vice")
    major = _integer(result.get("api_major"), "api_major")
    minor = _integer(result.get("api_minor"), "api_minor")
    if major != 1 or minor < 0:
        raise _incompatible(
            f"unsupported connector API {major}.{minor}; require 1.0 or newer 1.x"
        )
    if result.get("machine") != "c64":
        raise _incompatible("connector machine must be c64")
    if result.get("method_namespace") != contract.get("method_namespace"):
        raise _incompatible("connector method namespace is incompatible")
    surface = _integer(result.get("surface_revision"), "surface_revision")
    if surface < REQUIRED_SURFACE_REVISION:
        raise _incompatible(
            f"connector surface revision {surface} is too old; this C64 MCP "
            f"requires surface revision {REQUIRED_SURFACE_REVISION}, which "
            "adds c64_vice_v1_capture_display. Upgrade the Ghidra VICE "
            "connector."
        )
    if _integer(result.get("binary_monitor_api"), "binary_monitor_api") != 2:
        raise _incompatible("connector binary-monitor API must be 2")

    connector_name = _nonblank(result.get("connector_name"), "connector_name")
    if connector_name != "ghidra-vice-connector":
        raise _incompatible("unexpected connector name")
    connector_version = _nonblank(
        result.get("connector_version"), "connector_version"
    )
    vice_version = _nonblank(result.get("vice_version"), "vice_version")
    instance_id = _valid_uuid(result.get("instance_id"))
    if envelope.get("instance_id") != instance_id:
        raise _incompatible(
            "capability result and envelope instance IDs disagree"
        )

    capabilities = _string_set(result.get("capabilities"), "capabilities")
    required_capabilities = _string_set(
        contract.get("capabilities"), "packaged capabilities"
    )
    if minor == 0 and capabilities != required_capabilities:
        raise _incompatible(
            "API 1.0 capability set does not exactly match the contract"
        )
    if minor > 0 and not required_capabilities <= capabilities:
        raise _incompatible(
            "newer API 1.x connector omits required capabilities"
        )

    limits = _limits(result.get("limits"), contract.get("limits"))
    return CapabilityInfo(
        instance_id=instance_id,
        connector_name=connector_name,
        connector_version=connector_version,
        vice_version=vice_version,
        api_major=major,
        api_minor=minor,
        limits=limits,
    )


def parse_connector_envelope(
    invocation: Mapping[str, object],
    *,
    expected_instance: str,
) -> dict[str, object]:
    """Decode one generic invocation response into a checked connector envelope."""

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
        raise _incompatible("connector method did not return a JSON string")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise _incompatible("connector returned malformed JSON") from error
    if not isinstance(value, dict):
        raise _incompatible("connector envelope must be a JSON object")
    envelope = cast(dict[str, object], value)
    _require_success_envelope(envelope, expected_instance=expected_instance)
    return envelope


def parse_handshake_envelope(
    invocation: Mapping[str, object],
) -> dict[str, object]:
    """Decode a capability invocation before an instance is known."""

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
                    "the active Ghidra VICE target changed during handshake; "
                    "retry vice_connect",
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
                fallback_code="vice_connector_unavailable",
                fallback_message="Ghidra could not invoke the VICE connector",
            )
        raise ViceError(
            "vice_connector_unavailable",
            "Ghidra could not invoke the VICE connector",
        )
    raw = invocation.get("result")
    if not isinstance(raw, str):
        raise _incompatible("capability method did not return a JSON string")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise _incompatible("capability method returned malformed JSON") from error
    if not isinstance(value, dict):
        raise _incompatible("capability envelope must be an object")
    return cast(dict[str, object], value)


def _validate_method(
    name: str,
    actual: Mapping[str, object],
    expected: Mapping[str, object],
) -> None:
    if actual.get("return_type") != expected.get("return_type"):
        raise _incompatible(f"method {name} has the wrong return type")
    actual_parameters = _parameter_map(actual.get("parameters"), name)
    expected_parameters = _parameter_map(
        expected.get("parameters"), name, contract=True
    )
    if actual_parameters.keys() != expected_parameters.keys():
        raise _incompatible(f"method {name} parameter names do not match")
    for parameter, required in expected_parameters.items():
        observed = actual_parameters[parameter]
        if observed.get("type") != required.get("type"):
            raise _incompatible(
                f"method {name} parameter {parameter} has the wrong type"
            )
        if observed.get("required") is not required.get("required"):
            raise _incompatible(
                f"method {name} parameter {parameter} required flag differs"
            )
        is_required = required.get("required") is True
        if observed.get("default_available") is (not is_required):
            if not is_required and observed.get("default") != required.get(
                "default"
            ):
                raise _incompatible(
                    f"method {name} parameter {parameter} default differs"
                )
        else:
            raise _incompatible(
                f"method {name} parameter {parameter} default availability differs"
            )


def _method_map(
    value: object, *, contract: bool = False
) -> dict[str, Mapping[str, object]]:
    values = _sequence(value, "methods")
    result: dict[str, Mapping[str, object]] = {}
    for item in values:
        method = _mapping(item, "method")
        name = _nonblank(method.get("name"), "method name")
        if name in result:
            source = "contract" if contract else "target discovery"
            raise _incompatible(f"{source} contains duplicate method {name}")
        result[name] = method
    return result


def _parameter_map(
    value: object, method: str, *, contract: bool = False
) -> dict[str, Mapping[str, object]]:
    result: dict[str, Mapping[str, object]] = {}
    for item in _sequence(value, f"parameters for {method}"):
        parameter = _mapping(item, f"parameter for {method}")
        name = _nonblank(parameter.get("name"), f"parameter name for {method}")
        if name in result:
            source = "contract" if contract else "target discovery"
            raise _incompatible(
                f"{source} contains duplicate parameter {method}.{name}"
            )
        result[name] = parameter
    return result


def _require_success_envelope(
    envelope: Mapping[str, object],
    *,
    expected_instance: str | None,
) -> None:
    if envelope.get("api") != "c64.vice/1":
        raise _incompatible("connector envelope has the wrong API")
    instance = _valid_uuid(envelope.get("instance_id"))
    if expected_instance is not None and instance != expected_instance:
        raise ViceError(
            "vice_connector_changed",
            "the connector instance changed; run vice_connect again",
            expected_instance_id=expected_instance,
            observed_instance_id=instance,
        )
    command_sequence = _integer(
        envelope.get("command_sequence"),
        "command_sequence",
        minimum=0,
    )
    if envelope.get("ok") is True:
        if "result" not in envelope:
            raise _incompatible("successful connector envelope omitted result")
        return
    if envelope.get("ok") is False:
        error = _mapping(envelope.get("error"), "connector error")
        failure = ViceError.from_mapping(
            error,
            fallback_code="vice_connector_error",
            fallback_message="VICE connector operation failed",
        )
        failure.details["command_sequence"] = command_sequence
        raise failure
    raise _incompatible("connector envelope omitted boolean ok")


def _upstream_discovery_error(discovery: Mapping[str, object]) -> ViceError:
    value = discovery.get("error")
    if isinstance(value, Mapping):
        return ViceError(
            "vice_connector_unavailable",
            "no compatible active VICE connector target is available",
            upstream_error=dict(value),
            guidance=(
                "Install the Ghidra VICE connector and launch the "
                "'VICE C64 Debugger' TraceRMI offer."
            ),
        )
    return ViceError(
        "vice_connector_unavailable",
        "Ghidra target discovery failed",
    )


def _limits(value: object, expected_value: object) -> dict[str, int]:
    observed = _mapping(value, "limits")
    expected = _mapping(expected_value, "packaged limits")
    result: dict[str, int] = {}
    for name, minimum_value in expected.items():
        required = _integer(minimum_value, f"packaged limit {name}", minimum=1)
        actual = _integer(observed.get(name), f"limit {name}", minimum=1)
        if actual < required:
            raise _incompatible(f"connector limit {name} is too small")
        result[name] = actual
    return result


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _incompatible(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes, bytearray))
    ):
        raise _incompatible(f"{field} must be an array")
    return value


def _string_set(value: object, field: str) -> set[str]:
    result: set[str] = set()
    for item in _sequence(value, field):
        if not isinstance(item, str) or not item:
            raise _incompatible(f"{field} must contain nonblank strings")
        if item in result:
            raise _incompatible(f"{field} contains duplicate {item}")
        result.add(item)
    return result


def _nonblank(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise _incompatible(f"{field} must be a nonblank string")
    return value


def _integer(
    value: object, field: str, *, minimum: int | None = None
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise _incompatible(f"{field} must be an integer")
    if minimum is not None and value < minimum:
        raise _incompatible(f"{field} must be at least {minimum}")
    return value


def _valid_uuid(value: object) -> str:
    text = _nonblank(value, "instance_id")
    try:
        parsed = uuid.UUID(text)
    except ValueError as error:
        raise _incompatible("instance_id must be a UUID") from error
    if str(parsed) != text.lower():
        raise _incompatible("instance_id must use canonical UUID syntax")
    return text


def _incompatible(message: str) -> ViceError:
    return ViceError("vice_connector_incompatible", message)
