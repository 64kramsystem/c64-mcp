from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from c64_mcp.errors import ViceError
from c64_mcp.vice_contract import (
    load_contract,
    parse_connector_envelope,
    parse_handshake_envelope,
    validate_capabilities,
    validate_discovery,
)

INSTANCE = "12345678-1234-1234-1234-123456789abc"


def discovery() -> dict[str, object]:
    methods: list[dict[str, object]] = []
    contract = load_contract()
    for source in contract["methods"]:  # type: ignore[index,union-attr]
        method = copy.deepcopy(source)
        for parameter in method["parameters"]:
            required = parameter["required"]
            parameter["default_available"] = not required
            if required:
                parameter["default"] = None
            parameter["display"] = parameter["name"]
            parameter["description"] = ""
        method["action"] = None
        method["display"] = method["name"]
        method["description"] = ""
        methods.append(method)
    return {
        "ok": True,
        "target_token": "opaque-target",
        "methods": list(reversed(methods)),
    }


def connector_envelope(
    result: object,
    *,
    ok: bool = True,
    instance_id: str = INSTANCE,
) -> dict[str, object]:
    value: dict[str, object] = {
        "api": "c64.vice/1",
        "ok": ok,
        "command_sequence": 7,
        "instance_id": instance_id,
        "connection_state": "connected",
        "execution_state": "stopped",
    }
    value["result" if ok else "error"] = result
    return value


def capability_envelope(
    *,
    minor: int = 0,
    capabilities: list[str] | None = None,
) -> dict[str, object]:
    contract = load_contract()
    result = {
        "protocol": "c64.vice",
        "api_major": 1,
        "api_minor": minor,
        "connector_name": "ghidra-vice-connector",
        "connector_version": "1.0.0",
        "instance_id": INSTANCE,
        "machine": "c64",
        "vice_version": "3.10.0",
        "binary_monitor_api": 2,
        "capabilities": (
            contract["capabilities"]
            if capabilities is None
            else capabilities
        ),
        "method_namespace": "c64_vice_v1_",
        "surface_revision": 1,
        "limits": contract["limits"],
    }
    return connector_envelope(result)


def invocation(envelope: dict[str, object]) -> dict[str, object]:
    return {
        "ok": True,
        "result": json.dumps(envelope),
        "before": {},
        "after": {},
    }


def test_packaged_contract_validates_complete_discovery() -> None:
    assert validate_discovery(discovery()) == "opaque-target"


def test_discovery_parameter_order_is_irrelevant() -> None:
    value = discovery()
    methods = value["methods"]
    assert isinstance(methods, list)
    for method in methods:
        method["parameters"].reverse()

    assert validate_discovery(value) == "opaque-target"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["methods"].pop(),  # type: ignore[union-attr]
            "required method",
        ),
        (
            lambda value: value["methods"][0].__setitem__(  # type: ignore[index,union-attr]
                "return_type", "LONG"
            ),
            "return type",
        ),
        (
            lambda value: value["methods"][0]["parameters"][0].__setitem__(  # type: ignore[index,union-attr]
                "type", "STRING"
            ),
            "wrong type",
        ),
        (
            lambda value: value["methods"][0]["parameters"][0].__setitem__(  # type: ignore[index,union-attr]
                "default_available", True
            ),
            "default availability",
        ),
    ],
)
def test_discovery_rejects_every_schema_mismatch(
    mutation: object,
    message: str,
) -> None:
    value = discovery()
    assert callable(mutation)
    mutation(value)

    with pytest.raises(ViceError, match=message) as captured:
        validate_discovery(value)

    assert captured.value.code == "vice_connector_incompatible"


def test_discovery_maps_missing_active_target_to_install_guidance() -> None:
    with pytest.raises(ViceError) as captured:
        validate_discovery(
            {
                "ok": False,
                "error": {
                    "code": "no_active_trace",
                    "message": "no active trace",
                },
            }
        )

    assert captured.value.code == "vice_connector_unavailable"
    assert "VICE C64 Debugger" in str(captured.value.details["guidance"])


def test_capabilities_validate_identity_versions_limits_and_exact_v1_set() -> None:
    info = validate_capabilities(capability_envelope())

    assert info.instance_id == INSTANCE
    assert info.connector_version == "1.0.0"
    assert info.vice_version == "3.10.0"
    assert info.limits["memory_read_bytes"] == 65_536


def test_newer_minor_allows_only_capability_superset() -> None:
    contract = load_contract()
    required = list(contract["capabilities"])  # type: ignore[arg-type]

    assert validate_capabilities(
        capability_envelope(minor=1, capabilities=[*required, "future"])
    ).api_minor == 1
    with pytest.raises(ViceError, match="omits required"):
        validate_capabilities(
            capability_envelope(minor=1, capabilities=required[:-1])
        )


def test_api_1_0_rejects_extra_capability_and_changed_instance() -> None:
    contract = load_contract()
    required = list(contract["capabilities"])  # type: ignore[arg-type]
    with pytest.raises(ViceError, match="exactly"):
        validate_capabilities(
            capability_envelope(capabilities=[*required, "future"])
        )

    value = capability_envelope()
    result = value["result"]
    assert isinstance(result, dict)
    result["instance_id"] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    with pytest.raises(ViceError, match="disagree"):
        validate_capabilities(value)


def test_connector_envelope_parser_preserves_failure_and_detects_replacement() -> None:
    failure = connector_envelope(
        {
            "code": "vice_timeout",
            "message": "read timed out",
            "outcome_unknown": True,
            "command_sequence": 999,
        },
        ok=False,
    )
    with pytest.raises(ViceError) as captured:
        parse_connector_envelope(
            invocation(failure), expected_instance=INSTANCE
        )
    assert captured.value.code == "vice_timeout"
    assert captured.value.details["outcome_unknown"] is True
    assert captured.value.details["command_sequence"] == 7

    replacement = connector_envelope(
        {}, instance_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    )
    with pytest.raises(ViceError) as changed:
        parse_connector_envelope(
            invocation(replacement), expected_instance=INSTANCE
        )
    assert changed.value.code == "vice_connector_changed"


def test_generic_timeout_is_distinct_from_connector_timeout() -> None:
    with pytest.raises(ViceError) as captured:
        parse_connector_envelope(
            {
                "ok": False,
                "error": {
                    "code": "target_method_timeout",
                    "message": "late",
                },
                "timeout_layer": "generic",
                "outcome_unknown": True,
            },
            expected_instance=INSTANCE,
        )

    assert captured.value.code == "vice_target_method_timeout"
    assert captured.value.details["timeout_layer"] == "generic"


def test_handshake_parser_rejects_non_string_result() -> None:
    with pytest.raises(ViceError, match="JSON string"):
        parse_handshake_envelope({"ok": True, "result": {}})


def test_handshake_parser_reports_target_replacement() -> None:
    with pytest.raises(ViceError) as captured:
        parse_handshake_envelope(
            {
                "ok": False,
                "error": {
                    "code": "stale_target_token",
                    "message": "owner changed",
                },
            }
        )

    assert captured.value.code == "vice_connector_changed"


@pytest.mark.skipif(
    "C64_MCP_CONTRACT_REPO_CHECK" not in __import__("os").environ,
    reason="cross-repository contract check is opt-in",
)
def test_packaged_contract_matches_explicit_connector_fixture(
) -> None:
    connector = os.environ.get("GHIDRA_VICE_CONNECTOR_REPO")
    c64 = os.environ.get("C64_MCP_REPO")
    assert connector and c64
    source = Path(connector) / "contracts/c64-vice-api-v1.json"
    packaged = (
        Path(c64)
        / "src/c64_mcp/contracts/c64-vice-api-v1.json"
    )
    assert json.loads(source.read_text()) == json.loads(packaged.read_text())
