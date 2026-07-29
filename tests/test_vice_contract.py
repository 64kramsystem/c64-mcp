import json

import pytest

from c64_mcp.errors import ViceError
from c64_mcp.vice_contract import (
    REQUIRED_METHOD_ARGS,
    parse_connector_envelope,
    parse_handshake_envelope,
    validate_capabilities,
    validate_discovery,
)

INSTANCE = "opaque-instance"


def methods():
    return [
        {
            "name": name,
            "parameters": [{"name": argument} for argument in sorted(arguments)],
        }
        for name, arguments in REQUIRED_METHOD_ARGS.items()
    ]


def envelope(result=None, *, ok=True, instance=INSTANCE):
    value = {
        "api": "c64.vice/1",
        "ok": ok,
        "command_sequence": 4,
        "instance_id": instance,
        "connection_state": "connected",
        "execution_state": "stopped",
        "stop_count": 3,
        "pc": 0xC000,
    }
    value["result" if ok else "error"] = {} if result is None else result
    return value


def invocation(value):
    return {"ok": True, "result": json.dumps(value)}


def test_discovery_checks_only_methods_and_arguments_the_client_uses():
    discovery = {
        "ok": True,
        "target_token": "target",
        "methods": methods(),
    }
    assert validate_discovery(discovery) == "target"

    discovery["methods"] = methods()[1:]
    with pytest.raises(ViceError, match="required method"):
        validate_discovery(discovery)


def test_discovery_rejects_a_missing_keyword_argument():
    records = methods()
    records[0]["parameters"] = []
    with pytest.raises(ViceError, match="missing parameters"):
        validate_discovery({"ok": True, "target_token": "target", "methods": records})


def test_capabilities_validate_identity_machine_and_operational_limits():
    value = envelope(
        {
            "protocol": "c64.vice",
            "api_major": 1,
            "machine": "c64",
            "instance_id": INSTANCE,
            "connector_name": "ghidra-vice-connector",
            "connector_version": "1.0.0",
            "vice_version": "3.11",
            "limits": {
                "keyboard_feed_bytes": 255,
                "memory_chunk_bytes": 16_384,
            },
        }
    )
    info = validate_capabilities(value)
    assert info.instance_id == INSTANCE

    value["result"]["limits"]["memory_chunk_bytes"] = 1024
    with pytest.raises(ViceError, match="too small"):
        validate_capabilities(value)


def test_connector_envelope_carries_stop_state_on_success_and_failure():
    parsed = parse_connector_envelope(
        invocation(envelope({"value": 1})),
        expected_instance=INSTANCE,
    )
    assert parsed["stop_count"] == 3
    assert parsed["pc"] == 0xC000

    failed = envelope({"code": "vice_timeout", "message": "timed out"}, ok=False)
    with pytest.raises(ViceError) as caught:
        parse_connector_envelope(invocation(failed), expected_instance=INSTANCE)
    assert caught.value.details["stop_count"] == 3
    assert caught.value.details["pc"] == 0xC000


def test_changed_instance_is_rejected_and_handshake_decoder_is_unbound():
    decoded = parse_handshake_envelope(invocation(envelope()))
    assert decoded["instance_id"] == INSTANCE
    with pytest.raises(ViceError, match="instance changed"):
        parse_connector_envelope(
            invocation(envelope(instance="replacement")),
            expected_instance=INSTANCE,
        )
