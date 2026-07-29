import json

import pytest

from c64_mcp.vice import ViceSession
from c64_mcp.vice_contract import REQUIRED_METHOD_ARGS

INSTANCE = "opaque-instance"


def envelope(result=None, *, sequence=1, stop_count=0, pc=0xC000):
    return {
        "api": "c64.vice/1",
        "ok": True,
        "command_sequence": sequence,
        "instance_id": INSTANCE,
        "connection_state": "connected",
        "execution_state": "stopped",
        "stop_count": stop_count,
        "pc": pc,
        "result": {} if result is None else result,
    }


class FakeGhidra:
    def __init__(self):
        self.calls = []
        self.sequence = 0
        self.stop_count = 0
        self.memory = bytes(range(256)) * 256
        self.writes = []

    def target_methods(self):
        return {
            "ok": True,
            "target_token": "target",
            "methods": [
                {
                    "name": name,
                    "parameters": [
                        {"name": argument} for argument in sorted(arguments)
                    ],
                }
                for name, arguments in REQUIRED_METHOD_ARGS.items()
            ],
        }

    def invoke_target_method(
        self,
        target_token,
        method,
        arguments,
        *,
        connector_timeout_ms,
    ):
        self.calls.append((method, arguments, connector_timeout_ms))
        self.sequence += 1
        if method == "c64_vice_v1_capabilities":
            result = {
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
                    "display_capture_chunk_bytes": 16_384,
                },
            }
        elif method == "c64_vice_v1_status":
            result = {}
        elif method == "c64_vice_v1_read_memory":
            start = arguments["start"]
            end = min(
                arguments["end"],
                start + arguments["max_bytes"] - 1,
            )
            data = self.memory[start : end + 1]
            result = {
                "bytes": data.hex(),
                "byte_count": len(data),
                "complete": end == arguments["end"],
                "next_address": None if end == arguments["end"] else end + 1,
            }
        else:
            result = {"method": method}
        return {
            "ok": True,
            "result": json.dumps(
                envelope(
                    result,
                    sequence=self.sequence,
                    stop_count=self.stop_count,
                )
            ),
        }

    def write_memory_bytes_result(
        self,
        program,
        start,
        data,
        *,
        dry_run=True,
        conflict_policy="error",
    ):
        self.writes.append((program, start, data, dry_run, conflict_policy))
        return {"ok": True, "committed": not dry_run}


def connected():
    fake = FakeGhidra()
    session = ViceSession(fake)
    assert session.connect()["ok"] is True
    return fake, session


def test_connect_is_idempotent_and_disconnect_is_local():
    fake, session = connected()
    assert session.connect()["idempotent"] is True
    before = len(fake.calls)
    assert session.status()["state"] == "stopped"
    assert session.disconnect()["released"] is True
    assert len(fake.calls) == before


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
            lambda value: value.read_memory(bank_id=0, start=0x1000, end=0x1001),
            "c64_vice_v1_read_memory",
        ),
        (
            lambda value: value.write_memory(bank_id=0, start=0x1000, bytes="aabb"),
            "c64_vice_v1_write_memory",
        ),
        (
            lambda value: value.toggle_checkpoint(number=1, enabled=False),
            "c64_vice_v1_toggle_checkpoint",
        ),
        (lambda value: value.step(), "c64_vice_v1_step"),
        (lambda value: value.resume(), "c64_vice_v1_resume"),
        (lambda value: value.interrupt(), "c64_vice_v1_interrupt"),
        (
            lambda value: value.wait_for_stop(after_stop_count=0, timeout_ms=100),
            "c64_vice_v1_wait_for_stop",
        ),
        (
            lambda value: value.feed_keyboard(data="20"),
            "c64_vice_v1_feed_keyboard",
        ),
        (
            lambda value: value.set_joyport(port=2, value=0xEF),
            "c64_vice_v1_set_joyport",
        ),
        (
            lambda value: value.save_snapshot(filename="/tmp/test.vsf"),
            "c64_vice_v1_save_snapshot",
        ),
        (
            lambda value: value.load_snapshot(filename="/tmp/test.vsf"),
            "c64_vice_v1_load_snapshot",
        ),
    ],
)
def test_public_primitives_map_to_one_connector_method(call, method):
    fake, session = connected()
    before = len(fake.calls)
    result = call(session)
    assert result["ok"] is True
    assert [item[0] for item in fake.calls[before:]] == [method]


def test_memory_transfer_caps_are_enforced_before_invocation():
    fake, session = connected()
    before = len(fake.calls)
    result = session.write_memory(bank_id=0, start=0, bytes=[0] * 16_385)
    assert result["ok"] is False
    assert len(fake.calls) == before


def test_copy_streams_chunks_and_writes_once_without_returning_payload():
    fake, session = connected()
    result = session.copy_memory_to_ghidra(
        bank_id=0,
        start=0,
        end=32_767,
        program="game",
        destination="ram:0000",
        dry_run=False,
    )
    reads = [call for call in fake.calls if call[0] == "c64_vice_v1_read_memory"]
    assert len(reads) == 2
    assert result["ok"] is True
    assert result["byte_count"] == 32_768
    assert "bytes" not in result
    assert len(fake.writes) == 1
    assert fake.writes[0][4] == "overwrite_bytes"


def test_copy_rejects_an_intervening_stop_before_writing():
    class MovingFake(FakeGhidra):
        def invoke_target_method(self, *args, **kwargs):
            result = super().invoke_target_method(*args, **kwargs)
            if args[1] == "c64_vice_v1_read_memory":
                self.stop_count += 1
            return result

    fake = MovingFake()
    session = ViceSession(fake)
    assert session.connect()["ok"] is True
    result = session.copy_memory_to_ghidra(
        bank_id=0,
        start=0,
        end=32_767,
        program="game",
        destination="ram:0000",
    )
    assert result["ok"] is False
    assert fake.writes == []


def test_display_chunk_methods_do_not_invent_timeout_arguments():
    fake, session = connected()
    session.read_display_capture(capture_id="capture", offset=0)
    assert "timeout_ms" not in fake.calls[-1][1]
    session.discard_display_capture(capture_id="capture")
    assert "timeout_ms" not in fake.calls[-1][1]
