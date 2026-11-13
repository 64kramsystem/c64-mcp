from __future__ import annotations

import os

import pytest

from c64_mcp.config import Settings
from c64_mcp.ghidra_client import GhidraClient
from c64_mcp.vice import ViceSession


def live_session() -> ViceSession:
    if os.environ.get("C64_MCP_VICE_LIVE") != "1":
        pytest.skip(
            "set C64_MCP_VICE_LIVE=1 with a disposable active VICE C64 Debugger trace"
        )
    settings = Settings.from_environ(os.environ)
    return ViceSession(
        GhidraClient(
            timeout=settings.ghidra_timeout,
            socket_path=settings.ghidra_mcp_socket,
        )
    )


def test_live_connector_contract_and_read_only_tools() -> None:
    session = live_session()

    connected = session.connect()
    assert connected["ok"] is True, connected
    assert session.status()["state"] in {"connected", "stopped", "running"}

    registers = session.get_registers()
    banks = session.list_banks()
    checkpoints = session.list_checkpoints()
    memory = session.read_memory(
        bank_id=0,
        start=0,
        end=15,
        max_bytes=16,
    )

    assert registers["ok"] is True, registers
    assert banks["ok"] is True, banks
    assert checkpoints["ok"] is True, checkpoints
    assert memory["ok"] is True, memory
    assert memory["result"]["byte_count"] == 16  # type: ignore[index]
    assert session.disconnect()["connector_externally_owned"] is True


def test_live_disposable_mutating_surface() -> None:
    if os.environ.get("C64_MCP_VICE_MUTATE") != "1":
        pytest.skip(
            "set C64_MCP_VICE_MUTATE=1 only for a disposable "
            "VICE process and debugger trace"
        )
    session = live_session()
    assert session.connect()["ok"] is True

    registers = session.get_registers(names=["A"])
    assert registers["ok"] is True, registers
    record = registers["result"]["registers"][0]  # type: ignore[index]
    original_a = record["value"]
    assert session.set_registers(values={"A": original_a})["ok"] is True

    memory = session.read_memory(bank_id=0, start=0x0200, end=0x0200, max_bytes=1)
    assert memory["ok"] is True, memory
    original_byte = memory["result"]["bytes"]  # type: ignore[index]
    assert (
        session.write_memory(bank_id=0, start=0x0200, bytes=original_byte)["ok"] is True
    )

    created = session.set_checkpoint(start=0x0200, end=0x0200, enabled=False)
    assert created["ok"] is True, created
    number = created["result"]["checkpoint"]["number"]  # type: ignore[index]
    assert session.toggle_checkpoint(number=number, enabled=True)["ok"] is True
    assert session.toggle_checkpoint(number=number, enabled=False)["ok"] is True
    assert session.delete_checkpoint(number=number)["ok"] is True

    assert session.step()["ok"] is True
    assert session.next()["ok"] is True
    assert session.resume()["ok"] is True
    stopped = session.interrupt()
    assert stopped["ok"] is True, stopped
    stop_count = stopped.get("stop_count")
    if isinstance(stop_count, int):
        waited = session.wait_for_stop(
            after_stop_count=max(0, stop_count - 1),
            timeout_ms=1_000,
        )
        assert waited["ok"] is True, waited
    assert session.reset(kind="soft")["ok"] is True


def test_live_conditions_resources_and_autostart(tmp_path) -> None:
    if os.environ.get("C64_MCP_VICE_MUTATE") != "1":
        pytest.skip("requires a disposable VICE process")
    session = live_session()

    def checked(label, result):
        print(label, result, flush=True)
        assert result["ok"] is True, result
        return result["result"]

    assert session.connect()["ok"] is True
    if session.status()["state"] == "running":
        checked("interrupt", session.interrupt())
    before = checked("get AutostartWarp", session.get_resource(name="AutostartWarp"))["value"]
    try:
        changed = 0 if before else 1
        checked("set AutostartWarp", session.set_resource(name="AutostartWarp", value=str(changed)))
        assert checked("get changed AutostartWarp", session.get_resource(name="AutostartWarp"))["value"] == changed
    finally:
        checked("restore AutostartWarp", session.set_resource(name="AutostartWarp", value=str(before)))

    checked("write loop", session.write_memory(bank_id=0, start=0xC000, bytes="ee00c1ad00c14c00c0"))
    checked("zero counter", session.write_memory(bank_id=0, start=0xC100, bytes="00"))
    checked("set PC", session.set_registers(values={"PC": 0xC000}))
    checkpoint = checked("set conditional checkpoint", session.set_checkpoint(
        start=0xC006, end=0xC006, condition="A == $02"
    ))["checkpoint"]
    assert checkpoint["has_condition"] is True
    try:
        count = session.status()["stop_count"]
        checked("resume", session.resume())
        stopped = session.wait_for_stop(after_stop_count=count, timeout_ms=5000)
        print("conditional stop", stopped, flush=True)
        assert stopped["ok"] is True, stopped
        assert stopped["pc"] == 0xC006
        registers = checked("registers at conditional stop", session.get_registers(names=["A"]))
        assert registers["registers"][0]["value"] == 2
    finally:
        checked("delete conditional checkpoint", session.delete_checkpoint(number=checkpoint["number"]))

    prg = tmp_path / "test.prg"
    prg.write_bytes(bytes.fromhex("01080000"))
    checked("autostart scheduled", session.autostart(filename=str(prg), run=False))
    checked("interrupt after autostart", session.interrupt())
