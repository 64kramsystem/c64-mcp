"""CPU history against an explicitly selected disposable Ghidra/VICE stack."""

import os
from pathlib import Path

import pytest
from mcp import Client

from c64_mcp.config import Settings
from c64_mcp.ghidra_client import GhidraClient
from c64_mcp.server import create_server


@pytest.mark.asyncio
async def test_cpu_history_disposable_stack():
    socket_path = os.environ.get("C64_FRAME_TEST_SOCKET")
    if not socket_path or os.environ.get("C64_FRAME_TEST_DISPOSABLE") != "1":
        pytest.skip("requires explicit disposable stack")
    ghidra = GhidraClient(socket_path=socket_path)
    server = create_server(Settings.from_environ({}), ghidra=ghidra)
    async with Client(server, mode="2026-07-28") as client:

        async def call(name, **args):
            response = await client.call_tool(name, args)
            assert not response.is_error, response
            result = response.structured_content
            assert result["ok"], result
            return result

        for invalid in (True, "2"):
            response = await client.call_tool("vice_cpu_history", {"count": invalid})
            assert response.is_error
        await call("vice_connect")
        banks = (await call("vice_list_banks"))["result"]["banks"]
        ram = next(b["id"] for b in banks if b["name"].lower() == "ram")
        code = bytes.fromhex(
            (Path(__file__).parent / "fixtures/cpu-history.hex").read_text()
        )
        await call("vice_write_memory", bank_id=ram, start=0xC000, bytes=code.hex())
        await call(
            "vice_set_registers",
            values={"PC": 0xC000, "A": 0, "X": 0, "Y": 0, "SP": 255, "FL": 0x24},
        )
        await call("vice_step", count=3)
        before = await call("vice_get_registers")
        status = await call("vice_status")
        trace_before = ghidra.call_get("/debugger/registers", {})
        history = (await call("vice_cpu_history", count=3))["result"]
        assert ghidra.call_get("/debugger/registers", {}) == trace_before
        assert history["count"] == 3
        entries = history["entries"]
        regs = [{r["name"]: r["value"] for r in e["registers"]} for e in entries]
        assert [r["PC"] for r in regs] == [0xC000, 0xC003, 0xC006]
        assert [r["A"] for r in regs] == [0, 0x42, 0x42]
        assert [r["X"] for r in regs] == [0, 0, 0x42]
        assert [e["instruction_prefix"] for e in entries] == [
            "ad10c0",
            "ae10c0",
            "ac10c0",
        ]
        assert all(
            later["cycle"] - earlier["cycle"] >= 4
            for earlier, later in zip(entries, entries[1:], strict=False)
        )
        assert [r["Y"] for r in regs] == [0, 0, 0]
        assert [r["SP"] for r in regs] == [255, 255, 255]
        assert [r["FL"] for r in regs] == [0x24, 0x24, 0x24]
        assert all(set(r) == {"PC", "A", "X", "Y", "SP", "FL"} for r in regs)
        assert (await call("vice_get_registers"))["result"] == before["result"]
        assert (await call("vice_status"))["stop_count"] == status["stop_count"]
        await call("vice_write_memory", bank_id=ram, start=0xC000, bytes="ea")
        assert (await call("vice_cpu_history", count=3))["result"] == history
