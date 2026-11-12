"""Frame controls against an explicitly selected disposable Ghidra/VICE stack."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from mcp import Client

from c64_mcp.config import Settings
from c64_mcp.ghidra_client import GhidraClient
from c64_mcp.server import create_server


@pytest.mark.asyncio
async def test_frame_tools_disposable_stack():
    socket_path = os.environ.get("C64_FRAME_TEST_SOCKET")
    if not socket_path or os.environ.get("C64_FRAME_TEST_DISPOSABLE") != "1":
        pytest.skip("requires explicit disposable stack and C64_FRAME_TEST_SOCKET")
    server = create_server(
        Settings.from_environ({}), ghidra=GhidraClient(socket_path=socket_path)
    )
    async with Client(server, mode="2026-07-28") as client:

        async def call(name, **arguments):
            response = await client.call_tool(name, arguments)
            assert not response.is_error, response
            result = response.structured_content
            assert result["ok"] is True, result
            return result

        async def registers():
            result = await call("vice_get_registers")
            return {
                item["name"]: item["value"] for item in result["result"]["registers"]
            }

        async def memory():
            result = await call(
                "vice_read_memory", bank_id=ram, start=0xC100, end=0xC100, max_bytes=1
            )
            return int(result["result"]["bytes"], 16)

        await call("vice_connect")
        banks = (await call("vice_list_banks"))["result"]["banks"]
        ram = next(bank["id"] for bank in banks if bank["name"].lower() == "ram")
        fixture = Path(__file__).parent / "fixtures/frame-counter.hex"
        code = bytes.fromhex(
            " ".join(line.split("#", 1)[0] for line in fixture.read_text().splitlines())
        )
        await call("vice_write_memory", bank_id=ram, start=0xC000, bytes=code.hex())
        await call("vice_write_memory", bank_id=ram, start=0xC100, bytes="00")
        await call("vice_set_registers", values={"PC": 0xC000})
        before = (await call("vice_status"))["stop_count"]
        first = await call("vice_advance_frames", frame_count=1)
        assert first["result"]["reason"] == "frames"
        assert first["result"]["frames_completed"] == 1
        assert first["stop_count"] == before + 1
        assert (await registers())["LIN"] == 0
        before_counter = await memory()
        three = await call("vice_advance_frames", frame_count=3)
        assert three["result"]["reason"] == "frames"
        assert three["result"]["frames_completed"] == 3
        assert three["stop_count"] == first["stop_count"] + 1
        assert (await memory() - before_counter) % 256 == 3
        assert (await call("vice_list_checkpoints"))["result"]["checkpoints"] == []
        current = (await registers())["PC"]
        same = await call("vice_run_until", address=current, max_frames=2)
        assert same["result"]["reason"] == "target"
        assert same["result"]["frames_completed"] == 0
        assert same["stop_count"] == three["stop_count"]
        await call("vice_set_registers", values={"PC": 0xC000})
        same_after_set = await call("vice_run_until", address=0xC000, max_frames=2)
        assert same_after_set["result"]["reason"] == "target"
        assert same_after_set["pc"] == 0xC000
        assert same_after_set["stop_count"] == same["stop_count"]
        limited = await call("vice_run_until", address=0x1000, max_frames=2)
        assert limited["result"]["reason"] == "frame_limit"
        assert limited["result"]["frames_completed"] == 2
        previous = await memory()
        target = await call("vice_run_until", address=0xC00A, max_frames=2)
        assert target["result"]["reason"] == "target"
        assert target["pc"] == 0xC00A
        assert await memory() == previous
        cp = (await call("vice_set_checkpoint", start=0xC00D, end=0xC00D))["result"][
            "checkpoint"
        ]
        stopped = await call("vice_advance_frames", frame_count=3)
        assert stopped["result"]["reason"] == "checkpoint"
        assert [
            item["number"] for item in stopped["result"]["event"]["checkpoints"]
        ] == [cp["number"]]
        assert [
            item["number"]
            for item in (await call("vice_list_checkpoints"))["result"]["checkpoints"]
        ] == [cp["number"]]
        await call("vice_delete_checkpoint", number=cp["number"])
        timeout = await call("vice_advance_frames", frame_count=1000000, timeout_ms=10)
        assert timeout["result"]["reason"] == "timeout"
        assert timeout["execution_state"] == "stopped"
        assert (await call("vice_list_checkpoints"))["result"]["checkpoints"] == []
        fixture = Path(__file__).parent / "fixtures/mid-raster-line.hex"
        program = bytes.fromhex(
            " ".join(text.split("#", 1)[0] for text in fixture.read_text().splitlines())
        )
        await call("vice_write_memory", bank_id=ram, start=0xC200, bytes=program.hex())
        await call("vice_set_registers", values={"PC": 0xC200})
        positioned = await call("vice_run_until", address=0xC207, max_frames=2)
        assert positioned["result"]["reason"] == "target"
        assert (await registers())["LIN"] == 100
        advanced = await call("vice_advance_frames", frame_count=1)
        assert advanced["result"]["frames_completed"] == 1
        assert (await registers())["LIN"] == 0
        last_line = os.environ.get("C64_FRAME_TEST_LAST_LINE")
        if last_line:
            line = int(last_line)
            fixture = Path(__file__).parent / "fixtures/last-raster-line.hex"
            program = bytearray(
                bytes.fromhex(
                    " ".join(
                        text.split("#", 1)[0]
                        for text in fixture.read_text().splitlines()
                    )
                )
            )
            program[9] = line & 0xFF
            await call(
                "vice_write_memory", bank_id=ram, start=0xC200, bytes=program.hex()
            )
            await call("vice_set_registers", values={"PC": 0xC200})
            positioned = await call("vice_run_until", address=0xC20C, max_frames=2)
            assert positioned["result"]["reason"] == "target"
            assert (await registers())["LIN"] == line
            advanced = await call("vice_advance_frames", frame_count=1)
            assert advanced["result"]["frames_completed"] == 1
            assert (await registers())["LIN"] == 0
            assert (await call("vice_list_checkpoints"))["result"]["checkpoints"] == []
        await call("vice_disconnect")
