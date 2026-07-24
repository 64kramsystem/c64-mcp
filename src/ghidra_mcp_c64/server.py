"""MCP server construction."""

from __future__ import annotations

import asyncio
from typing import Any, Literal, cast

from mcp.server.fastmcp import FastMCP

from .config import Settings
from .ghidra_client import GhidraClient
from .profile_tools import ProfileGhidraClient
from .profile_tools import (
    apply_c64_symbol_profile as apply_profile,
)
from .profile_tools import (
    get_c64_symbol_profile as get_profile,
)
from .text.tools import BytesInput, TextGhidraClient
from .text.tools import decode_c64_text as decode_text
from .text.tools import define_c64_text as define_text
from .text.tools import search_c64_text as search_text
from .vice import ViceGhidraClient, ViceSession

EncodingArgument = Literal[
    "petscii_upper",
    "petscii_lower",
    "screen_code_upper",
    "screen_code_lower",
]
HighBitArgument = Literal["exact", "strip", "annotate_reverse"]
ControlArgument = Literal["names", "escaped", "unicode"]
QueryModeArgument = Literal["text", "bytes"]
ConflictPolicyArgument = Literal["error", "keep", "replace"]
CopyConflictPolicyArgument = Literal["error", "overwrite_bytes"]
ResetKindArgument = Literal["soft", "hard", "drive8", "drive9"]


def create_server(
    settings: Settings,
    ghidra: Any | None = None,
) -> FastMCP:
    """Create the stdio server without opening external connections.

    Accepting the explicit Ghidra boundary keeps construction testable and
    prevents hidden bridge imports.
    """

    instance = (
        ghidra
        if ghidra is not None
        else GhidraClient(
            settings.ghidra_mcp_url,
            settings.ghidra_auth_token,
            settings.ghidra_timeout,
        )
    )
    text_client = cast(TextGhidraClient, instance)
    profile_client = cast(ProfileGhidraClient, instance)
    vice = ViceSession(cast(ViceGhidraClient, instance))
    server = FastMCP("ghidra-mcp-c64")

    @server.tool()
    async def get_c64_symbol_profile() -> dict[str, object]:
        """Return the complete source-cited bundled C64 symbol profile."""

        return await asyncio.to_thread(get_profile)

    @server.tool()
    async def apply_c64_symbol_profile(
        program: str,
        dry_run: bool = True,
        conflict_policy: ConflictPolicyArgument = "error",
        replace_user_definitions: bool = False,
        create_memory_blocks: bool = False,
    ) -> dict[str, object]:
        """Idempotently apply the bundled profile to a named program."""

        return await asyncio.to_thread(
            apply_profile,
            profile_client,
            program=program,
            dry_run=dry_run,
            conflict_policy=conflict_policy,
            replace_user_definitions=replace_user_definitions,
            create_memory_blocks=create_memory_blocks,
        )

    @server.tool()
    async def decode_c64_text(
        bytes: BytesInput | None = None,
        program: str | None = None,
        start: str | None = None,
        max_length: int | None = None,
        encoding: EncodingArgument = "petscii_upper",
        length: int | None = None,
        terminator: int | None = None,
        prefix_size: int | None = None,
        prefix_includes_self: bool = False,
        high_bit: HighBitArgument = "exact",
        controls: ControlArgument = "names",
        tokens: dict[str, str] | None = None,
        recursive_tokens: bool = False,
        token_recursion_limit: int = 8,
    ) -> dict[str, object]:
        """Decode inline or named-program PETSCII or C64 screen codes."""

        return await asyncio.to_thread(
            decode_text,
            text_client,
            bytes=bytes,
            program=program,
            start=start,
            max_length=max_length,
            encoding=encoding,
            length=length,
            terminator=terminator,
            prefix_size=prefix_size,
            prefix_includes_self=prefix_includes_self,
            high_bit=high_bit,
            controls=controls,
            tokens=tokens,
            recursive_tokens=recursive_tokens,
            token_recursion_limit=token_recursion_limit,
        )

    @server.tool()
    async def search_c64_text(
        program: str,
        start: str,
        end: str,
        query: str | list[int],
        query_mode: QueryModeArgument = "text",
        encoding: EncodingArgument = "petscii_upper",
        length: int | None = None,
        terminator: int | None = None,
        prefix_size: int | None = None,
        prefix_includes_self: bool = False,
        high_bit: HighBitArgument = "exact",
        controls: ControlArgument = "names",
        tokens: dict[str, str] | None = None,
        recursive_tokens: bool = False,
        token_recursion_limit: int = 8,
        stride: int = 1,
        max_scan_bytes: int = 65_536,
        max_results: int = 100,
    ) -> dict[str, object]:
        """Search a bounded Ghidra range for raw or decoded C64 text."""

        return await asyncio.to_thread(
            search_text,
            text_client,
            program=program,
            start=start,
            end=end,
            query=query,
            query_mode=query_mode,
            encoding=encoding,
            length=length,
            terminator=terminator,
            prefix_size=prefix_size,
            prefix_includes_self=prefix_includes_self,
            high_bit=high_bit,
            controls=controls,
            tokens=tokens,
            recursive_tokens=recursive_tokens,
            token_recursion_limit=token_recursion_limit,
            stride=stride,
            max_scan_bytes=max_scan_bytes,
            max_results=max_results,
        )

    @server.tool()
    async def define_c64_text(
        program: str,
        start: str,
        max_length: int | None = None,
        encoding: EncodingArgument = "petscii_upper",
        length: int | None = None,
        terminator: int | None = None,
        prefix_size: int | None = None,
        prefix_includes_self: bool = False,
        high_bit: HighBitArgument = "exact",
        controls: ControlArgument = "names",
        tokens: dict[str, str] | None = None,
        recursive_tokens: bool = False,
        token_recursion_limit: int = 8,
        label: str | None = None,
        namespace: str | None = None,
        comment: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, object]:
        """Decode, type, and annotate an exact C64 text byte range."""

        return await asyncio.to_thread(
            define_text,
            text_client,
            program=program,
            start=start,
            max_length=max_length,
            encoding=encoding,
            length=length,
            terminator=terminator,
            prefix_size=prefix_size,
            prefix_includes_self=prefix_includes_self,
            high_bit=high_bit,
            controls=controls,
            tokens=tokens,
            recursive_tokens=recursive_tokens,
            token_recursion_limit=token_recursion_limit,
            label=label,
            namespace=namespace,
            comment=comment,
            dry_run=dry_run,
        )

    @server.tool()
    async def vice_connect() -> dict[str, object]:
        """Bind to one compatible active Ghidra VICE connector target."""

        return await asyncio.to_thread(vice.connect)

    @server.tool()
    async def vice_disconnect() -> dict[str, object]:
        """Release only the local binding; do not stop connector or VICE."""

        return await asyncio.to_thread(vice.disconnect)

    @server.tool()
    async def vice_status() -> dict[str, object]:
        """Return cached binding state without launching or contacting VICE."""

        return await asyncio.to_thread(vice.status)

    @server.tool()
    async def vice_get_registers(
        names: list[str] | None = None,
        memspace: int = 0,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Read all or selected dynamically discovered VICE registers."""

        return await asyncio.to_thread(
            vice.get_registers,
            names=names,
            memspace=memspace,
            timeout_ms=timeout_ms,
        )

    @server.tool()
    async def vice_set_registers(
        values: dict[str, int],
        memspace: int = 0,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Atomically validate and update a non-empty register map."""

        return await asyncio.to_thread(
            vice.set_registers,
            values=values,
            memspace=memspace,
            timeout_ms=timeout_ms,
        )

    @server.tool()
    async def vice_list_banks(
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """List the complete connector-discovered VICE memory bank map."""

        return await asyncio.to_thread(
            vice.list_banks, timeout_ms=timeout_ms
        )

    @server.tool()
    async def vice_read_memory(
        bank_id: int,
        start: int,
        end: int,
        side_effects: bool = False,
        max_bytes: int = 4096,
        memspace: int = 0,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Read a bounded inclusive 16-bit range from one VICE bank."""

        return await asyncio.to_thread(
            vice.read_memory,
            bank_id=bank_id,
            start=start,
            end=end,
            side_effects=side_effects,
            max_bytes=max_bytes,
            memspace=memspace,
            timeout_ms=timeout_ms,
        )

    @server.tool()
    async def vice_write_memory(
        bank_id: int,
        start: int,
        bytes: BytesInput,
        side_effects: bool = False,
        memspace: int = 0,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Write bounded non-wrapping bytes through the connector."""

        return await asyncio.to_thread(
            vice.write_memory,
            bank_id=bank_id,
            start=start,
            bytes=bytes,
            side_effects=side_effects,
            memspace=memspace,
            timeout_ms=timeout_ms,
        )

    @server.tool()
    async def vice_list_checkpoints(
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """List all VICE checkpoints through the active connector."""

        return await asyncio.to_thread(
            vice.list_checkpoints, timeout_ms=timeout_ms
        )

    @server.tool()
    async def vice_set_checkpoint(
        start: int,
        end: int,
        stop_on_hit: bool = True,
        enabled: bool = True,
        operations: int = 4,
        temporary: bool = False,
        memspace: int = 0,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Create one inclusive VICE checkpoint."""

        return await asyncio.to_thread(
            vice.set_checkpoint,
            start=start,
            end=end,
            stop_on_hit=stop_on_hit,
            enabled=enabled,
            operations=operations,
            temporary=temporary,
            memspace=memspace,
            timeout_ms=timeout_ms,
        )

    @server.tool()
    async def vice_delete_checkpoint(
        number: int,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Delete one VICE checkpoint by number."""

        return await asyncio.to_thread(
            vice.delete_checkpoint,
            number=number,
            timeout_ms=timeout_ms,
        )

    @server.tool()
    async def vice_toggle_checkpoint(
        number: int,
        enabled: bool,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Enable or disable one VICE checkpoint."""

        return await asyncio.to_thread(
            vice.toggle_checkpoint,
            number=number,
            enabled=enabled,
            timeout_ms=timeout_ms,
        )

    @server.tool()
    async def vice_step(
        count: int = 1,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Step one or more instructions and wait for synchronized stop."""

        return await asyncio.to_thread(
            vice.step, count=count, timeout_ms=timeout_ms
        )

    @server.tool()
    async def vice_next(
        count: int = 1,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Step over one or more calls and wait for synchronized stop."""

        return await asyncio.to_thread(
            vice.next, count=count, timeout_ms=timeout_ms
        )

    @server.tool()
    async def vice_finish(
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Run until RTS/RTI completion and synchronized stop."""

        return await asyncio.to_thread(
            vice.finish, timeout_ms=timeout_ms
        )

    @server.tool()
    async def vice_resume(
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Resume execution and wait for the synchronized resumed event."""

        return await asyncio.to_thread(
            vice.resume, timeout_ms=timeout_ms
        )

    @server.tool()
    async def vice_interrupt(
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Enter the VICE monitor and wait for synchronized stop."""

        return await asyncio.to_thread(
            vice.interrupt, timeout_ms=timeout_ms
        )

    @server.tool()
    async def vice_wait_for_stop(
        after_sequence: int,
        timeout_ms: int,
    ) -> dict[str, object]:
        """Non-consumingly await a stopped event after a public sequence."""

        return await asyncio.to_thread(
            vice.wait_for_stop,
            after_sequence=after_sequence,
            timeout_ms=timeout_ms,
        )

    @server.tool()
    async def vice_reset(
        kind: ResetKindArgument = "soft",
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Reset the C64 or drive 8/9 through the active connector."""

        return await asyncio.to_thread(
            vice.reset, kind=kind, timeout_ms=timeout_ms
        )

    @server.tool()
    async def copy_vice_memory_to_ghidra(
        bank_id: int,
        start: int,
        end: int,
        program: str,
        destination: str,
        conflict_policy: CopyConflictPolicyArgument = "error",
        dry_run: bool = True,
        memspace: int = 0,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Read VICE once, digest it, then preview or commit one Ghidra write."""

        return await asyncio.to_thread(
            vice.copy_memory_to_ghidra,
            bank_id=bank_id,
            start=start,
            end=end,
            program=program,
            destination=destination,
            conflict_policy=conflict_policy,
            dry_run=dry_run,
            memspace=memspace,
            timeout_ms=timeout_ms,
        )

    return server
