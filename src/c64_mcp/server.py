"""MCP server construction."""

from __future__ import annotations

import asyncio
from typing import Any, Literal, cast

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult

from .config import Settings
from .ghidra_client import GhidraClient
from .graphics.capture import CaptureViceSession
from .graphics.capture import vice_capture_screen as capture_screen
from .graphics.sources import GraphicsGhidraClient, GraphicsViceSession
from .graphics.tools import decode_c64_char_screen as decode_char_screen
from .graphics.tools import decode_c64_charset as decode_charset
from .graphics.tools import decode_c64_hires_bitmap as decode_hires_bitmap
from .graphics.tools import (
    decode_c64_multicolor_bitmap as decode_multicolor_bitmap,
)
from .graphics.tools import decode_c64_sprites as decode_sprites
from .profile_tools import ProfileGhidraClient
from .profile_tools import (
    apply_c64_symbol_profile as apply_profile,
)
from .profile_tools import (
    get_c64_symbol_profile as get_profile,
)
from .reversing import ReversingGhidraClient, capture_transition
from .reversing import find_split_pointer_partners as find_split_partners
from .reversing import import_vice_phase as import_phase
from .reversing import search_6502_indexed_operands as search_indexed
from .text.tools import BytesInput, TextGhidraClient
from .text.tools import decode_c64_text as decode_text
from .text.tools import define_c64_text as define_text
from .text.tools import search_c64_text as search_text
from .tool_profiles import ToolProfileRegistry
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
    graphics_client = cast(GraphicsGhidraClient, instance)
    vice = ViceSession(cast(ViceGhidraClient, instance))
    graphics_vice = cast(GraphicsViceSession, vice)
    capture_vice = cast(CaptureViceSession, vice)
    reversing_client = cast(ReversingGhidraClient, instance)
    server = FastMCP("c64-mcp")
    registry = ToolProfileRegistry(server, settings.tool_profile)

    @registry.tool("symbols")
    async def get_c64_symbol_profile() -> dict[str, object]:
        """Return the complete source-cited bundled C64 symbol profile."""

        return await asyncio.to_thread(get_profile)

    @registry.tool("symbols")
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

    @registry.tool("text")
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

    @registry.tool("text")
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

    @registry.tool("text")
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

    @registry.tool("graphics")
    async def decode_c64_hires_bitmap(
        bitmap: dict[str, Any],
        screen: dict[str, Any],
        columns: int = 40,
        rows: int = 25,
        palette: list[Any] | None = None,
        output_path: str | None = None,
        overwrite: bool = False,
        allow_non_atomic_vice_reads: bool = False,
    ) -> CallToolResult:
        """Decode C64 hires bitmap bytes into an indexed PNG."""

        return await asyncio.to_thread(
            decode_hires_bitmap,
            graphics_client,
            graphics_vice,
            bitmap=bitmap,
            screen=screen,
            columns=columns,
            rows=rows,
            palette=palette,
            output_path=output_path,
            overwrite=overwrite,
            allow_non_atomic_vice_reads=allow_non_atomic_vice_reads,
        )

    @registry.tool("graphics")
    async def decode_c64_multicolor_bitmap(
        bitmap: dict[str, Any],
        screen: dict[str, Any],
        color: dict[str, Any],
        columns: int = 40,
        rows: int = 25,
        background: int = 0,
        palette: list[Any] | None = None,
        output_path: str | None = None,
        overwrite: bool = False,
        allow_non_atomic_vice_reads: bool = False,
    ) -> CallToolResult:
        """Decode C64 multicolor bitmap bytes into an indexed PNG."""

        return await asyncio.to_thread(
            decode_multicolor_bitmap,
            graphics_client,
            graphics_vice,
            bitmap=bitmap,
            screen=screen,
            color=color,
            columns=columns,
            rows=rows,
            background=background,
            palette=palette,
            output_path=output_path,
            overwrite=overwrite,
            allow_non_atomic_vice_reads=allow_non_atomic_vice_reads,
        )

    @registry.tool("graphics")
    async def decode_c64_charset(
        charset: dict[str, Any],
        glyph_count: int = 256,
        sheet_columns: int = 16,
        foreground: int = 1,
        background: int = 0,
        multicolor: bool = False,
        background_1: int | None = None,
        background_2: int | None = None,
        palette: list[Any] | None = None,
        output_path: str | None = None,
        overwrite: bool = False,
        allow_non_atomic_vice_reads: bool = False,
    ) -> CallToolResult:
        """Decode a C64 character set into an indexed PNG glyph sheet."""

        return await asyncio.to_thread(
            decode_charset,
            graphics_client,
            graphics_vice,
            charset=charset,
            glyph_count=glyph_count,
            sheet_columns=sheet_columns,
            foreground=foreground,
            background=background,
            multicolor=multicolor,
            background_1=background_1,
            background_2=background_2,
            palette=palette,
            output_path=output_path,
            overwrite=overwrite,
            allow_non_atomic_vice_reads=allow_non_atomic_vice_reads,
        )

    @registry.tool("graphics")
    async def decode_c64_char_screen(
        screen: dict[str, Any],
        charset: dict[str, Any],
        color: dict[str, Any] | None = None,
        columns: int = 40,
        rows: int = 25,
        background: int = 0,
        foreground: int = 1,
        multicolor: bool = False,
        background_1: int | None = None,
        background_2: int | None = None,
        palette: list[Any] | None = None,
        output_path: str | None = None,
        overwrite: bool = False,
        allow_non_atomic_vice_reads: bool = False,
    ) -> CallToolResult:
        """Decode C64 text-mode screen codes into an indexed PNG."""

        return await asyncio.to_thread(
            decode_char_screen,
            graphics_client,
            graphics_vice,
            screen=screen,
            charset=charset,
            color=color,
            columns=columns,
            rows=rows,
            background=background,
            foreground=foreground,
            multicolor=multicolor,
            background_1=background_1,
            background_2=background_2,
            palette=palette,
            output_path=output_path,
            overwrite=overwrite,
            allow_non_atomic_vice_reads=allow_non_atomic_vice_reads,
        )

    @registry.tool("graphics")
    async def decode_c64_sprites(
        sprites: dict[str, Any],
        sprite_count: int,
        sprite_colors: list[int],
        sprite_stride: int = 64,
        sheet_columns: int = 8,
        multicolor: bool = False,
        multicolor_0: int | None = None,
        multicolor_1: int | None = None,
        background: int = 0,
        palette: list[Any] | None = None,
        output_path: str | None = None,
        overwrite: bool = False,
        allow_non_atomic_vice_reads: bool = False,
    ) -> CallToolResult:
        """Decode C64 sprite definitions into an indexed PNG sheet."""

        return await asyncio.to_thread(
            decode_sprites,
            graphics_client,
            graphics_vice,
            sprites=sprites,
            sprite_count=sprite_count,
            sprite_colors=sprite_colors,
            sprite_stride=sprite_stride,
            sheet_columns=sheet_columns,
            multicolor=multicolor,
            multicolor_0=multicolor_0,
            multicolor_1=multicolor_1,
            background=background,
            palette=palette,
            output_path=output_path,
            overwrite=overwrite,
            allow_non_atomic_vice_reads=allow_non_atomic_vice_reads,
        )

    @registry.tool("vice")
    async def vice_connect() -> dict[str, object]:
        """Bind to one compatible active Ghidra VICE connector target."""

        return await asyncio.to_thread(vice.connect)

    @registry.tool("vice")
    async def vice_disconnect() -> dict[str, object]:
        """Release only the local binding; do not stop connector or VICE."""

        return await asyncio.to_thread(vice.disconnect)

    @registry.tool("vice")
    async def vice_status() -> dict[str, object]:
        """Return cached binding state without launching or contacting VICE."""

        return await asyncio.to_thread(vice.status)

    @registry.tool("vice")
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

    @registry.tool("vice")
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

    @registry.tool("vice")
    async def vice_list_banks(
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """List the complete connector-discovered VICE memory bank map."""

        return await asyncio.to_thread(
            vice.list_banks, timeout_ms=timeout_ms
        )

    @registry.tool("vice")
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

    @registry.tool("vice")
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

    @registry.tool("vice")
    async def vice_list_checkpoints(
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """List all VICE checkpoints through the active connector."""

        return await asyncio.to_thread(
            vice.list_checkpoints, timeout_ms=timeout_ms
        )

    @registry.tool("vice")
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

    @registry.tool("vice")
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

    @registry.tool("vice")
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

    @registry.tool("vice")
    async def vice_step(
        count: int = 1,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Step one or more instructions and wait for synchronized stop."""

        return await asyncio.to_thread(
            vice.step, count=count, timeout_ms=timeout_ms
        )

    @registry.tool("vice")
    async def vice_next(
        count: int = 1,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Step over one or more calls and wait for synchronized stop."""

        return await asyncio.to_thread(
            vice.next, count=count, timeout_ms=timeout_ms
        )

    @registry.tool("vice")
    async def vice_finish(
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Run until RTS/RTI completion and synchronized stop."""

        return await asyncio.to_thread(
            vice.finish, timeout_ms=timeout_ms
        )

    @registry.tool("vice")
    async def vice_resume(
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Resume execution and wait for the synchronized resumed event."""

        return await asyncio.to_thread(
            vice.resume, timeout_ms=timeout_ms
        )

    @registry.tool("vice")
    async def vice_interrupt(
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Enter the VICE monitor and wait for synchronized stop."""

        return await asyncio.to_thread(
            vice.interrupt, timeout_ms=timeout_ms
        )

    @registry.tool("vice")
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

    @registry.tool("vice")
    async def vice_reset(
        kind: ResetKindArgument = "soft",
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Reset the C64 or drive 8/9 through the active connector."""

        return await asyncio.to_thread(
            vice.reset, kind=kind, timeout_ms=timeout_ms
        )

    @registry.tool("vice")
    async def vice_capture_screen(
        crop: bool = True,
        use_vic: bool = True,
        timeout_ms: int = 10_000,
        output_path: str | None = None,
        overwrite: bool = False,
    ) -> CallToolResult:
        """Capture the live VICE screen as an indexed PNG."""

        return await asyncio.to_thread(
            capture_screen,
            capture_vice,
            crop=crop,
            use_vic=use_vic,
            timeout_ms=timeout_ms,
            output_path=output_path,
            overwrite=overwrite,
        )

    @registry.tool("vice")
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

    @registry.tool("vice")
    async def vice_feed_keyboard(
        data: BytesInput,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Queue raw PETSCII bytes in VICE's keyboard buffer."""

        return await asyncio.to_thread(
            vice.feed_keyboard,
            data=data,
            timeout_ms=timeout_ms,
        )

    @registry.tool("vice")
    async def vice_set_joyport(
        port: int,
        value: int,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Set one raw active-low VICE joystick-port byte."""

        return await asyncio.to_thread(
            vice.set_joyport,
            port=port,
            value=value,
            timeout_ms=timeout_ms,
        )

    @registry.tool("vice")
    async def vice_save_snapshot(
        filename: str,
        save_roms: bool = False,
        save_disks: bool = True,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Save one VICE snapshot at a path visible to the VICE host."""

        return await asyncio.to_thread(
            vice.save_snapshot,
            filename=filename,
            save_roms=save_roms,
            save_disks=save_disks,
            timeout_ms=timeout_ms,
        )

    @registry.tool("vice")
    async def vice_load_snapshot(
        filename: str,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Load one VICE snapshot from a path visible to the VICE host."""

        return await asyncio.to_thread(
            vice.load_snapshot,
            filename=filename,
            timeout_ms=timeout_ms,
        )

    @registry.tool("vice")
    async def vice_list_events(
        after_sequence: int,
        limit: int = 128,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """List a bounded page of retained public VICE events."""

        return await asyncio.to_thread(
            vice.list_events,
            after_sequence=after_sequence,
            limit=limit,
            timeout_ms=timeout_ms,
        )

    @registry.tool("vice")
    async def vice_capture_state(
        expected_event_sequence: int,
        expected_command_sequence: int,
        ranges: list[dict[str, object]],
        register_names: list[str] | None = None,
        include_checkpoints: bool = True,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Atomically capture registers and at most 16 KiB of named ranges."""

        return await asyncio.to_thread(
            vice.capture_state,
            expected_event_sequence=expected_event_sequence,
            expected_command_sequence=expected_command_sequence,
            ranges=ranges,
            register_names=register_names,
            include_checkpoints=include_checkpoints,
            timeout_ms=timeout_ms,
        )

    @registry.tool("reversing")
    async def import_vice_phase(
        program: str,
        phase: str,
        output_dir: str,
        dry_run: bool = True,
        overwrite: bool = False,
        timeout_ms: int = 10_000,
        ghidra_timeout_ms: int = 30_000,
    ) -> dict[str, object]:
        """Capture canonical CPU/RAM/ROM/I/O banks and import one phase."""

        return await asyncio.to_thread(
            import_phase,
            vice,
            reversing_client,
            program=program,
            phase=phase,
            output_dir=output_dir,
            dry_run=dry_run,
            overwrite=overwrite,
            timeout_ms=timeout_ms,
            ghidra_timeout_ms=ghidra_timeout_ms,
        )

    @registry.tool("reversing")
    async def vice_capture_transition(
        ranges: list[dict[str, object]],
        checkpoint_start: int,
        checkpoint_end: int,
        checkpoint_operations: int = 4,
        checkpoint_memspace: int = 0,
        petscii: BytesInput | None = None,
        joyport_port: int | None = None,
        joyport_value: int | None = None,
        register_names: list[str] | None = None,
        manifest_path: str | None = None,
        overwrite: bool = False,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Capture and diff exact ranges around one stopping checkpoint."""

        return await asyncio.to_thread(
            capture_transition,
            vice,
            ranges=ranges,
            checkpoint_start=checkpoint_start,
            checkpoint_end=checkpoint_end,
            checkpoint_operations=checkpoint_operations,
            checkpoint_memspace=checkpoint_memspace,
            petscii=petscii,
            joyport_port=joyport_port,
            joyport_value=joyport_value,
            register_names=register_names,
            manifest_path=manifest_path,
            overwrite=overwrite,
            timeout_ms=timeout_ms,
        )

    @registry.tool("reversing")
    async def search_6502_indexed_operands(
        program: str,
        target_start: str,
        target_end: str,
        source_start: str,
        source_end: str,
        limit: int = 1_000,
        offset: int = 0,
    ) -> dict[str, object]:
        """Find 6502 absolute indexed operands without modifying Ghidra."""

        return await asyncio.to_thread(
            search_indexed,
            reversing_client,
            program=program,
            target_start=target_start,
            target_end=target_end,
            source_start=source_start,
            source_end=source_end,
            limit=limit,
            offset=offset,
        )

    @registry.tool("reversing")
    async def find_split_pointer_partners(
        program: str,
        first_start: str,
        count: int,
        partner_start: str,
        partner_end: str,
        target_start: str,
        target_end: str,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, object]:
        """Find split pointer arrays without modifying Ghidra."""

        return await asyncio.to_thread(
            find_split_partners,
            reversing_client,
            program=program,
            first_start=first_start,
            count=count,
            partner_start=partner_start,
            partner_end=partner_end,
            target_start=target_start,
            target_end=target_end,
            limit=limit,
            offset=offset,
        )

    registry.install_management_tools()
    return server
