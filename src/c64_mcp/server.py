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
from .graphics.sources import GraphicsGhidraClient
from .graphics.tools import decode_c64_char_screen as decode_char_screen
from .graphics.tools import decode_c64_charset as decode_charset
from .graphics.tools import decode_c64_hires_bitmap as decode_hires_bitmap
from .graphics.tools import (
    decode_c64_multicolor_bitmap as decode_multicolor_bitmap,
)
from .graphics.tools import decode_c64_sprites as decode_sprites
from .symbols import SymbolGhidraClient
from .symbols import apply_c64_symbols as apply_symbols
from .text.tools import BytesInput, TextGhidraClient
from .text.tools import decode_c64_text as decode_text
from .vice import ViceGhidraClient, ViceSession

EncodingArgument = Literal[
    "petscii_upper",
    "petscii_lower",
    "screen_code_upper",
    "screen_code_lower",
]
ResetKindArgument = Literal["soft", "hard"]


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
            settings.ghidra_timeout,
        )
    )
    text_client = cast(TextGhidraClient, instance)
    symbol_client = cast(SymbolGhidraClient, instance)
    graphics_client = cast(GraphicsGhidraClient, instance)
    vice = ViceSession(cast(ViceGhidraClient, instance))
    capture_vice = cast(CaptureViceSession, vice)
    server = FastMCP("c64-mcp")

    @server.tool()
    async def apply_c64_symbols(program: str) -> dict[str, object]:
        """Add the bundled C64 hardware and KERNAL labels to a program."""

        return await asyncio.to_thread(
            apply_symbols,
            symbol_client,
            program=program,
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
        tokens: dict[str, str] | None = None,
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
            tokens=tokens,
        )

    @server.tool()
    async def decode_c64_hires_bitmap(
        bitmap: dict[str, Any],
        screen: dict[str, Any],
        columns: int = 40,
        rows: int = 25,
        output_path: str | None = None,
        overwrite: bool = False,
    ) -> CallToolResult:
        """Decode C64 hires bitmap bytes into an indexed PNG."""

        return await asyncio.to_thread(
            decode_hires_bitmap,
            graphics_client,
            bitmap=bitmap,
            screen=screen,
            columns=columns,
            rows=rows,
            output_path=output_path,
            overwrite=overwrite,
        )

    @server.tool()
    async def decode_c64_multicolor_bitmap(
        bitmap: dict[str, Any],
        screen: dict[str, Any],
        color: dict[str, Any],
        columns: int = 40,
        rows: int = 25,
        background: int = 0,
        output_path: str | None = None,
        overwrite: bool = False,
    ) -> CallToolResult:
        """Decode C64 multicolor bitmap bytes into an indexed PNG."""

        return await asyncio.to_thread(
            decode_multicolor_bitmap,
            graphics_client,
            bitmap=bitmap,
            screen=screen,
            color=color,
            columns=columns,
            rows=rows,
            background=background,
            output_path=output_path,
            overwrite=overwrite,
        )

    @server.tool()
    async def decode_c64_charset(
        charset: dict[str, Any],
        glyph_count: int = 256,
        sheet_columns: int = 16,
        foreground: int = 1,
        background: int = 0,
        multicolor: bool = False,
        background_1: int | None = None,
        background_2: int | None = None,
        output_path: str | None = None,
        overwrite: bool = False,
    ) -> CallToolResult:
        """Decode a C64 character set into an indexed PNG glyph sheet."""

        return await asyncio.to_thread(
            decode_charset,
            graphics_client,
            charset=charset,
            glyph_count=glyph_count,
            sheet_columns=sheet_columns,
            foreground=foreground,
            background=background,
            multicolor=multicolor,
            background_1=background_1,
            background_2=background_2,
            output_path=output_path,
            overwrite=overwrite,
        )

    @server.tool()
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
        output_path: str | None = None,
        overwrite: bool = False,
    ) -> CallToolResult:
        """Decode C64 text-mode screen codes into an indexed PNG."""

        return await asyncio.to_thread(
            decode_char_screen,
            graphics_client,
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
            output_path=output_path,
            overwrite=overwrite,
        )

    @server.tool()
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
        output_path: str | None = None,
        overwrite: bool = False,
    ) -> CallToolResult:
        """Decode C64 sprite definitions into an indexed PNG sheet."""

        return await asyncio.to_thread(
            decode_sprites,
            graphics_client,
            sprites=sprites,
            sprite_count=sprite_count,
            sprite_colors=sprite_colors,
            sprite_stride=sprite_stride,
            sheet_columns=sheet_columns,
            multicolor=multicolor,
            multicolor_0=multicolor_0,
            multicolor_1=multicolor_1,
            background=background,
            output_path=output_path,
            overwrite=overwrite,
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

        return await asyncio.to_thread(vice.list_banks, timeout_ms=timeout_ms)

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

        return await asyncio.to_thread(vice.list_checkpoints, timeout_ms=timeout_ms)

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

        return await asyncio.to_thread(vice.step, count=count, timeout_ms=timeout_ms)

    @server.tool()
    async def vice_next(
        count: int = 1,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Step over one or more calls and wait for synchronized stop."""

        return await asyncio.to_thread(vice.next, count=count, timeout_ms=timeout_ms)

    @server.tool()
    async def vice_finish(
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Run until RTS/RTI completion and synchronized stop."""

        return await asyncio.to_thread(vice.finish, timeout_ms=timeout_ms)

    @server.tool()
    async def vice_resume(
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Resume execution and wait for the synchronized resumed event."""

        return await asyncio.to_thread(vice.resume, timeout_ms=timeout_ms)

    @server.tool()
    async def vice_interrupt(
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Enter the VICE monitor and wait for synchronized stop."""

        return await asyncio.to_thread(vice.interrupt, timeout_ms=timeout_ms)

    @server.tool()
    async def vice_wait_for_stop(
        after_stop_count: int,
        timeout_ms: int,
    ) -> dict[str, object]:
        """Await the latest stop after a previously observed stop count."""

        return await asyncio.to_thread(
            vice.wait_for_stop,
            after_stop_count=after_stop_count,
            timeout_ms=timeout_ms,
        )

    @server.tool()
    async def vice_feed_keyboard(
        data: BytesInput,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Feed one bounded byte string to the C64 keyboard buffer."""

        return await asyncio.to_thread(
            vice.feed_keyboard, data=data, timeout_ms=timeout_ms
        )

    @server.tool()
    async def vice_set_joyport(
        port: int,
        value: int,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Set raw active-low joystick lines on public port 1 or 2."""

        return await asyncio.to_thread(
            vice.set_joyport,
            port=port,
            value=value,
            timeout_ms=timeout_ms,
        )

    @server.tool()
    async def vice_save_snapshot(
        filename: str,
        save_roms: bool = False,
        save_disks: bool = True,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Save a VICE snapshot."""

        return await asyncio.to_thread(
            vice.save_snapshot,
            filename=filename,
            save_roms=save_roms,
            save_disks=save_disks,
            timeout_ms=timeout_ms,
        )

    @server.tool()
    async def vice_load_snapshot(
        filename: str,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Load a VICE snapshot and refresh the trace."""

        return await asyncio.to_thread(
            vice.load_snapshot,
            filename=filename,
            timeout_ms=timeout_ms,
        )

    @server.tool()
    async def vice_reset(
        kind: ResetKindArgument = "soft",
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Soft- or hard-reset the C64."""

        return await asyncio.to_thread(vice.reset, kind=kind, timeout_ms=timeout_ms)

    @server.tool()
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

    @server.tool()
    async def copy_vice_memory_to_ghidra(
        bank_id: int,
        start: int,
        end: int,
        program: str,
        destination: str,
        dry_run: bool = True,
        memspace: int = 0,
        timeout_ms: int = 10_000,
    ) -> dict[str, object]:
        """Copy stable stopped VICE RAM directly into Ghidra."""

        return await asyncio.to_thread(
            vice.copy_memory_to_ghidra,
            bank_id=bank_id,
            start=start,
            end=end,
            program=program,
            destination=destination,
            dry_run=dry_run,
            memspace=memspace,
            timeout_ms=timeout_ms,
        )

    return server
