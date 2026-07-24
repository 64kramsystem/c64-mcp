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

    return server
