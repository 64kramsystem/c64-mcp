"""Runtime visibility profiles for the C64 MCP tool catalog."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ParamSpec, TypeVar, cast

from mcp.server.fastmcp import Context, FastMCP

from .config import TOOL_PROFILE_NAMES, ToolProfile

P = ParamSpec("P")
R = TypeVar("R")
McpContext = Context[Any, Any, Any]

TOOL_GROUPS = ("symbols", "text", "graphics", "vice", "reversing")
GROUP_DESCRIPTIONS = {
    "symbols": "C64 platform symbols, equates, and memory-map profiles",
    "text": "PETSCII and screen-code decoding, search, and annotation",
    "graphics": (
        "VIC-II bitmap, character, charset, and sprite decoding to PNG"
    ),
    "vice": "Live VICE debugger control and static-memory copying",
    "reversing": "Phase capture, transition evidence, and 6502 analysis",
}
PROFILE_GROUPS: dict[ToolProfile, frozenset[str]] = {
    "minimal": frozenset(),
    "static": frozenset({"symbols", "text", "graphics"}),
    "vice": frozenset({"vice"}),
    "full": frozenset(TOOL_GROUPS),
}


@dataclass(frozen=True)
class ToolEntry:
    """One immutable tool-catalog entry."""

    name: str
    group: str
    description: str
    function: Callable[..., Any]


def _error(code: str, message: str, **details: object) -> dict[str, object]:
    error: dict[str, object] = {"code": code, "message": message}
    error.update(details)
    return {"ok": False, "error": error}


class ToolProfileRegistry:
    """Own the complete catalog and its currently callable subset."""

    def __init__(self, server: FastMCP, profile: ToolProfile) -> None:
        if profile not in TOOL_PROFILE_NAMES:
            raise ValueError(f"unknown C64 tool profile: {profile}")
        self._server = server
        self._profile = profile
        self._baseline = PROFILE_GROUPS[profile]
        self._loaded = set(self._baseline)
        self._catalog: dict[str, ToolEntry] = {}
        self._management: dict[str, ToolEntry] = {}
        self._lock = asyncio.Lock()

    def tool(
        self, group: str
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Catalog a handler and expose it when its group is in the baseline."""

        if group not in TOOL_GROUPS:
            raise ValueError(f"unknown C64 tool group: {group}")

        def register(function: Callable[P, R]) -> Callable[P, R]:
            name = function.__name__
            if name in self._catalog or name in self._management:
                raise ValueError(f"duplicate C64 tool name: {name}")
            entry = ToolEntry(
                name=name,
                group=group,
                description=(function.__doc__ or "").strip(),
                function=cast(Callable[..., Any], function),
            )
            self._catalog[name] = entry
            if group in self._baseline:
                self._server.add_tool(function)
            return function

        return register

    def install_management_tools(self) -> None:
        """Install the small, always-visible catalog-management surface."""

        registry = self

        async def list_c64_tool_groups() -> dict[str, object]:
            """List C64 tool groups, counts, and current visibility."""

            return await registry.list_groups()

        async def load_c64_tool_group(
            group: str, ctx: McpContext | None = None
        ) -> dict[str, object]:
            """Load a C64 tool group, or use 'all' to load every group."""

            return await registry.load(group, ctx)

        async def unload_c64_tool_group(
            group: str, ctx: McpContext | None = None
        ) -> dict[str, object]:
            """Unload a non-baseline C64 tool group."""

            return await registry.unload(group, ctx)

        async def search_c64_tools(
            query: str, limit: int = 15
        ) -> dict[str, object]:
            """Search the complete C64 tool catalog, including hidden tools."""

            return await registry.search(query, limit)

        for function in (
            list_c64_tool_groups,
            load_c64_tool_group,
            unload_c64_tool_group,
            search_c64_tools,
        ):
            name = function.__name__
            entry = ToolEntry(
                name=name,
                group="management",
                description=(function.__doc__ or "").strip(),
                function=function,
            )
            self._management[name] = entry
            self._server.add_tool(function)

    async def list_groups(self) -> dict[str, object]:
        """Return a consistent snapshot of group visibility."""

        async with self._lock:
            groups = []
            for group in TOOL_GROUPS:
                names = sorted(
                    entry.name
                    for entry in self._catalog.values()
                    if entry.group == group
                )
                groups.append(
                    {
                        "group": group,
                        "description": GROUP_DESCRIPTIONS[group],
                        "tool_count": len(names),
                        "loaded": group in self._loaded,
                        "baseline": group in self._baseline,
                        "tools": names,
                    }
                )
            return {
                "ok": True,
                "profile": self._profile,
                "groups": groups,
                "loaded_groups": sorted(self._loaded),
                "callable_tools": (
                    len(self._management)
                    + sum(
                        1
                        for entry in self._catalog.values()
                        if entry.group in self._loaded
                    )
                ),
                "catalog_tools": len(self._management) + len(self._catalog),
            }

    async def load(
        self, group: str, ctx: McpContext | None = None
    ) -> dict[str, object]:
        """Atomically expose one group or every group."""

        async with self._lock:
            requested = set(TOOL_GROUPS) if group == "all" else {group}
            unknown = requested - set(TOOL_GROUPS)
            if unknown:
                return _error(
                    "unknown_group",
                    f"unknown C64 tool group: {group}",
                    group=group,
                    available_groups=list(TOOL_GROUPS),
                )
            added_groups = requested - self._loaded
            if not added_groups:
                result: dict[str, object] = {
                    "ok": True,
                    "changed": False,
                    "loaded": group,
                    "new_tools": 0,
                    "new_tool_names": [],
                    "profile": self._profile,
                    "loaded_groups": sorted(self._loaded),
                }
            else:
                entries = sorted(
                    (
                        entry
                        for entry in self._catalog.values()
                        if entry.group in added_groups
                    ),
                    key=lambda entry: entry.name,
                )
                added: list[ToolEntry] = []
                try:
                    for entry in entries:
                        self._server.add_tool(entry.function)
                        added.append(entry)
                except Exception as error:
                    rollback_errors = []
                    for entry in reversed(added):
                        try:
                            self._server.remove_tool(entry.name)
                        except Exception as rollback_error:
                            rollback_errors.append(str(rollback_error))
                    return _error(
                        "registration_failed",
                        f"failed to load C64 tool group '{group}': {error}",
                        group=group,
                        rollback_errors=rollback_errors,
                    )
                self._loaded.update(added_groups)
                result = {
                    "ok": True,
                    "changed": True,
                    "loaded": group,
                    "new_tools": len(entries),
                    "new_tool_names": [entry.name for entry in entries],
                    "profile": self._profile,
                    "loaded_groups": sorted(self._loaded),
                }
        result["tools_changed"] = await self._notify_tools_changed(
            ctx, bool(result["changed"])
        )
        return result

    async def unload(
        self, group: str, ctx: McpContext | None = None
    ) -> dict[str, object]:
        """Atomically hide one transiently loaded group."""

        async with self._lock:
            if group not in TOOL_GROUPS:
                return _error(
                    "unknown_group",
                    f"unknown C64 tool group: {group}",
                    group=group,
                    available_groups=list(TOOL_GROUPS),
                )
            if self._profile == "full":
                return _error(
                    "no_partial_unload",
                    "the full profile keeps every C64 tool group visible",
                    group=group,
                    profile=self._profile,
                )
            if group in self._baseline:
                return _error(
                    "protected_group",
                    f"group '{group}' belongs to the profile baseline",
                    group=group,
                    profile=self._profile,
                    baseline_groups=sorted(self._baseline),
                )
            if group not in self._loaded:
                result: dict[str, object] = {
                    "ok": True,
                    "changed": False,
                    "unloaded": group,
                    "removed_tools": 0,
                    "removed_tool_names": [],
                    "profile": self._profile,
                    "loaded_groups": sorted(self._loaded),
                }
            else:
                entries = sorted(
                    (
                        entry
                        for entry in self._catalog.values()
                        if entry.group == group
                    ),
                    key=lambda entry: entry.name,
                )
                removed: list[ToolEntry] = []
                try:
                    for entry in entries:
                        self._server.remove_tool(entry.name)
                        removed.append(entry)
                except Exception as error:
                    rollback_errors = []
                    for entry in removed:
                        try:
                            self._server.add_tool(entry.function)
                        except Exception as rollback_error:
                            rollback_errors.append(str(rollback_error))
                    return _error(
                        "registration_failed",
                        f"failed to unload C64 tool group '{group}': {error}",
                        group=group,
                        rollback_errors=rollback_errors,
                    )
                self._loaded.remove(group)
                result = {
                    "ok": True,
                    "changed": True,
                    "unloaded": group,
                    "removed_tools": len(entries),
                    "removed_tool_names": [entry.name for entry in entries],
                    "profile": self._profile,
                    "loaded_groups": sorted(self._loaded),
                }
        result["tools_changed"] = await self._notify_tools_changed(
            ctx, bool(result["changed"])
        )
        return result

    async def search(
        self, query: str, limit: int = 15
    ) -> dict[str, object]:
        """Search immutable metadata while observing loaded status atomically."""

        terms = [term.lower() for term in query.split() if term]
        if not terms:
            return _error(
                "invalid_query",
                "provide one or more C64 tool search keywords",
            )
        if limit < 1 or limit > 50:
            return _error(
                "invalid_limit",
                "limit must be between 1 and 50",
                limit=limit,
            )

        async with self._lock:
            entries = list(self._catalog.values()) + list(
                self._management.values()
            )
            loaded = set(self._loaded)
            scored: list[tuple[int, str, dict[str, object]]] = []
            for entry in entries:
                name = entry.name.lower()
                haystack = (
                    f"{entry.name} {entry.group} {entry.description}".lower()
                )
                score = sum(
                    3 if term in name else 1 if term in haystack else 0
                    for term in terms
                )
                if score == 0:
                    continue
                callable_now = (
                    entry.group == "management" or entry.group in loaded
                )
                match: dict[str, object] = {
                    "name": entry.name,
                    "group": entry.group,
                    "status": (
                        "callable" if callable_now else "not_loaded"
                    ),
                    "description": entry.description,
                }
                if not callable_now:
                    match["fix"] = (
                        f'load_c64_tool_group("{entry.group}")'
                    )
                scored.append((-score, entry.name, match))
            scored.sort()
            matches = [item[2] for item in scored[:limit]]
            return {
                "ok": True,
                "query": query,
                "match_count": len(scored),
                "returned": len(matches),
                "matches": matches,
            }

    @staticmethod
    async def _notify_tools_changed(
        ctx: McpContext | None, changed: bool
    ) -> dict[str, object]:
        status: dict[str, object] = {
            "attempted": False,
            "sent": False,
            "error": None,
        }
        # The public property raises when a direct call has no request context.
        request_context = None if ctx is None else ctx._request_context
        if not changed or request_context is None:
            return status
        status["attempted"] = True
        try:
            await request_context.session.send_tool_list_changed()
        except Exception as error:
            status["error"] = str(error)
        else:
            status["sent"] = True
        return status
