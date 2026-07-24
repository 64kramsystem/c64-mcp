"""Bundled C64 symbol-profile loading and application."""

from __future__ import annotations

import json
from collections.abc import Mapping
from importlib import resources
from typing import Protocol, cast

from .errors import ProfileError, RequestError

_CONFLICT_POLICIES = frozenset({"error", "keep", "replace"})
_PROFILE_ARRAYS = ("symbols", "equates", "comments", "memory_blocks")


class ProfileGhidraClient(Protocol):
    """Public Ghidra call required by the C64 profile subsystem."""

    def apply_profile(
        self,
        program: str,
        profile: Mapping[str, object],
        *,
        dry_run: bool = True,
        conflict_policy: str = "error",
        replace_user_definitions: bool = False,
        create_memory_blocks: bool = False,
    ) -> dict[str, object]:
        """Apply one generic profile to an explicitly named program."""


def load_c64_profile() -> dict[str, object]:
    """Load a fresh JSON-safe copy of the bundled versioned C64 profile."""

    try:
        raw = (
            resources.files("ghidra_mcp_c64.profiles")
            .joinpath("c64.json")
            .read_text("utf-8")
        )
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProfileError("bundled C64 profile could not be loaded") from error
    if not isinstance(value, dict):
        raise ProfileError("bundled C64 profile must be a JSON object")
    if value.get("schema_version") != 1:
        raise ProfileError("bundled C64 profile has unsupported schema_version")
    if value.get("id") != "c64":
        raise ProfileError("bundled C64 profile has invalid id")
    version = value.get("version")
    if not isinstance(version, str) or not version:
        raise ProfileError("bundled C64 profile has invalid version")
    for name in _PROFILE_ARRAYS:
        if not isinstance(value.get(name), list):
            raise ProfileError(
                f"bundled C64 profile field {name!r} must be an array"
            )
    return cast(dict[str, object], value)


def get_c64_symbol_profile() -> dict[str, object]:
    """Return the complete bundled profile as an independent JSON object."""

    return load_c64_profile()


def apply_c64_symbol_profile(
    ghidra: ProfileGhidraClient,
    *,
    program: str,
    dry_run: bool = True,
    conflict_policy: str = "error",
    replace_user_definitions: bool = False,
    create_memory_blocks: bool = False,
) -> dict[str, object]:
    """Apply the bundled profile through the generic public endpoint."""

    if not isinstance(program, str) or not program.strip():
        raise RequestError("program must not be blank")
    if (
        not isinstance(conflict_policy, str)
        or conflict_policy not in _CONFLICT_POLICIES
    ):
        raise RequestError(
            "conflict_policy must be error, keep, or replace"
        )
    _require_bool("dry_run", dry_run)
    _require_bool(
        "replace_user_definitions", replace_user_definitions
    )
    _require_bool("create_memory_blocks", create_memory_blocks)
    return ghidra.apply_profile(
        program,
        load_c64_profile(),
        dry_run=dry_run,
        conflict_policy=conflict_policy,
        replace_user_definitions=replace_user_definitions,
        create_memory_blocks=create_memory_blocks,
    )


def _require_bool(name: str, value: object) -> None:
    if type(value) is not bool:
        raise RequestError(f"{name} must be a boolean")
