from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

import pytest

from c64_mcp.errors import RequestError
from c64_mcp.profile_tools import (
    apply_c64_symbol_profile,
    get_c64_symbol_profile,
    load_c64_profile,
)


@dataclass
class FakeProfileGhidra:
    calls: list[dict[str, object]] = field(default_factory=list)

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
        self.calls.append(
            {
                "program": program,
                "profile": profile,
                "dry_run": dry_run,
                "conflict_policy": conflict_policy,
                "replace_user_definitions": replace_user_definitions,
                "create_memory_blocks": create_memory_blocks,
            }
        )
        return {"committed": not dry_run}


def test_get_returns_the_bundled_runtime_profile() -> None:
    profile = get_c64_symbol_profile()

    assert profile == load_c64_profile()
    assert profile["equates"]
    assert profile["memory_blocks"]


def test_apply_forwards_only_the_bundled_profile_and_explicit_program() -> None:
    ghidra = FakeProfileGhidra()

    result = apply_c64_symbol_profile(
        ghidra,
        program="snapshot",
        dry_run=False,
        conflict_policy="keep",
        replace_user_definitions=True,
        create_memory_blocks=True,
    )

    assert result == {"committed": True}
    assert len(ghidra.calls) == 1
    call = ghidra.calls[0]
    profile = call["profile"]
    assert isinstance(profile, Mapping)
    assert profile == load_c64_profile()
    assert call == {
        "program": "snapshot",
        "profile": profile,
        "dry_run": False,
        "conflict_policy": "keep",
        "replace_user_definitions": True,
        "create_memory_blocks": True,
    }


@pytest.mark.parametrize("program", ["", " ", "\n"])
def test_apply_rejects_blank_program_before_client_io(program: str) -> None:
    ghidra = FakeProfileGhidra()

    with pytest.raises(RequestError, match="program"):
        apply_c64_symbol_profile(ghidra, program=program)

    assert ghidra.calls == []


@pytest.mark.parametrize("policy", ["merge", "", " keep ", 1])
def test_apply_rejects_invalid_conflict_policy_before_client_io(
    policy: object,
) -> None:
    ghidra = FakeProfileGhidra()

    with pytest.raises(RequestError, match="conflict_policy"):
        apply_c64_symbol_profile(
            ghidra,
            program="snapshot",
            conflict_policy=policy,  # type: ignore[arg-type]
        )

    assert ghidra.calls == []


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("dry_run", 1),
        ("replace_user_definitions", 0),
        ("create_memory_blocks", "false"),
    ],
)
def test_apply_rejects_non_boolean_flags_before_client_io(
    field_name: str,
    value: object,
) -> None:
    ghidra = FakeProfileGhidra()
    arguments: dict[str, object] = {
        "program": "snapshot",
        field_name: value,
    }

    with pytest.raises(RequestError, match=field_name):
        apply_c64_symbol_profile(
            ghidra,
            **arguments,  # type: ignore[arg-type]
        )

    assert ghidra.calls == []
