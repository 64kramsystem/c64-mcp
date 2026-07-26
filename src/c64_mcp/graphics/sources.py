"""The discriminated byte source shared by every graphics decoder.

A decoder needs bytes; where they come from is orthogonal to how they are
interpreted. Three kinds are accepted:

```json
{"kind": "inline", "bytes": "00ff…"}
{"kind": "ghidra", "program": "name", "start": "ram:2000"}
{"kind": "vice",   "bank_id": 1, "start": 8192}
```

`bank_id` is mandatory for the VICE kind: the same 16-bit address returns
different bytes depending on the bank, so an omitted bank is a silent wrong
answer rather than a convenience.

Reads are planned before any of them happens, so an invalid request or a source
that is too short for the requested geometry costs nothing and touches neither
Ghidra nor a live emulator.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from ..errors import RequestError, ViceError

MAX_SOURCE_BYTES = 65_536
ADDRESS_SPACE_LIMIT = 0x10000
NON_ATOMIC_WARNING = "non_atomic_vice_reads"
DEFAULT_TIMEOUT_MS = 10_000
_HEX = re.compile(r"^[0-9a-fA-F]*$")

_INLINE_FIELDS = frozenset({"kind", "bytes"})
_GHIDRA_FIELDS = frozenset({"kind", "program", "start"})
_VICE_FIELDS = frozenset({"kind", "bank_id", "start"})


class GraphicsGhidraClient(Protocol):
    """The single public Ghidra call the graphics decoders need."""

    def read_bytes(self, program: str, start: str, length: int) -> bytes:
        """Read exactly length mapped bytes."""


class GraphicsViceSession(Protocol):
    """The public VICE surface the graphics decoders need."""

    def status(self) -> dict[str, object]:
        """Return cached binding state without contacting VICE."""

    def read_memory(
        self,
        *,
        bank_id: int,
        start: int,
        end: int,
        side_effects: bool = False,
        max_bytes: int = 4096,
        memspace: int = 0,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ) -> dict[str, object]:
        """Read a bounded inclusive 16-bit range from one VICE bank."""


@dataclass(frozen=True, slots=True)
class SourceSpec:
    """One parsed, not yet fetched byte source."""

    name: str
    kind: str
    data: bytes | None = None
    program: str | None = None
    address: str | None = None
    bank_id: int | None = None
    start: int | None = None


@dataclass(frozen=True, slots=True)
class LoadedSource:
    """One fetched byte source and how much of it the decode used."""

    name: str
    kind: str
    data: bytes
    consumed: int

    def as_summary(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "supplied": len(self.data),
            "consumed": self.consumed,
            "trailing": len(self.data) - self.consumed,
        }


def parse_source(value: object, name: str) -> SourceSpec:
    """Validate one discriminated byte source without fetching anything."""

    if not isinstance(value, Mapping):
        raise RequestError(
            f"{name} must be an object with a 'kind' of inline, ghidra, "
            "or vice"
        )
    kind = value.get("kind")
    if kind == "inline":
        _reject_extra(value, _INLINE_FIELDS, name, "inline")
        if "bytes" not in value:
            raise RequestError(f"{name} inline source requires bytes")
        return SourceSpec(
            name=name, kind="inline", data=_parse_bytes(value["bytes"], name)
        )
    if kind == "ghidra":
        _reject_extra(value, _GHIDRA_FIELDS, name, "ghidra")
        program = value.get("program")
        start = value.get("start")
        if not isinstance(program, str) or not program.strip():
            raise RequestError(
                f"{name} ghidra source requires a nonblank program"
            )
        if not isinstance(start, str) or not start.strip():
            raise RequestError(
                f"{name} ghidra source requires a start address such as "
                "'ram:2000'"
            )
        return SourceSpec(
            name=name, kind="ghidra", program=program, address=start
        )
    if kind == "vice":
        _reject_extra(value, _VICE_FIELDS, name, "vice")
        bank_id = value.get("bank_id")
        start = value.get("start")
        if (
            not isinstance(bank_id, int)
            or isinstance(bank_id, bool)
            or bank_id < 0
        ):
            raise RequestError(
                f"{name} vice source requires bank_id: the same address "
                "holds different bytes in different banks"
            )
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or start < 0
            or start > 0xFFFF
        ):
            raise RequestError(
                f"{name} vice source requires a start address from 0 to 65535"
            )
        return SourceSpec(
            name=name, kind="vice", bank_id=bank_id, start=start
        )
    raise RequestError(
        f"{name} must have a kind of inline, ghidra, or vice"
    )


class SourcePlan:
    """Declare every source and its length first, then fetch in order."""

    def __init__(
        self,
        ghidra: GraphicsGhidraClient,
        vice: GraphicsViceSession,
        *,
        allow_non_atomic_vice_reads: bool = False,
    ) -> None:
        if not isinstance(allow_non_atomic_vice_reads, bool):
            raise RequestError(
                "allow_non_atomic_vice_reads must be a boolean"
            )
        self._ghidra = ghidra
        self._vice = vice
        self._allow_non_atomic = allow_non_atomic_vice_reads
        self._specs: list[SourceSpec] = []
        self._required: dict[str, int | None] = {}
        self._loaded: dict[str, LoadedSource] = {}
        self._committed = False
        self.warnings: list[str] = []

    def declare(self, spec: SourceSpec, required: int | None) -> None:
        """Register one source, with a length that may still be unknown."""

        if self._committed:
            raise RequestError("sources must be declared before any read")
        self._specs.append(spec)
        self._required[spec.name] = required

    def commit(self) -> None:
        """Check every known length and the live-read atomicity rule."""

        for spec in self._specs:
            required = self._required[spec.name]
            if (
                spec.kind == "inline"
                and required is not None
                and spec.data is not None
                and len(spec.data) < required
            ):
                raise RequestError(
                    f"{spec.name} supplies {len(spec.data)} bytes but "
                    f"{required} are required"
                )
        live = [spec for spec in self._specs if spec.kind == "vice"]
        if len(live) > 1 and not self._allow_non_atomic and self._running():
            raise RequestError(
                f"{len(live)} VICE sources cannot be read atomically while "
                "the emulator is running; stop it, or pass "
                "allow_non_atomic_vice_reads=true to accept a torn read"
            )
        if len(live) > 1 and self._allow_non_atomic and self._running():
            self.warnings.append(NON_ATOMIC_WARNING)
        self._committed = True

    def resolve(self, spec: SourceSpec, required: int) -> None:
        """Supply a length that could only be derived from earlier bytes."""

        self._required[spec.name] = required

    def load(self, spec: SourceSpec) -> bytes:
        """Fetch one declared source, reading exactly what it must supply."""

        if not self._committed:
            raise RequestError("the source plan must be committed first")
        required = self._required[spec.name]
        if required is None:
            raise RequestError(
                f"{spec.name} has no resolved length requirement"
            )
        if spec.kind == "inline":
            assert spec.data is not None
            data = spec.data
        elif spec.kind == "ghidra":
            assert spec.program is not None and spec.address is not None
            data = self._ghidra.read_bytes(
                spec.program, spec.address, required
            )
        else:
            data = self._read_vice(spec, required)
        if len(data) < required:
            raise RequestError(
                f"{spec.name} supplies {len(data)} bytes but {required} "
                "are required"
            )
        loaded = LoadedSource(
            name=spec.name,
            kind=spec.kind,
            data=data,
            consumed=required,
        )
        self._loaded[spec.name] = loaded
        return data

    def summary(self) -> dict[str, object]:
        """Return the per-source record in declaration order."""

        return {
            spec.name: self._loaded[spec.name].as_summary()
            for spec in self._specs
            if spec.name in self._loaded
        }

    def _running(self) -> bool:
        state = self._vice.status().get("state")
        return state == "running"

    def _read_vice(self, spec: SourceSpec, required: int) -> bytes:
        assert spec.bank_id is not None and spec.start is not None
        available = ADDRESS_SPACE_LIMIT - spec.start
        if required > available:
            raise RequestError(
                f"{spec.name} needs {required} bytes from ${spec.start:04X} "
                f"but only {available} remain below $FFFF; VICE reads do "
                "not wrap"
            )
        envelope = self._vice.read_memory(
            bank_id=spec.bank_id,
            start=spec.start,
            end=spec.start + required - 1,
            side_effects=False,
            max_bytes=required,
            memspace=0,
            timeout_ms=DEFAULT_TIMEOUT_MS,
        )
        if envelope.get("ok") is False:
            error = envelope.get("error")
            if isinstance(error, Mapping):
                raise ViceError.from_mapping(
                    error,
                    fallback_code="vice_read_failed",
                    fallback_message=(
                        f"reading {spec.name} from VICE failed"
                    ),
                )
            raise ViceError(
                "vice_read_failed",
                f"reading {spec.name} from VICE failed",
            )
        result = envelope.get("result")
        if not isinstance(result, Mapping):
            raise ViceError(
                "vice_connector_incompatible",
                "the VICE memory read returned no result object",
            )
        raw = result.get("bytes")
        if (
            not isinstance(raw, str)
            or len(raw) % 2
            or _HEX.fullmatch(raw) is None
        ):
            raise ViceError(
                "vice_connector_incompatible",
                "the VICE memory read omitted hexadecimal bytes",
            )
        return bytes.fromhex(raw)


def _reject_extra(
    value: Mapping[str, object],
    allowed: frozenset[str],
    name: str,
    kind: str,
) -> None:
    extra = sorted(set(value) - allowed)
    if extra:
        raise RequestError(
            f"{name} {kind} source does not accept "
            f"{', '.join(extra)}; allowed fields are "
            f"{', '.join(sorted(allowed))}"
        )


def _parse_bytes(value: object, name: str) -> bytes:
    if isinstance(value, str):
        compact = "".join(value.split())
        if len(compact) % 2 or not _HEX.fullmatch(compact):
            raise RequestError(
                f"{name} bytes must contain an even number of hexadecimal "
                "digits"
            )
        result = bytes.fromhex(compact)
    elif isinstance(value, list):
        converted = bytearray()
        for item in value:
            if (
                not isinstance(item, int)
                or isinstance(item, bool)
                or item < 0
                or item > 255
            ):
                raise RequestError(
                    f"{name} bytes array values must be integers from 0 to 255"
                )
            converted.append(item)
        result = bytes(converted)
    else:
        raise RequestError(f"{name} bytes must be hex text or a byte array")
    if len(result) > MAX_SOURCE_BYTES:
        raise RequestError(
            f"{name} exceeds the {MAX_SOURCE_BYTES}-byte inline hard maximum"
        )
    return result
