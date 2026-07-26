"""Bounded public HTTP boundary to the generic Ghidra MCP server."""

from __future__ import annotations

import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any

from .errors import GhidraError, GhidraTransportError

MAX_RESPONSE_BYTES = 67_108_864
_HEX = re.compile(r"^[0-9a-fA-F]*$")


class GhidraClient:
    """Small synchronous client for the public local Ghidra HTTP API."""

    def __init__(
        self,
        base_url: str,
        auth_token: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_token = auth_token
        self._timeout = _positive_timeout(timeout)

    def call_get(
        self,
        path: str,
        query: Mapping[str, object],
        timeout: float | None = None,
        *,
        allow_error_response: bool = False,
    ) -> dict[str, object]:
        request = urllib.request.Request(
            self._url(path, query),
            headers=self._headers(),
            method="GET",
        )
        return self._send(
            request,
            path,
            timeout,
            allow_error_response=allow_error_response,
            request_committed=False,
        )

    def call_post(
        self,
        path: str,
        body: Mapping[str, object],
        query: Mapping[str, object],
        timeout: float | None = None,
        *,
        allow_error_response: bool = False,
    ) -> dict[str, object]:
        try:
            encoded = json.dumps(
                body, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise GhidraError(
                f"request body for {path} is not JSON-safe"
            ) from error
        request = urllib.request.Request(
            self._url(path, query),
            data=encoded,
            headers=self._headers(content_type=True),
            method="POST",
        )
        return self._send(
            request,
            path,
            timeout,
            allow_error_response=allow_error_response,
            request_committed=True,
        )

    def target_methods(self) -> dict[str, object]:
        """Discover the exact active TraceRMI target and method surface."""

        return self.call_get(
            "/debugger/target_methods",
            {},
            allow_error_response=True,
        )

    def invoke_target_method(
        self,
        target_token: str,
        method: str,
        arguments: Mapping[str, object],
        *,
        connector_timeout_ms: int,
    ) -> dict[str, object]:
        """Invoke one target method with connector/generic/HTTP budgets."""

        if not isinstance(target_token, str) or not target_token:
            raise ValueError("target_token must not be blank")
        if not isinstance(method, str) or not method:
            raise ValueError("method must not be blank")
        if (
            not isinstance(connector_timeout_ms, int)
            or isinstance(connector_timeout_ms, bool)
            or not 1 <= connector_timeout_ms <= 55_000
        ):
            raise ValueError(
                "connector_timeout_ms must be from 1 to 55000"
            )
        generic_timeout_ms = connector_timeout_ms + 5_000
        http_timeout = (generic_timeout_ms + 5_000) / 1000.0
        return self.call_post(
            "/debugger/invoke_target_method",
            {
                "target_token": target_token,
                "method": method,
                "arguments": dict(arguments),
                "timeout_ms": generic_timeout_ms,
            },
            {},
            timeout=http_timeout,
            allow_error_response=True,
        )

    def read_bytes(
        self, program: str, start: str, length: int
    ) -> bytes:
        _require_program(program)
        if length <= 0 or length > 1_048_576:
            raise ValueError(
                "length must be from 1 to 1048576 bytes"
            )
        result = self.call_get(
            "/inspect_memory_content",
            {
                "program": program,
                "address": start,
                "length": length,
                "detect_strings": False,
            },
        )
        bytes_read = result.get("bytes_read")
        if not isinstance(bytes_read, int) or isinstance(bytes_read, bool):
            raise GhidraError(
                "inspect_memory_content omitted integer bytes_read"
            )
        if bytes_read != length:
            raise GhidraError(
                f"inspect_memory_content returned {bytes_read} of "
                f"{length} requested bytes"
            )
        dump = result.get("hex_dump")
        if not isinstance(dump, str):
            raise GhidraError(
                "inspect_memory_content omitted string hex_dump"
            )
        # AnalysisService currently emits a literal backslash-n between
        # 16-byte rows rather than an actual newline. Accept that exact
        # documented wire shape as well as ordinary JSON whitespace.
        compact = "".join(dump.replace("\\n", "").split())
        if len(compact) != length * 2 or not _HEX.fullmatch(compact):
            raise GhidraError(
                "inspect_memory_content returned malformed hex_dump"
            )
        return bytes.fromhex(compact)

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
        _require_program(program)
        return self.call_post(
            "/apply_symbol_profile",
            {
                "profile": profile,
                "dry_run": dry_run,
                "conflict_policy": conflict_policy,
                "replace_user_definitions": replace_user_definitions,
                "create_memory_blocks": create_memory_blocks,
            },
            {"program": program},
        )

    def apply_data_regions(
        self,
        program: str,
        regions: list[Mapping[str, object]],
        *,
        dry_run: bool = True,
    ) -> dict[str, object]:
        _require_program(program)
        return self.call_post(
            "/apply_data_regions",
            {"regions": regions, "dry_run": dry_run},
            {"program": program},
        )

    def write_memory_bytes(
        self,
        program: str,
        start: str,
        data: str,
        *,
        dry_run: bool = True,
        conflict_policy: str = "error",
    ) -> dict[str, object]:
        _require_program(program)
        return self.call_post(
            "/write_memory_bytes",
            {
                "start": start,
                "bytes": data,
                "conflict_policy": conflict_policy,
                "dry_run": dry_run,
            },
            {"program": program},
        )

    def write_memory_bytes_result(
        self,
        program: str,
        start: str,
        data: str,
        *,
        dry_run: bool = True,
        conflict_policy: str = "error",
    ) -> dict[str, object]:
        """Write bytes while preserving a normal upstream error envelope."""

        _require_program(program)
        return self.call_post(
            "/write_memory_bytes",
            {
                "start": start,
                "bytes": data,
                "conflict_policy": conflict_policy,
                "dry_run": dry_run,
            },
            {"program": program},
            allow_error_response=True,
        )

    def _send(
        self,
        request: urllib.request.Request,
        path: str,
        timeout: float | None,
        *,
        allow_error_response: bool,
        request_committed: bool,
    ) -> dict[str, object]:
        effective_timeout = (
            self._timeout
            if timeout is None
            else _positive_timeout(timeout)
        )
        try:
            with urllib.request.urlopen(
                request, timeout=effective_timeout
            ) as response:
                raw = _read_bounded(response)
        except urllib.error.HTTPError as error:
            try:
                raw_error = _read_bounded(error)
                detail = _error_detail(raw_error)
            except Exception:
                detail = f"HTTP {error.code}"
            raise GhidraError(
                self._sanitize(
                    f"Ghidra HTTP {error.code} calling {path}: {detail}"
                )
            ) from None
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            timed_out = _is_timeout(error)
            raise GhidraTransportError(
                (
                    f"Ghidra HTTP timeout calling {path}"
                    if timed_out
                    else f"Ghidra transport failure calling {path}"
                ),
                code=(
                    "ghidra_http_timeout"
                    if timed_out
                    else "ghidra_transport_failure"
                ),
                timeout_layer="http" if timed_out else None,
                outcome_unknown=request_committed,
                request_committed=request_committed,
            ) from None

        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise GhidraError(
                f"Ghidra response from {path} is not valid UTF-8 JSON"
            ) from error
        if not isinstance(decoded, dict):
            raise GhidraError(
                f"Ghidra response from {path} must be a JSON object"
            )
        if "error" in decoded and not allow_error_response:
            raise GhidraError(
                self._sanitize(
                    f"Ghidra error from {path}: {decoded['error']}"
                )
            )
        return decoded

    def _url(
        self, path: str, query: Mapping[str, object]
    ) -> str:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("path must be an absolute local HTTP path")
        encoded_query = urllib.parse.urlencode(query, doseq=True)
        suffix = f"?{encoded_query}" if encoded_query else ""
        return f"{self._base_url}{path}{suffix}"

    def _headers(self, *, content_type: bool = False) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = "application/json"
        if self._auth_token is not None:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        return headers

    def _sanitize(self, value: str) -> str:
        if self._auth_token:
            return value.replace(self._auth_token, "[redacted]")
        return value


def _read_bounded(response: Any) -> bytes:
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if not isinstance(raw, bytes):
        raise GhidraError("Ghidra transport returned a non-byte response")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise GhidraError(
            f"Ghidra response exceeds {MAX_RESPONSE_BYTES} bytes"
        )
    return raw


def _error_detail(raw: bytes) -> str:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "HTTP error"
    if isinstance(value, dict):
        detail = value.get("error")
        if isinstance(detail, str):
            return detail
    return "HTTP error"


def _positive_timeout(value: float) -> float:
    converted = float(value)
    if not math.isfinite(converted) or converted <= 0:
        raise ValueError("timeout must be a finite positive number")
    return converted


def _is_timeout(error: BaseException) -> bool:
    current: object = error
    seen: set[int] = set()
    while isinstance(current, BaseException) and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, TimeoutError):
            return True
        if isinstance(current, urllib.error.URLError):
            current = current.reason
            continue
        current = current.__cause__
    return False


def _require_program(program: str) -> None:
    if not isinstance(program, str) or not program.strip():
        raise ValueError("program must not be blank")
