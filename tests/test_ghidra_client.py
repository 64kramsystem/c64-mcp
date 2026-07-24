from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message
from typing import Any

import pytest

from ghidra_mcp_c64.errors import GhidraError
from ghidra_mcp_c64.ghidra_client import GhidraClient


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._stream = io.BytesIO(payload)

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def test_post_sends_explicit_program_and_bearer_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    def fake_open(request: Any, timeout: float) -> FakeResponse:
        observed["request"] = request
        observed["timeout"] = timeout
        return FakeResponse(b'{"committed":false}')

    monkeypatch.setattr("urllib.request.urlopen", fake_open)
    client = GhidraClient(
        "http://127.0.0.1:8089", "secret-token", timeout=30.0
    )

    result = client.call_post(
        "/apply_symbol_profile",
        {"profile": {}},
        {"program": "snapshot name"},
    )

    request = observed["request"]
    assert request.full_url.endswith("program=snapshot+name")
    assert request.method == "POST"
    assert request.headers["Authorization"] == "Bearer secret-token"
    assert json.loads(request.data) == {"profile": {}}
    assert observed["timeout"] == 30.0
    assert result == {"committed": False}


def test_token_never_appears_in_transport_or_upstream_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_open(_request: Any, timeout: float) -> FakeResponse:
        del timeout
        raise urllib.error.URLError("secret-token network detail")

    monkeypatch.setattr("urllib.request.urlopen", fake_open)
    client = GhidraClient("http://127.0.0.1:8089", "secret-token")

    with pytest.raises(GhidraError) as captured:
        client.call_get("/mcp/schema", {})

    assert "secret-token" not in str(captured.value)
    assert "Authorization" not in str(captured.value)


def test_http_and_json_error_shapes_are_stable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = Message()

    def http_failure(_request: Any, timeout: float) -> FakeResponse:
        del timeout
        raise urllib.error.HTTPError(
            "http://127.0.0.1:8089/fail",
            409,
            "conflict",
            headers,
            io.BytesIO(b'{"error":"profile conflict"}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", http_failure)
    client = GhidraClient("http://127.0.0.1:8089")
    with pytest.raises(GhidraError, match="profile conflict"):
        client.call_get("/fail", {})

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: FakeResponse(b'{"error":"bad profile"}'),
    )
    with pytest.raises(GhidraError, match="bad profile"):
        client.call_get("/validate_symbol_profile", {})

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: FakeResponse(b"[]"),
    )
    with pytest.raises(GhidraError, match="JSON object"):
        client.call_get("/mcp/schema", {})


def test_per_call_timeout_overrides_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[float] = []

    def fake_open(_request: Any, timeout: float) -> FakeResponse:
        observed.append(timeout)
        return FakeResponse(b"{}")

    monkeypatch.setattr("urllib.request.urlopen", fake_open)
    client = GhidraClient(
        "http://127.0.0.1:8089", timeout=30.0
    )

    client.call_get("/mcp/schema", {}, timeout=65.0)
    client.call_get("/mcp/schema", {})

    assert observed == [65.0, 30.0]
    with pytest.raises(ValueError, match="timeout"):
        client.call_get("/mcp/schema", {}, timeout=0)


def test_response_body_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ghidra_mcp_c64.ghidra_client.MAX_RESPONSE_BYTES", 8
    )
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: FakeResponse(b'{"long":1}'),
    )

    with pytest.raises(GhidraError, match="response exceeds"):
        GhidraClient("http://127.0.0.1:8089").call_get("/large", {})


def test_read_bytes_requires_exact_complete_lower_or_upper_hex(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    replies = iter(
        [
            b'{"bytes_read":3,"hex_dump":"AA bb\\n0C"}',
            b'{"bytes_read":2,"hex_dump":"aa"}',
            b'{"bytes_read":1,"hex_dump":"gg"}',
        ]
    )
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: FakeResponse(next(replies)),
    )
    client = GhidraClient("http://127.0.0.1:8089")

    assert client.read_bytes("snapshot", "0x1000", 3) == b"\xaa\xbb\x0c"
    with pytest.raises(GhidraError, match="returned 2 of 3"):
        client.read_bytes("snapshot", "0x1000", 3)
    with pytest.raises(GhidraError, match="hex_dump"):
        client.read_bytes("snapshot", "0x1000", 1)


def test_read_bytes_accepts_literal_line_separators_from_generic_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dump = " ".join(f"{value:02X}" for value in range(16))
    dump += "\\n10 "
    payload = json.dumps(
        {"bytes_read": 17, "hex_dump": dump}
    ).encode("utf-8")
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: FakeResponse(payload),
    )

    result = GhidraClient("http://127.0.0.1:8089").read_bytes(
        "snapshot", "0x1000", 17
    )

    assert result == bytes(range(17))


def test_mutating_convenience_calls_always_name_the_program(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[Any] = []

    def fake_open(request: Any, timeout: float) -> FakeResponse:
        del timeout
        requests.append(request)
        return FakeResponse(b"{}")

    monkeypatch.setattr("urllib.request.urlopen", fake_open)
    client = GhidraClient("http://127.0.0.1:8089")

    client.apply_profile("snapshot", {"schema_version": 1}, dry_run=True)
    client.apply_data_regions("snapshot", [], dry_run=True)
    client.write_memory_bytes(
        "snapshot", "0x1000", "aa", dry_run=True
    )

    assert all("program=snapshot" in request.full_url for request in requests)
    assert [request.method for request in requests] == ["POST", "POST", "POST"]


@pytest.mark.parametrize("program", ["", " ", "\n"])
def test_convenience_calls_reject_blank_programs(program: str) -> None:
    client = GhidraClient("http://127.0.0.1:8089")

    with pytest.raises(ValueError, match="program"):
        client.apply_profile(program, {}, dry_run=True)
