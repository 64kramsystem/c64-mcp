import io
import json
import urllib.error

import pytest

from c64_mcp.errors import GhidraError, GhidraTransportError
from c64_mcp.ghidra_client import GhidraClient


class FakeResponse:
    def __init__(self, payload):
        self.stream = io.BytesIO(payload)

    def read(self, size=-1):
        return self.stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


def test_http_requests_name_program_and_decode_json(monkeypatch):
    observed = {}

    def open_request(request, timeout):
        observed.update(request=request, timeout=timeout)
        return FakeResponse(b'{"bytes_read":1,"hex_dump":"AA"}')

    monkeypatch.setattr("urllib.request.urlopen", open_request)
    client = GhidraClient("http://127.0.0.1:8089", timeout=12)

    assert client.read_bytes("game", "RAM:1000", 1) == b"\xaa"
    request = observed["request"]
    assert "program=game" in request.full_url
    assert observed["timeout"] == 12


def test_response_must_be_a_bounded_json_object(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: FakeResponse(b"[]"),
    )
    with pytest.raises(GhidraError, match="JSON object"):
        GhidraClient("http://127.0.0.1:8089").call_get("/mcp/schema", {})

    monkeypatch.setattr("c64_mcp.ghidra_client.MAX_RESPONSE_BYTES", 4)
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: FakeResponse(b'{"ok":true}'),
    )
    with pytest.raises(GhidraError, match="response exceeds"):
        GhidraClient("http://127.0.0.1:8089").call_get("/large", {})


def test_target_invocation_uses_nested_timeout_budget(monkeypatch):
    observed = {}

    def open_request(request, timeout):
        observed.update(request=request, timeout=timeout)
        return FakeResponse(b'{"ok":true}')

    monkeypatch.setattr("urllib.request.urlopen", open_request)
    result = GhidraClient("http://127.0.0.1:8089").invoke_target_method(
        "target",
        "method",
        {"value": 1},
        connector_timeout_ms=10_000,
    )

    body = json.loads(observed["request"].data)
    assert body["timeout_ms"] == 15_000
    assert observed["timeout"] == 20
    assert result["ok"] is True


def test_invocation_timeout_reports_unknown_committed_outcome(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            urllib.error.URLError(TimeoutError())
        ),
    )

    with pytest.raises(GhidraTransportError) as captured:
        GhidraClient("http://127.0.0.1:8089").invoke_target_method(
            "target", "method", {}, connector_timeout_ms=1_000
        )

    assert captured.value.outcome_unknown is True
    assert captured.value.request_committed is True


def test_memory_write_preserves_upstream_error_envelope(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: FakeResponse(
            b'{"error":"conflict","committed":false}'
        ),
    )

    result = GhidraClient("http://127.0.0.1:8089").write_memory_bytes_result(
        "game", "RAM:1000", "aa", dry_run=False
    )

    assert result == {"error": "conflict", "committed": False}
