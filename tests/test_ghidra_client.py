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

    def open_request(_self, request, timeout):
        observed.update(request=request, timeout=timeout)
        return FakeResponse(b'{"bytes_read":1,"hex_dump":"AA"}')

    monkeypatch.setattr("urllib.request.OpenerDirector.open", open_request)
    client = GhidraClient(timeout=12, socket_path="/unused")

    assert client.read_bytes("game", "RAM:1000", 1) == b"\xaa"
    request = observed["request"]
    assert "program=game" in request.full_url
    assert observed["timeout"] == 12


def test_response_must_be_a_bounded_json_object(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.OpenerDirector.open",
        lambda *_args, **_kwargs: FakeResponse(b"[]"),
    )
    with pytest.raises(GhidraError, match="JSON object"):
        GhidraClient(socket_path="/unused").call_get("/mcp/schema", {})

    monkeypatch.setattr("c64_mcp.ghidra_client.MAX_RESPONSE_BYTES", 4)
    monkeypatch.setattr(
        "urllib.request.OpenerDirector.open",
        lambda *_args, **_kwargs: FakeResponse(b'{"ok":true}'),
    )
    with pytest.raises(GhidraError, match="response exceeds"):
        GhidraClient(socket_path="/unused").call_get("/large", {})


def test_memory_read_rejects_old_formatted_hex_dumps(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.OpenerDirector.open",
        lambda *_args, **_kwargs: FakeResponse(
            json.dumps({"bytes_read": 2, "hex_dump": "AA\\nBB"}).encode()
        ),
    )
    with pytest.raises(GhidraError, match="malformed hex_dump"):
        GhidraClient(socket_path="/unused").read_bytes("game", "RAM:1000", 2)


def test_target_invocation_uses_nested_timeout_budget(monkeypatch):
    observed = {}

    def open_request(_self, request, timeout):
        observed.update(request=request, timeout=timeout)
        return FakeResponse(b'{"ok":true}')

    monkeypatch.setattr("urllib.request.OpenerDirector.open", open_request)
    result = GhidraClient(socket_path="/unused").invoke_target_method(
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
        "urllib.request.OpenerDirector.open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            urllib.error.URLError(TimeoutError())
        ),
    )

    with pytest.raises(GhidraTransportError) as captured:
        GhidraClient(socket_path="/unused").invoke_target_method(
            "target", "method", {}, connector_timeout_ms=1_000
        )

    assert captured.value.outcome_unknown is True
    assert captured.value.request_committed is True


def test_memory_write_preserves_upstream_error_envelope(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.OpenerDirector.open",
        lambda *_args, **_kwargs: FakeResponse(
            b'{"error":"conflict","committed":false}'
        ),
    )

    result = GhidraClient(socket_path="/unused").write_memory_bytes_result(
        "game", "RAM:1000", "aa", dry_run=False
    )

    assert result == {"error": "conflict", "committed": False}


@pytest.fixture
def socket_dir():
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory(dir="/tmp", prefix="c64-") as directory:
        yield Path(directory)


@pytest.fixture
def unix_servers(socket_dir):
    import contextlib
    import http.server
    import socketserver
    import threading

    @contextlib.contextmanager
    def start(
        name,
        pid,
        payload=b'{"ok":true}',
        status=200,
        discovery_payload=None,
        redirect=None,
    ):
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.respond()

            def do_POST(self):
                self.respond()

            def respond(self):
                size = int(self.headers.get("Content-Length", 0))
                requests.append((self.command, self.path, self.rfile.read(size)))
                if payload is None:
                    return
                discovery = self.path == "/mcp/instance_info"
                body = (
                    json.dumps({"data": {"pid": pid}}).encode()
                    if discovery
                    else payload
                )
                if discovery and discovery_payload is not None:
                    body = discovery_payload
                self.send_response(302 if redirect else (200 if discovery else status))
                if redirect:
                    self.send_header("Location", redirect)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        path = socket_dir / f"{name}.sock"
        server = socketserver.UnixStreamServer(str(path), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield str(path), requests
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
            path.unlink(missing_ok=True)

    return start


def test_unix_requests_ignore_proxies_and_preserve_http_semantics(
    unix_servers, monkeypatch
):
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("no_proxy", "")
    with unix_servers("explicit", 1) as (path, requests):
        client = GhidraClient(socket_path=path)
        assert client.call_post("/write", {"value": "é"}, {"program": "a b"}) == {
            "ok": True
        }
        assert requests == [("POST", "/write?program=a+b", b'{"value":"\xc3\xa9"}')]
    with (
        unix_servers("error", 2, b'{"error":"bad"}', 409) as (path, _),
        pytest.raises(GhidraError, match="HTTP 409.*bad"),
    ):
        GhidraClient(socket_path=path).call_get("/bad", {})


def test_discovery_is_lazy_filters_stale_and_pins_selection(
    unix_servers, monkeypatch, socket_dir
):
    monkeypatch.setattr("c64_mcp.ghidra_client.socket_dirs", lambda: [socket_dir])
    (socket_dir / "stale.sock").touch()
    client = GhidraClient()
    with unix_servers("first", 1) as (path, requests):
        assert requests == []
        assert client.call_get("/one", {}) == {"ok": True}
        assert [r[1] for r in requests] == ["/mcp/instance_info", "/one"]
        with unix_servers("second", 2) as (_, other_requests):
            assert client.call_get("/two", {}) == {"ok": True}
            assert other_requests == []
    with unix_servers("replacement", 3) as (_, requests):
        with pytest.raises(GhidraTransportError, match=path):
            client.call_post("/write", {}, {})
        assert requests == []


def test_discovery_requires_exactly_one_reachable_instance(
    unix_servers, monkeypatch, socket_dir
):
    monkeypatch.setattr(
        "c64_mcp.ghidra_client.socket_dirs", lambda: [socket_dir, socket_dir]
    )
    with pytest.raises(GhidraError, match="candidates: none"):
        GhidraClient().call_get("/one", {})
    with (
        unix_servers("first", 1) as (first, first_requests),
        unix_servers("second", 2) as (second, second_requests),
    ):
        with pytest.raises(GhidraError) as captured:
            GhidraClient().call_post("/write", {}, {})
        assert first in str(captured.value) and second in str(captured.value)
        assert all(
            r[1] == "/mcp/instance_info" for r in first_requests + second_requests
        )


def test_unix_failures_include_endpoint_and_cause(socket_dir):
    path = str(socket_dir / "missing.sock")
    with pytest.raises(GhidraTransportError) as captured:
        GhidraClient(socket_path=path).call_get("/read", {})
    assert path in str(captured.value)
    assert "No such file" in str(captured.value)
    assert captured.value.code == "ghidra_transport_failure"
    assert captured.value.request_committed is False


def test_unix_dropped_write_is_not_replayed(unix_servers):
    with unix_servers("drop", 1, payload=None) as (path, requests):
        with pytest.raises(GhidraTransportError) as captured:
            GhidraClient(socket_path=path).call_post("/write", {"value": 1}, {})
        assert len(requests) == 1
        assert requests[0][0:2] == ("POST", "/write")
        assert captured.value.request_committed is True
        assert captured.value.outcome_unknown is True


def test_server_construction_does_not_discover(monkeypatch):
    from c64_mcp.config import Settings
    from c64_mcp.server import create_server

    def unexpected_discovery():
        pytest.fail("server construction must not discover sockets")

    monkeypatch.setattr("c64_mcp.ghidra_client._discover_socket", unexpected_discovery)
    create_server(Settings.from_environ({}))


def test_discovery_failure_is_pre_send_transport_error(monkeypatch, socket_dir):
    import socket

    monkeypatch.setattr("c64_mcp.ghidra_client.socket_dirs", lambda: [socket_dir])
    stale = socket_dir / "stale.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind(str(stale))
    with pytest.raises(GhidraTransportError) as captured:
        GhidraClient().call_post("/write", {"value": 1}, {})
    error = captured.value
    assert error.code == "ghidra_transport_failure"
    assert error.request_committed is False
    assert error.outcome_unknown is False
    assert str(socket_dir) in str(error)
    assert str(stale) in str(error)
    assert "Connection refused" in str(error)


def test_oversized_discovery_candidate_does_not_hide_valid_socket(
    monkeypatch, socket_dir, unix_servers
):
    monkeypatch.setattr("c64_mcp.ghidra_client.socket_dirs", lambda: [socket_dir])
    monkeypatch.setattr("c64_mcp.ghidra_client.MAX_RESPONSE_BYTES", 40)
    with (
        unix_servers("oversized", 1, discovery_payload=b"x" * 41),
        unix_servers("valid", 2) as (_, requests),
    ):
        assert GhidraClient().call_get("/read", {}) == {"ok": True}
        assert requests[-1][1] == "/read"


def test_vice_classifies_discovery_as_transport_failure(monkeypatch, socket_dir):
    from c64_mcp.vice import ViceSession

    monkeypatch.setattr("c64_mcp.ghidra_client.socket_dirs", lambda: [socket_dir])
    result = ViceSession(GhidraClient()).connect()
    assert result["ok"] is False
    assert result["error"]["code"] == "ghidra_transport_failure"
    assert result["error"]["outcome_unknown"] is False
    assert result["error"]["request_committed"] is False


def test_unix_redirects_never_contact_tcp(monkeypatch, socket_dir, unix_servers):
    import socketserver
    import threading

    requests = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            requests.append(self.client_address)

    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        redirect = f"https://127.0.0.1:{server.server_address[1]}/escaped"
        with unix_servers("redirect", 1, redirect=redirect) as (path, _):
            with pytest.raises(GhidraError, match="HTTP 302"):
                GhidraClient(socket_path=path).call_get("/read", {})
            monkeypatch.setattr(
                "c64_mcp.ghidra_client.socket_dirs", lambda: [socket_dir]
            )
            with pytest.raises(GhidraTransportError, match="HTTP Error 302"):
                GhidraClient().call_get("/read", {})
        assert requests == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
