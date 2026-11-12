"""Real TLS, certificate pinning, bounded inventory and logout against a local Redfish fixture."""
import hashlib
import http.server
import json
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from demos.redfish_probe import Redfish, RedfishError, inventory, main
from tools.bootstrap import generate


@pytest.fixture
def device(tmp_path):
    directory = generate(tmp_path/"device")
    cfg = json.loads((directory/"mock.json").read_text())
    state = {"requests": [], "mode": "ok", "pages": False,
             "handler_errors": [], "unexpected_errors": []}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def record(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            state["requests"].append((self.command, self.path, dict(self.headers), body))

        def reply(self, status, body=None, headers=None):
            raw = json.dumps(body).encode() if body is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            try:
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                pass

        def do_GET(self):
            self.record()
            if self.path == "/redfish/v1/":
                if state["mode"] == "redirect":
                    self.reply(302, {"error": "SECRET_FROM_BMC"}, {"Location": "https://example.invalid/"})
                else:
                    self.reply(200, {"RedfishVersion": "test", "Managers": {"@odata.id": "/redfish/v1/Managers"}})
            elif self.path == "/redfish/v1/Managers":
                body = {"Members": [{"@odata.id": "/redfish/v1/Managers/1"}]}
                if state["pages"]:
                    body["Members@odata.nextLink"] = "/redfish/v1/Managers?page=2"
                self.reply(200, body)
            elif self.path == "/redfish/v1/Managers?page=2":
                self.reply(200, {"Members": [{"@odata.id": "/redfish/v1/Managers/2"}]})
            elif self.path.startswith("/redfish/v1/Managers/"):
                self.reply(200, {"Id": self.path.rsplit("/", 1)[-1], "Manufacturer": "Fixture", "Model": "Test BMC",
                                 "FirmwareVersion": "1.0", "SecretToken": "NEVER_PRINT_THIS"})
            else:
                self.reply(404)

        def do_POST(self):
            self.record()
            if state["mode"] == "auth_failed":
                self.reply(401, {"error": "SECRET_FROM_BMC"})
                return
            headers = {"X-Auth-Token": "redfish-private-token"}
            if state["mode"] != "missing_location":
                headers["Location"] = ("https://other.invalid/redfish/v1/SessionService/Sessions/1"
                                       if state["mode"] == "foreign_location" else "/redfish/v1/SessionService/Sessions/1")
            self.reply(201, {}, headers)

        def do_DELETE(self):
            self.record()
            assert self.headers.get("X-Auth-Token") == "redfish-private-token"
            assert self.path == "/redfish/v1/SessionService/Sessions/1"
            self.reply(503 if state["mode"] == "cleanup_failure" else 204)

    class Server(http.server.ThreadingHTTPServer):

        def handle_error(self, request, client_address):
            error = sys.exc_info()[1]
            if isinstance(error, (ConnectionResetError, ConnectionAbortedError,
                                  BrokenPipeError, ssl.SSLError, TimeoutError)):
                state["handler_errors"].append(type(error).__name__)
                return
            state["unexpected_errors"].append(repr(error))
            super().handle_error(request, client_address)

    server = Server(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cfg["cert"], cfg["key"])
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cert = x509.load_pem_x509_certificate(Path(cfg["cert"]).read_bytes())
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    state.update({"port": server.server_port, "fingerprint": fp})
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def client(device, **kwargs):
    return Redfish("127.0.0.1", device["port"], cert_sha256=device["fingerprint"], **kwargs)


def args(device):
    return ["--host", "127.0.0.1", "--port", str(device["port"]), "--cert-sha256", device["fingerprint"]]


def credentials(monkeypatch):
    monkeypatch.setenv("BMC_USER", "test-user")
    monkeypatch.setenv("BMC_PASSWORD", "credential-must-not-appear")


def test_authenticated_inventory_and_cleanup_are_sanitized(device, monkeypatch, capsys):
    credentials(monkeypatch)
    assert main(args(device)+["--authenticate"]) == 0
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["authentication"] == "ok" and report["session_cleanup"] == "ok"
    assert report["inventory"]["resources"]["Managers"][0]["FirmwareVersion"] == "1.0"
    assert not any(secret in output for secret in ("credential-must-not-appear", "redfish-private-token", "NEVER_PRINT_THIS"))
    assert device["requests"][-1][0] == "DELETE"


def test_pin_mismatch_sends_no_http_or_credentials(device):
    c = Redfish("127.0.0.1", device["port"], cert_sha256="00"*32)
    with pytest.raises(RedfishError, match="tls_identity_mismatch"):
        c.login("user", "password")
    assert device["requests"] == [] and c.session_state == "not_created"


def test_aborted_peer_is_not_dumped_and_the_server_keeps_serving(device):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", device["port"]), timeout=5) as raw:
        context.wrap_socket(raw).close()
    deadline = time.monotonic() + 5
    while not device["handler_errors"] and time.monotonic() < deadline:
        time.sleep(0.02)
    assert device["handler_errors"], "the aborted connection was never handled"
    assert device["unexpected_errors"] == []
    assert client(device).json("/redfish/v1/")["RedfishVersion"] == "test"


def test_option_errors_name_the_probe_not_the_test_runner(capsys):
    with pytest.raises(SystemExit) as error:
        main(["--host", "127.0.0.1", "--max-requests", "2"])
    assert error.value.code == 2
    assert capsys.readouterr().err.startswith("usage: redfish_probe")


def test_request_budget_preserves_logout(device, monkeypatch, capsys):
    credentials(monkeypatch)
    assert main(args(device)+["--authenticate", "--max-requests", "4"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["error"] == "request_budget_exceeded"
    assert report["requests_used"] == 4 and report["session_cleanup"] == "ok"
    assert [r[0] for r in device["requests"]] == ["GET", "POST", "GET", "DELETE"]


def test_probe_deadline_does_not_prevent_logout(device):
    clock = [0.0]
    c = client(device, clock=lambda: clock[0], total_timeout=10)
    c.login("user", "password")
    clock[0] = 11
    with pytest.raises(RedfishError, match="probe_deadline_exceeded"):
        c.json("/redfish/v1/")
    assert c.logout() == "ok"
    assert [r[0] for r in device["requests"]] == ["POST", "DELETE"]


@pytest.mark.parametrize("mode,expected", [("cleanup_failure", "failed"), ("missing_location", "unavailable"), ("foreign_location", "failed")])
def test_cleanup_failure_and_unsafe_location_report_separately(device, monkeypatch, capsys, mode, expected):
    device["mode"] = mode
    credentials(monkeypatch)
    assert main(args(device)+["--authenticate"]) == 3
    report = json.loads(capsys.readouterr().out)
    assert report["authentication"] == "ok" and report["session_cleanup"] == expected
    if mode == "foreign_location":
        assert not any(r[0] == "DELETE" for r in device["requests"])


def test_bad_login_is_not_reported_as_residual_session(device, monkeypatch, capsys):
    device["mode"] = "auth_failed"
    credentials(monkeypatch)
    assert main(args(device)+["--authenticate"]) == 2
    output = capsys.readouterr().out
    assert "SECRET_FROM_BMC" not in output
    assert json.loads(output)["session_cleanup"] == "not_needed"
    assert len([r for r in device["requests"] if r[0] == "POST"]) == 1


def test_pagination_and_global_member_limit(device):
    device["pages"] = True
    c = client(device)
    result = inventory(c, {"Managers": {"@odata.id": "/redfish/v1/Managers"}}, max_members=1)
    assert result["truncated"] and len(result["resources"]["Managers"]) == 1
    assert not any("?page=2" in r[1] for r in device["requests"])
    c = client(device)
    result = inventory(c, {"Managers": {"@odata.id": "/redfish/v1/Managers"}}, max_members=2)
    assert not result["truncated"] and len(result["resources"]["Managers"]) == 2


@pytest.mark.parametrize("extra", [
    ["--cert-sha256", ""], ["--cert-sha256", "invalid"],
    ["--show-cert-fingerprint", "--authenticate"],
    ["--show-cert-fingerprint", "--ca-bundle", "nonexistent"],
    ["--timeout", "nan"], ["--total-timeout", "inf"], ["--max-requests", "2"],
])
def test_invalid_options_fail_before_network(extra):
    with pytest.raises(SystemExit) as error:
        main(["--host", "127.0.0.1"]+extra)
    assert error.value.code == 2


@pytest.mark.parametrize("path", ["https://evil.example/redfish/v1/", "//evil.example/redfish/v1/", "/redfish/v1/../other", "/redfish/v1/%2e%2e/other", "//[malformed/redfish/v1/"])
def test_untrusted_resource_reference_rejected_before_request(device, path):
    c = client(device)
    with pytest.raises(RedfishError, match="invalid_resource_path"):
        c.json(path)
    assert device["requests"] == []


def test_redirect_is_reported_without_response_body(device, capsys):
    device["mode"] = "redirect"
    assert main(args(device)) == 2
    output = capsys.readouterr().out
    assert json.loads(output)["error"] == "redirect_denied_302"
    assert "SECRET_FROM_BMC" not in output
