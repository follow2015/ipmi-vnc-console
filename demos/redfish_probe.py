#!/usr/bin/env python3
"""Bounded Redfish inventory probe; never performs power/configuration actions."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
from typing import Any


class RedfishError(Exception):
    pass


def validate_host(host: str) -> str:
    if not isinstance(host, str) or not host or len(host) > 253:
        raise RedfishError("invalid_host")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
            raise RedfishError("invalid_host") from None
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split(".")):
            raise RedfishError("invalid_host") from None
        return host


def normalize_fingerprint(value: str | None) -> str | None:
    if value is None:
        return None
    result = value.replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", result):
        raise RedfishError("invalid_certificate_fingerprint")
    return result


class Redfish:
    def __init__(self, host: str, port: int = 443, ca_bundle: str | None = None,
                 timeout: float = 5, cert_sha256: str | None = None, *,
                 max_requests: int = 20, total_timeout: float = 60,
                 clock=time.monotonic):
        self.host = validate_host(host)
        if not 1 <= port <= 65535 or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise RedfishError("invalid_connection_limits")
        if not 3 <= max_requests <= 200 or not math.isfinite(total_timeout) or not 0 < total_timeout <= 300:
            raise RedfishError("invalid_probe_limits")
        if ca_bundle is not None and cert_sha256 is not None:
            raise RedfishError("conflicting_tls_modes")
        self.port, self.timeout = port, timeout
        self.cert_sha256 = normalize_fingerprint(cert_sha256)
        try:
            self.context = ssl.create_default_context(cafile=ca_bundle)
        except (OSError, ssl.SSLError):
            raise RedfishError("invalid_ca_bundle") from None
        if self.cert_sha256:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        self.clock = clock
        self.deadline = clock() + total_timeout
        self.max_requests = max_requests
        self.requests_used = 0
        self.token: str | None = None
        self.session_url: str | None = None
        self.session_state = "not_created"

    def path(self, path: str) -> str:
        if not isinstance(path, str) or len(path) > 2048 or any(ord(c) < 32 for c in path):
            raise RedfishError("invalid_resource_path")
        try:
            parsed = urllib.parse.urlsplit(path)
        except ValueError:
            raise RedfishError("invalid_resource_path") from None
        decoded = urllib.parse.unquote(parsed.path)
        if (parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/redfish/v1/")
                or "\\" in decoded or any(p in (".", "..") for p in decoded.split("/"))):
            raise RedfishError("invalid_resource_path")
        return urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))

    def remaining(self) -> float:
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise RedfishError("probe_deadline_exceeded")
        return min(self.timeout, remaining)

    def request(self, path: str, method: str = "GET", payload: dict[str, Any] | None = None, *, cleanup=False):
        request_path = self.path(path)
        if method not in ("GET", "POST", "DELETE"):
            raise RedfishError("method_denied")
        if method == "POST" and request_path != "/redfish/v1/SessionService/Sessions":
            raise RedfishError("method_denied")
        if method == "DELETE" and not cleanup:
            raise RedfishError("method_denied")
        if self.requests_used >= self.max_requests - (0 if cleanup else 1):
            raise RedfishError("request_budget_exceeded")
        timeout = min(5.0, self.timeout) if cleanup else self.remaining()
        self.requests_used += 1
        headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["X-Auth-Token"] = self.token
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=self.context)
        cleanup_deadline = self.clock()+timeout

        def read_timeout():
            if not cleanup:
                return self.remaining()
            value = cleanup_deadline-self.clock()
            if value <= 0:
                raise RedfishError("cleanup_deadline_exceeded")
            return value

        try:
            conn.connect()
            if self.cert_sha256:
                actual = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
                if actual != self.cert_sha256:
                    raise RedfishError("tls_identity_mismatch")
            conn.sock.settimeout(read_timeout())
            if method == "POST":
                self.session_state = "possible"
            conn.request(method, request_path, body=data, headers=headers)
            conn.sock.settimeout(read_timeout())
            response = conn.getresponse()
            if method == "POST" and response.status in (401, 403):
                self.session_state = "not_created"
            if method == "POST" and response.status in (200, 201):
                self.session_state = "created"
                self.token = response.headers.get("X-Auth-Token")
                self.session_url = response.headers.get("Location")
            if 300 <= response.status < 400:
                raise RedfishError(f"redirect_denied_{response.status}")
            if response.status >= 400:
                raise RedfishError(f"http_{response.status}")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise RedfishError("unsupported_content_encoding")
            chunks = bytearray()
            while True:
                next_timeout = read_timeout()
                if conn.sock is not None:
                    conn.sock.settimeout(next_timeout)
                chunk = response.read1(min(65536, 2_000_001-len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
                if len(chunks) > 2_000_000:
                    raise RedfishError("response_too_large")
            return response.status, response.headers, bytes(chunks)
        except ssl.SSLCertVerificationError:
            raise RedfishError("tls_verification_failed") from None
        except (OSError, TimeoutError, http.client.HTTPException):
            raise RedfishError("transport_failed") from None
        finally:
            conn.close()

    def json(self, path: str) -> dict[str, Any]:
        _, _, raw = self.request(path)
        try:
            result = json.loads(raw)
        except (UnicodeDecodeError, ValueError):
            raise RedfishError("invalid_json") from None
        if not isinstance(result, dict):
            raise RedfishError("invalid_json_object")
        return result

    def login(self, username: str, password: str) -> None:
        status, _, _ = self.request("/redfish/v1/SessionService/Sessions", "POST",
                                    {"UserName": username, "Password": password})
        if status not in (200, 201) or not self.token:
            raise RedfishError("invalid_session_response")

    def logout(self) -> str:
        if self.session_state == "not_created":
            return "not_needed"
        if not self.token or not self.session_url:
            self.token = None
            return "unavailable"
        try:
            parsed = urllib.parse.urlsplit(self.session_url)
            if parsed.scheme or parsed.netloc:
                if (parsed.scheme != "https" or parsed.hostname != self.host or (parsed.port or 443) != self.port
                        or parsed.username or parsed.password):
                    raise RedfishError("invalid_session_location")
            path = parsed.path
            if (parsed.query or parsed.fragment
                    or not re.fullmatch(r"/redfish/v1/SessionService/Sessions/[A-Za-z0-9_.-]+", path)
                    or path.rsplit("/", 1)[-1] in (".", "..")):
                raise RedfishError("invalid_session_location")
            self.request(path, "DELETE", cleanup=True)
            self.session_state = "not_created"
            self.session_url = None
            return "ok"
        finally:
            self.token = None


FIELDS = ("Id", "Name", "Manufacturer", "Model", "FirmwareVersion", "ManagerType", "PowerState")


def inventory(client: Redfish, root: dict, max_members: int = 12) -> dict:
    if not 1 <= max_members <= 50:
        raise RedfishError("invalid_member_budget")
    output = {"resources": {}, "truncated": False}
    members_left = max_members
    for name in ("Managers", "Systems", "Chassis"):
        link = root.get(name)
        endpoint = link.get("@odata.id") if isinstance(link, dict) else None
        if not endpoint:
            continue
        items = []
        visited = set()
        while endpoint:
            if endpoint in visited:
                raise RedfishError("pagination_cycle")
            visited.add(endpoint)
            collection = client.json(endpoint)
            members = collection.get("Members", [])
            if not isinstance(members, list):
                raise RedfishError("invalid_members")
            for ref in members:
                if members_left <= 0:
                    output["truncated"] = True
                    break
                if not isinstance(ref, dict) or not isinstance(ref.get("@odata.id"), str):
                    raise RedfishError("invalid_member_reference")
                item = client.json(ref["@odata.id"])
                items.append({field: item[field][:256] for field in FIELDS if isinstance(item.get(field), str)})
                members_left -= 1
            next_page = collection.get("Members@odata.nextLink")
            if next_page is not None and not isinstance(next_page, str):
                raise RedfishError("invalid_next_page")
            endpoint = next_page
            if endpoint and members_left <= 0:
                output["truncated"] = True
                break
        output["resources"][name] = items
    return output


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=443)
    trust = p.add_mutually_exclusive_group()
    trust.add_argument("--ca-bundle")
    trust.add_argument("--cert-sha256")
    p.add_argument("--show-cert-fingerprint", action="store_true", help="only acquire untrusted certificate metadata, no HTTP")
    p.add_argument("--timeout", type=float, default=5)
    p.add_argument("--total-timeout", type=float, default=60)
    p.add_argument("--max-requests", type=int, default=20, help="includes one reserved logout request")
    p.add_argument("--max-members", type=int, default=12, help="global member-detail limit across collections")
    p.add_argument("--inventory", action="store_true", help="also read bounded inventory without creating a session")
    p.add_argument("--authenticate", action="store_true", help="create a session using BMC_USER/BMC_PASSWORD, then read inventory")
    return p


def main(argv=None) -> int:
    p = parser()
    args = p.parse_args(argv)
    try:
        validate_host(args.host)
        normalize_fingerprint(args.cert_sha256)
        if not 1 <= args.max_members <= 50:
            raise RedfishError("invalid_member_budget")
        if args.show_cert_fingerprint and (args.authenticate or args.inventory or args.ca_bundle is not None or args.cert_sha256 is not None):
            raise RedfishError("fingerprint_only_conflicting_options")
        client = Redfish(args.host, args.port, args.ca_bundle, args.timeout, args.cert_sha256,
                         max_requests=args.max_requests, total_timeout=args.total_timeout)
    except RedfishError as exc:
        p.error(str(exc))
    if args.authenticate and (not os.environ.get("BMC_USER") or not os.environ.get("BMC_PASSWORD")):
        p.error("--authenticate requires BMC_USER and BMC_PASSWORD")
    report = {"probe": "redfish", "host": args.host, "authentication": "not_requested", "session_cleanup": "not_needed"}
    try:
        if args.show_cert_fingerprint:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((args.host, args.port), timeout=args.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=args.host) as tls:
                    report.update({"certificate_sha256": hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest(),
                                   "trusted": False, "note": "verify via a trusted independent channel before using credentials"})
        else:
            root = client.json("/redfish/v1/")
            report.update({"reachable": True, "redfish_version": root.get("RedfishVersion")})
            if args.authenticate:
                report["authentication"] = "failed_or_unconfirmed"
                client.login(os.environ["BMC_USER"], os.environ["BMC_PASSWORD"])
                report["authentication"] = "ok"
            if args.inventory or args.authenticate:
                report["inventory"] = inventory(client, root, args.max_members)
        exit_code = 0
    except (RedfishError, OSError, http.client.HTTPException) as exc:
        report["error"] = str(exc) if isinstance(exc, RedfishError) else "transport_failed"
        exit_code = 2
    finally:
        if args.authenticate:
            try:
                report["session_cleanup"] = client.logout()
            except (RedfishError, ValueError) as exc:
                report["session_cleanup"] = "failed"
                report["cleanup_error"] = str(exc) if isinstance(exc, RedfishError) else "invalid_session_location"
        report["requests_used"] = client.requests_used
    if exit_code == 0 and report["session_cleanup"] in ("failed", "unavailable"):
        exit_code = 3
    print(json.dumps(report, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
