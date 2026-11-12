"""Adapter contract from design section 5.2."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

UPSTREAM_AUTH_HEADERS = frozenset({
    "cookie", "authorization", "proxy-authorization", "x-auth-token",
    "x-csrf-token", "x-xsrf-token", "set-cookie",
})
RESPONSE_AUTH_HEADERS = frozenset({
    "set-cookie", "authorization", "proxy-authorization", "x-auth-token",
})

ENABLED_ADAPTER_IDS = frozenset({"mock-v1"})
ADAPTERS: dict[str, type[AdapterContract]] = {}


class AdapterDiscoveryError(ValueError):
    pass


class AdapterPolicyError(ValueError):
    pass


class AdapterUnavailable(RuntimeError):

    def __init__(self, operation: str):
        super().__init__(
            f"{operation} requires an approved adapter_capability entry, an independently "
            "verified fingerprint, licensing/least-privilege confirmation and Worker wiring. "
            "The upstream protocol transport exists and has been exercised only by the bounded "
            "probe tool; only discover(), console_spec() and the protocol/transport layers are "
            "available to the platform"
        )
        self.operation = operation


@dataclass(frozen=True)
class DiscoveryResult:
    vendor: str
    model: str
    firmware: str
    console_implementation: str
    candidate_consoles: tuple[str, ...]
    kvm_service_port: int
    upstream_tls: str
    evidence: tuple[str, ...]
    unconfirmed: tuple[str, ...]


@dataclass(frozen=True)
class ConsoleSpec:
    entry_path: str
    allowed_methods: frozenset[str]
    allowed_exact_paths: tuple[str, ...]
    allowed_path_prefixes: tuple[str, ...]
    login_path: str
    websocket_path: str
    websocket_scheme: str
    websocket_port: int
    websocket_binary: bool
    upstream_auth: str
    max_frame_bytes: int
    codec: str
    close_rule: str


class AdapterContract(ABC):

    adapter_id: str = ""
    capability_status: str = "unverified"

    @abstractmethod
    def discover(self, evidence: Mapping[str, Any]) -> DiscoveryResult:
        pass

    @abstractmethod
    def console_spec(self) -> ConsoleSpec:
        pass

    def rewrite_request(self, method: str, path: str, headers: Mapping[str, str], *,
                        upstream_host: str, browser_origin: str,
                        expected_origin: str) -> dict[str, str]:
        spec = self.console_spec()
        if browser_origin != expected_origin:
            raise AdapterPolicyError("origin_mismatch")
        if method.upper() not in spec.allowed_methods:
            raise AdapterPolicyError("method_denied")
        if method.upper() == "POST" and path != spec.login_path:
            raise AdapterPolicyError("post_path_denied")
        if not self._path_allowed(path, spec):
            raise AdapterPolicyError("path_denied")
        clean: dict[str, str] = {}
        for key, value in headers.items():
            low = key.lower()
            if low in UPSTREAM_AUTH_HEADERS or low in ("host", "origin", "referer"):
                continue
            if low in ("upgrade", "connection", "sec-websocket-key", "sec-websocket-version",
                       "sec-websocket-protocol"):
                if path != spec.websocket_path:
                    raise AdapterPolicyError("websocket_header_on_http_path")
                continue
            clean[key] = value
        clean["Host"] = upstream_host
        clean["Origin"] = f"https://{upstream_host}"
        return clean

    def rewrite_response(self, headers: list[tuple[str, str]], *,
                         upstream_host: str) -> tuple[list[tuple[str, str]], list[str]]:
        absorbed: list[str] = []
        out: list[tuple[str, str]] = []
        for key, value in headers:
            low = key.lower()
            if low == "set-cookie":
                absorbed.append(value)
                continue
            if low in RESPONSE_AUTH_HEADERS:
                continue
            if low == "location" and not self._safe_location(value, upstream_host):
                raise AdapterPolicyError("foreign_redirect")
            out.append((key, value))
        return out, absorbed

    @staticmethod
    def _path_allowed(path: str, spec: ConsoleSpec) -> bool:
        if not path.startswith("/") or ".." in path.split("/"):
            return False
        return (path in spec.allowed_exact_paths or path == spec.websocket_path
                or path.startswith(spec.allowed_path_prefixes))

    @staticmethod
    def _safe_location(value: str, upstream_host: str) -> bool:
        parsed = urlsplit(value)
        if parsed.scheme or parsed.netloc:
            return (parsed.scheme == "https" and parsed.hostname == upstream_host.split(":")[0]
                    and not parsed.username and not parsed.password)
        return value.startswith("/") and not value.startswith("//")

    def authenticate(self, *args: Any, **kwargs: Any):
        raise AdapterUnavailable("authenticate")

    def open_console(self, *args: Any, **kwargs: Any):
        raise AdapterUnavailable("open_console")

    def keepalive(self, *args: Any, **kwargs: Any):
        raise AdapterUnavailable("keepalive")

    def logout(self, *args: Any, **kwargs: Any):
        raise AdapterUnavailable("logout")


def register(cls: type[AdapterContract]) -> type[AdapterContract]:
    if not cls.adapter_id or cls.adapter_id in ENABLED_ADAPTER_IDS:
        raise ValueError("adapter id must be non-empty and not collide with enabled adapters")
    ADAPTERS[cls.adapter_id] = cls
    return cls


def is_enabled(adapter_id: str) -> bool:
    return adapter_id in ENABLED_ADAPTER_IDS
