"""Read-only BMC identity probe, shared by the asset-entry API."""
from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import time
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from demos.redfish_probe import (Redfish, RedfishError, inventory as redfish_inventory,
                                 legacy_tls_context, validate_host)

from ..common import parse_controlled_networks


RETRYABLE_CODES = frozenset({"certificate_unavailable", "inventory_unavailable"})

_INVENTORY_BUDGET = 30.0

ALLOWED_PROBE_PORTS = frozenset({443, 8443})


class ProbeError(ValueError):

    def __init__(self, code: str, *, retryable: bool | None = None):
        super().__init__(code)
        self.code = code
        self.retryable = code in RETRYABLE_CODES if retryable is None else retryable


_METADATA_IPS = frozenset({
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("fd00:ec2::254"),
})


def _reject_unsafe_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if (address.is_loopback or address.is_link_local or address.is_multicast
            or address.is_unspecified or address.is_reserved
            or address in _METADATA_IPS):
        raise ProbeError("probe_target_not_allowed")


def validate_probe_target(host: str, *, allowed_networks=(),
                          require_networks=False) -> tuple[str, str]:
    networks = parse_controlled_networks(allowed_networks)
    if require_networks and not networks:
        raise ProbeError("probe_target_not_allowed")
    try:
        name = validate_host(host)
    except RedfishError:
        raise ProbeError("invalid_probe_target") from None
    try:
        literal = ipaddress.ip_address(name)
        addresses = [literal]
    except ValueError:
        if networks:
            raise ProbeError("probe_target_not_allowed") from None
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except OSError:
            raise ProbeError("probe_dns_failed") from None
        if not infos:
            raise ProbeError("probe_dns_failed")
        addresses = []
        for info in infos:
            try:
                addresses.append(ipaddress.ip_address(info[4][0]))
            except ValueError:
                raise ProbeError("invalid_probe_target") from None
    for address in addresses:
        _reject_unsafe_address(address)
        if networks and not any(address in network for network in networks):
            raise ProbeError("probe_target_not_allowed")
    return str(addresses[0]), name


def validate_probe_host(host: str, *, allowed_networks=()) -> str:
    connect_ip, _ = validate_probe_target(host, allowed_networks=allowed_networks)
    return connect_ip


def read_certificate_sha256(connect_ip: str, sni_name: str, port: int,
                            timeout: float) -> str:
    context = legacy_tls_context(relaxed_identity=True)
    try:
        with socket.create_connection((connect_ip, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=sni_name) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        raise ProbeError("certificate_unavailable") from None
    if not der:
        raise ProbeError("certificate_unavailable")
    return hashlib.sha256(der).hexdigest()


def read_inventory(connect_ip: str, sni_name: str, port: int, timeout: float,
                   fingerprint: str, username: str, password: str) -> tuple[dict, str]:
    def is_tls_mismatch(exc: BaseException) -> bool:
        return isinstance(exc, RedfishError) and str(exc) == "tls_identity_mismatch"

    shared_deadline = time.monotonic() + _INVENTORY_BUDGET
    try:
        client = Redfish(sni_name, port, None, timeout, fingerprint,
                         max_requests=20, total_timeout=_INVENTORY_BUDGET,
                         basic_auth=(username, password), connect_ip=connect_ip,
                         deadline=shared_deadline)
        root = client.json("/redfish/v1/")
        return redfish_inventory(client, root, 12), "basic"
    except (RedfishError, OSError) as exc:
        if is_tls_mismatch(exc):
            raise ProbeError("tls_identity_mismatch", retryable=False) from None
    client = Redfish(sni_name, port, None, timeout, fingerprint,
                     max_requests=20, total_timeout=_INVENTORY_BUDGET,
                     connect_ip=connect_ip, deadline=shared_deadline)
    try:
        client.login(username, password)
        root = client.json("/redfish/v1/")
        return redfish_inventory(client, root, 12), "session"
    except (RedfishError, OSError) as exc:
        code = str(exc) if isinstance(exc, RedfishError) else ""
        if code.startswith("http_401") or code.startswith("http_403"):
            raise ProbeError("probe_auth_failed") from None
        if is_tls_mismatch(exc):
            raise ProbeError("tls_identity_mismatch", retryable=False) from None
        raise ProbeError("inventory_unavailable") from None
    finally:
        try:
            client.logout()
        except Exception:
            pass


def probe(host: str, username: str, password: str, *, port: int = 443,
          timeout: float = 8, allowed_networks=(), require_networks=False,
          on_step=None) -> dict:
    connect_ip, sni_name = validate_probe_target(
        host, allowed_networks=allowed_networks, require_networks=require_networks)
    if port not in ALLOWED_PROBE_PORTS:
        raise ProbeError("invalid_probe_port")
    if not 0 < timeout <= 30:
        raise ProbeError("invalid_probe_timeout")
    if on_step:
        on_step("target")
    fingerprint = read_certificate_sha256(connect_ip, sni_name, port, timeout)
    if on_step:
        on_step("certificate")
    inventory, auth_mode = read_inventory(
        connect_ip, sni_name, port, timeout, fingerprint, username, password)
    if on_step:
        on_step("inventory")
    return {"fingerprint": fingerprint, "inventory": inventory,
            "redfish_auth": auth_mode}
