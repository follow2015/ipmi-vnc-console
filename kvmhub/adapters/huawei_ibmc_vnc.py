"""Huawei iBMC built-in VNC adapter: standard RFB 3.8 over TLS."""
from __future__ import annotations

import os
from urllib.parse import urlsplit

from ..driver_specs import DRIVERS
from ..common import (HUAWEI_IBMC_VNC_ADAPTER_ID, Problem,
                      bmc_allowed_networks_from_env, require_controlled_host)
from ..huawei_kvm_upstream import normalise_pin, resolve_huawei_pin
from ..rfb_tcp_upstream import RfbTcpConfig, RfbTcpUpstream
from ..passthrough import RfbPassthroughSession
from ..client_assets import ASSET_DIR, ASSET_PATH, KNOWN_ASSETS
from .rfb_tcp_family import RfbTcpFamilyAdapter

HUAWEI_VNC_PORT = 5900
PIN_ENV = "KVMHUB_HUAWEI_VNC_PIN"


def huawei_vnc_pin_from_env() -> str:
    return os.environ.get(PIN_ENV, "").strip().lower().replace(":", "")



class HuaweiIbmcVncAdapter(RfbTcpFamilyAdapter):
    adapter_id = HUAWEI_IBMC_VNC_ADAPTER_ID
    connection_limit = DRIVERS[adapter_id].connection_limit
    supports_upstream_recovery = DRIVERS[adapter_id].supports_upstream_recovery
    login_budget = DRIVERS[adapter_id].login_budget

    def __init__(self, info: dict, *, networks=None, pin: str | None = None) -> None:
        target = urlsplit(info["target"])
        host = target.hostname
        if (target.scheme not in ("https", "http") or not host
                or target.username or target.password or target.query or target.fragment
                or target.path not in ("", "/") or info["adapter"] != self.adapter_id):
            raise Problem("invalid_target_policy", 502)
        require_controlled_host(
            host,
            bmc_allowed_networks_from_env() if networks is None else networks,
            adapter_id=self.adapter_id,
        )
        if pin is None:
            asset_pin = normalise_pin(info.get("fingerprint"))
            if asset_pin and (len(asset_pin) != 64
                              or any(c not in "0123456789abcdef" for c in asset_pin)):
                raise Problem("bmc_cert_pin_invalid", 400)
            expected_pin = resolve_huawei_pin(info, huawei_vnc_pin_from_env())
        else:
            expected_pin = normalise_pin(pin)
        if len(expected_pin) != 64 or any(c not in "0123456789abcdef" for c in expected_pin):
            raise Problem("bmc_cert_pin_unconfigured", 503)
        self.target = info["target"]
        self.host = host
        self.port = HUAWEI_VNC_PORT
        self.pin = expected_pin
        self.upstream: RfbTcpUpstream | None = None
        self.session: RfbPassthroughSession | None = None

    async def login(self, username: str, password: str) -> None:
        if not isinstance(password, str) or not password:
            raise Problem("credential_unavailable", 503)
        upstream = RfbTcpUpstream(RfbTcpConfig(
            host=self.host, port=self.port, password=password,
            tls_enabled=True, tls_cert_sha256=self.pin))
        self.upstream = upstream
        await upstream.connect()
