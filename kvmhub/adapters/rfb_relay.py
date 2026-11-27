"""Standard-RFB relay adapter: one implementation for every vendor."""
from __future__ import annotations

import os
from urllib.parse import urlsplit

from ..common import (Problem, RFB_RELAY_ADAPTER_ID, bmc_allowed_networks_from_env,
                      require_controlled_host)
from ..driver_specs import DRIVERS, resolve_adapter
from ..huawei_kvm_upstream import normalise_pin, resolve_huawei_pin, valid_pin
from ..passthrough import RfbPassthroughSession
from ..rfb_tcp_upstream import RfbTcpConfig, RfbTcpUpstream
from .rfb_tcp_family import RfbTcpFamilyAdapter

PIN_ENV = "KVMHUB_HUAWEI_VNC_PIN"


def huawei_vnc_pin_from_env() -> str:
    return os.environ.get(PIN_ENV, "").strip().lower().replace(":", "")


class RfbRelayAdapter(RfbTcpFamilyAdapter):

    adapter_id = RFB_RELAY_ADAPTER_ID
    connection_limit = 1
    supports_upstream_recovery = False
    login_budget = 28.0
    client_encodings: tuple[int, ...] | None = None

    def __init__(self, info: dict, *, networks=None, pin: str | None = None) -> None:
        spec = DRIVERS.get(self.adapter_id)
        if spec is None:
            raise Problem("adapter_not_verified", 403)
        target = urlsplit(str(info.get("target") or ""))
        host = target.hostname
        if (target.scheme not in ("https", "http") or not host
                or target.username or target.password or target.query or target.fragment
                or target.path not in ("", "/")
                or resolve_adapter(info.get("adapter")) != self.adapter_id):
            raise Problem("invalid_target_policy", 502)
        require_controlled_host(
            host,
            bmc_allowed_networks_from_env() if networks is None else networks,
            adapter_id=self.adapter_id,
        )
        params = self._access_params(info, spec)
        self.target = info["target"]
        self.host = host
        self.port = params["port"]
        self.tls = params["tls"]
        self.client_encodings = params["encodings"]
        self.pin = self._resolve_pin(info, pin) if self.tls == "pinned" else ""
        self.upstream: RfbTcpUpstream | None = None
        self.session: RfbPassthroughSession | None = None

    @staticmethod
    def _access_params(info: dict, spec) -> dict:
        params = spec.access_defaults
        supplied = info.get("access_params") or {}
        if not isinstance(supplied, dict):
            raise Problem("access_params_invalid", 502)
        merged = {**params, **supplied}
        port = merged.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise Problem("access_params_missing", 503)
        tls = merged.get("tls") or "none"
        if tls not in ("none", "pinned"):
            raise Problem("access_params_invalid", 502)
        if tls == "none" and merged.get("pin_source"):
            raise Problem("access_params_invalid", 502)
        encodings = merged.get("encodings")
        if encodings is not None:
            encodings = tuple(encodings)
        return {"port": port, "tls": tls,
                "pin_source": str(merged.get("pin_source") or ""),
                "encodings": encodings}

    @staticmethod
    def _resolve_pin(info: dict, override: str | None) -> str:
        if override is not None:
            expected = normalise_pin(override)
        else:
            asset_pin = normalise_pin(info.get("fingerprint"))
            if asset_pin and not valid_pin(asset_pin):
                raise Problem("bmc_cert_pin_invalid", 400)
            expected = resolve_huawei_pin(info, huawei_vnc_pin_from_env())
        if not valid_pin(expected):
            raise Problem("bmc_cert_pin_unconfigured", 503)
        return expected

    async def login(self, username: str, password: str) -> None:
        if not isinstance(password, str) or not password:
            raise Problem("credential_unavailable", 503)
        config = RfbTcpConfig(host=self.host, port=self.port, password=password)
        if self.tls == "pinned":
            config = RfbTcpConfig(host=self.host, port=self.port, password=password,
                                  tls_enabled=True, tls_cert_sha256=self.pin)
        upstream = RfbTcpUpstream(config)
        self.upstream = upstream
        await upstream.connect()
