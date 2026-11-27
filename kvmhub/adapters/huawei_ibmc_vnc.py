"""Huawei iBMC built-in VNC: standard RFB 3.8 over TLS (5900)."""
from __future__ import annotations

from ..common import HUAWEI_IBMC_VNC_ADAPTER_ID, RFB_RELAY_ADAPTER_ID
from ..driver_specs import LEGACY_RELAY_PROFILES
from .rfb_relay import PIN_ENV, RfbRelayAdapter, huawei_vnc_pin_from_env

HUAWEI_VNC_PORT = LEGACY_RELAY_PROFILES[HUAWEI_IBMC_VNC_ADAPTER_ID]["port"]
HUAWEI_ACCESS_PARAMS = dict(LEGACY_RELAY_PROFILES[HUAWEI_IBMC_VNC_ADAPTER_ID])

__all__ = ["HUAWEI_ACCESS_PARAMS", "HUAWEI_VNC_PORT", "PIN_ENV",
           "HuaweiIbmcVncAdapter", "huawei_vnc_pin_from_env"]


class HuaweiIbmcVncAdapter(RfbRelayAdapter):

    adapter_id = RFB_RELAY_ADAPTER_ID

    def __init__(self, info: dict, **kwargs) -> None:
        super().__init__({**info, "access_params": {
            **HUAWEI_ACCESS_PARAMS, **(info.get("access_params") or {})}}, **kwargs)
