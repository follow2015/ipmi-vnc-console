"""Dell iDRAC built-in VNC: standard RFB over bare TCP (plaintext, 5901)."""
from __future__ import annotations

from ..common import IDRAC_VNC_ADAPTER_ID, RFB_RELAY_ADAPTER_ID
from ..driver_specs import LEGACY_RELAY_PROFILES
from .rfb_relay import RfbRelayAdapter

IDRAC_VNC_PORT = LEGACY_RELAY_PROFILES[IDRAC_VNC_ADAPTER_ID]["port"]
IDRAC_ACCESS_PARAMS = dict(LEGACY_RELAY_PROFILES[IDRAC_VNC_ADAPTER_ID])


class IdracVncAdapter(RfbRelayAdapter):

    adapter_id = RFB_RELAY_ADAPTER_ID

    def __init__(self, info: dict, **kwargs) -> None:
        super().__init__({**info, "access_params": {
            **IDRAC_ACCESS_PARAMS, **(info.get("access_params") or {})}}, **kwargs)


__all__ = ["IDRAC_ACCESS_PARAMS", "IDRAC_VNC_PORT", "IdracVncAdapter"]
