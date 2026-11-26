"""Read-only IPMI identity probe for BMCs without Redfish."""
from __future__ import annotations

from ..common import parse_controlled_networks  # noqa: F401 - kept in sync with bmc_probe
from . import bmc_probe

DEFAULT_IPMI_PORT = 623

try:
    import pyipmi
    import pyipmi.interfaces
except ImportError:  # pragma: no cover - deployment decides whether it is present
    pyipmi = None  # type: ignore[assignment]


class IpmiProbeError(bmc_probe.ProbeError):
    pass


def _board_identity(ipmi) -> tuple[str, str, str]:
    device = ipmi.get_device_id()
    manufacturer = getattr(device, "manufacturer_name", "") or ""
    version = str(getattr(device, "fw_revision", "") or "").strip()
    model = ""
    for fru_id in (1, 0, 2):
        try:
            board = ipmi.get_fru_board_area(fru_id=fru_id)
        except Exception:  # noqa: BLE001 - an absent FRU must not lose Device ID
            continue
        name = str(getattr(board, "product_name", "") or "").strip()
        maker = str(getattr(board, "manufacturer", "") or "").strip()
        if name:
            model = name
            if not manufacturer:
                manufacturer = maker
            break
    if not model:
        model = f"ipmi-product-{getattr(device, 'product_id', 0)}"
    return manufacturer, model, version


def probe_identity(host: str, username: str, password: str, *, port: int = DEFAULT_IPMI_PORT,
                   allowed_networks=(), require_networks=False) -> dict:
    if pyipmi is None:
        raise IpmiProbeError("ipmi_unavailable", retryable=False)
    if port != DEFAULT_IPMI_PORT:
        raise IpmiProbeError("invalid_ipmi_port", retryable=False)
    bmc_probe.validate_probe_target(
        host, allowed_networks=allowed_networks, require_networks=require_networks)
    try:
        interface = pyipmi.interfaces.create_interface("rmcpplus", max_retries=0)
        ipmi = pyipmi.create_connection(interface)
        ipmi.session.set_session_type_rmcp(host, port=port)
        ipmi.session.set_auth_type_user(username, password)
        ipmi.target = pyipmi.Target(ipmb_address=0x20)
        with ipmi:
            maker, model, firmware = _board_identity(ipmi)
    except Exception as exc:  # noqa: BLE001 - pyipmi raises several error types
        text = str(exc).lower()
        if "auth" in text or "password" in text or "privilege" in text:
            raise IpmiProbeError("ipmi_auth_failed", retryable=False) from None
        raise IpmiProbeError("ipmi_unavailable", retryable=True) from None
    return {
        "fingerprint": "",
        "inventory": {"resources": {"Managers": [{
            "Manufacturer": maker, "Model": model,
            "FirmwareVersion": firmware}]}},
        "redfish_auth": "ipmi_rmcpplus",
    }
