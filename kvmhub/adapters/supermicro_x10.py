"""Discovery and measured-transport facts for the inspected Supermicro X10."""
from __future__ import annotations

from typing import Any, Mapping

from ..adapter_contract import (
    AdapterContract,
    AdapterDiscoveryError,
    ConsoleSpec,
    DiscoveryResult,
    register,
)
from ..ast2100_protocol import (
    AUTH_CHALLENGE_BYTES,
    AUTH_RESPONSE_BYTES,
    ENCODING_AST2100,
    MAX_RECT_DATA_BYTES,
    RECT_HEADER_BYTES,
    RFB_VERSION,
    SECURITY_TYPE_INSYDE,
)

CAPABILITY_KEY = {
    "vendor": "Supermicro (Inspur OEM)",
    "model_family": "X10DRT-PS / SA5248M4",
    "firmware": "8.78",
    "console_implementation": "iKVM/HTML5 noVNC fork, RFB 055.008 scheme 16, AST2100 encoding 87",
}

EVIDENCE = (
    "Redfish Managers/1 GraphicalConsole ServiceEnabled=true, ConnectTypesSupported=[KVMIP]",
    "Redfish Managers/1/NetworkProtocol KVMIP ProtocolEnabled=true, Port=5900",
    "Redfish Managers/1 Oem namespace Supermicro, FirmwareVersion 8.78, MouseMode Absolute",
    "Web UI Remote Control menu: Console Redirection (Java), iKVM/HTML5, Launch SOL",
    "HTML5 bootstrap page returns 200 and loads a vendored noVNC fork with ast2100.js",
    "nav_ui.js UI.connect uses port=443, encrypt=true; rfb.js builds wss://host:443/<path>",
    "bootstrap page injects a hidden #entry_value ticket consumed as VNC username/password",
    "TCP connect-only probe: 80/443/5900/623/22 open; 5901/2068/5120/7578/3072 closed",
    "WebSocket wss://192.0.2.11/ returned 101 with a Web session Cookie and no subprotocol",
    f"{RFB_VERSION.strip()}: security type {SECURITY_TYPE_INSYDE}, {AUTH_CHALLENGE_BYTES}-byte challenge, "
    f"{AUTH_RESPONSE_BYTES}-byte response, SecurityResult=0",
    f"FramebufferUpdate uses a {RECT_HEADER_BYTES}-byte vendor rect header; every observed rect is "
    f"AST2100 encoding {ENCODING_AST2100}, mode 0, 1024x768",
    "AST2100 payloads measured at 15940/15956 bytes (full) and 16/24 bytes (incremental); none start with JPEG SOI",
    "Canvas rendered 1024x768 at 27-31 FPS with non-black pixels; PointerEvent and KeyEvent messages were sent",
    "UI.rfb.disconnect() plus do_loggout() removed the ticket; BMC User List showed one session row",
    "POST /cgi/login.cgi with name/pwd returns 200; the SID is emitted twice, once empty/expired and once real",
    "A cookie jar sends both SIDs and the CGI answers the 441-byte SessionTimeout page; one absorbed SID works",
    "WebSocket upgrade needs Origin https://<bmc>; without it the BMC answers 400 Invalid response status",
    "#entry_value is 24 chars, reused as the RFB username; scheme 16 sends those 24 chars zero-padded to 48 bytes, no DES",
    "ServerInit is followed by a 12-byte Insyde extension: 4 reserved, SessionID, Video/KbMs/KickUser/VM flags",
    "Server message 57 is a 265-byte control record (4+4+256); the vendor also defines 2 Bell, 4 cursor, 22, 55 mouse mode",
    "Gateway transport completed handshake and six AST2100 updates (encoding 87, mode 0, 480x640), sent pointer and Shift, logged out",
)

UNCONFIRMED = (
    "AST2100 bitstream decoding is not implemented; only the frame structure is known",
    "gateway-driven frame requests kept the 480x640 init size; the 1024x768 renegotiation seen in the browser was not reproduced",
    "field-level keysym mapping and the host effect of batched input messages are unverified",
    "upstream ticket expiry, revocation and concurrency limits are unknown",
    "KVM licensing and least-privilege account scope are unknown",
    "certificate fingerprint was collected over the network, not independently verified",
    "adapter_capability approval is per capability row: exchange accepts mock-v1 by default and the "
    "passthrough adapter only for targets listed in passthrough_targets (empty by default)",
    "the Worker relays browser and BMC frames in a passthrough session but does not decode the "
    "AST2100 bitstream itself; input field layout is checked by length only",
    "the adapter contract's data plane (authenticate/open_console/keepalive/logout) still raises "
    "AdapterUnavailable; a real console is reached only through the passthrough relay",
)


@register
class SupermicroX10IKVMAdapter(AdapterContract):
    adapter_id = "smci-x10-ikvm-html5-discover"
    capability_status = "unverified"

    def discover(self, evidence: Mapping[str, Any]) -> DiscoveryResult:
        manager = evidence.get("manager")
        network = evidence.get("network_protocol")
        if not isinstance(manager, dict) or not isinstance(network, dict):
            raise AdapterDiscoveryError("manager and network_protocol evidence required")

        graphical = manager.get("GraphicalConsole")
        if not isinstance(graphical, dict) or graphical.get("ServiceEnabled") is not True:
            raise AdapterDiscoveryError("GraphicalConsole service not confirmed enabled")
        types = graphical.get("ConnectTypesSupported")
        if not isinstance(types, list) or "KVMIP" not in types:
            raise AdapterDiscoveryError("KVMIP console type not offered")

        kvmip = network.get("KVMIP")
        if not isinstance(kvmip, dict) or kvmip.get("ProtocolEnabled") is not True:
            raise AdapterDiscoveryError("KVMIP protocol not confirmed enabled")
        port = kvmip.get("Port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise AdapterDiscoveryError("invalid KVMIP port")

        oem = manager.get("Oem")
        if not isinstance(oem, dict) or "Supermicro" not in oem:
            raise AdapterDiscoveryError("Supermicro OEM namespace not present")
        firmware = manager.get("FirmwareVersion")
        if not isinstance(firmware, str) or not firmware:
            raise AdapterDiscoveryError("BMC firmware version missing")

        web = evidence.get("web_ui")
        candidates = ["ikvm-html5-novnc-ast2100"]
        if isinstance(web, dict) and web.get("java_route"):
            candidates.append("java-jviewer-jnlp")
        chassis = evidence.get("chassis")
        model = chassis.get("Model") if isinstance(chassis, dict) else manager.get("Model")
        if not isinstance(model, str) or not model:
            model = "X10DRT-PS"

        return DiscoveryResult(
            vendor=CAPABILITY_KEY["vendor"],
            model=model,
            firmware=firmware,
            console_implementation=CAPABILITY_KEY["console_implementation"],
            candidate_consoles=tuple(candidates),
            kvm_service_port=port,
            upstream_tls="TLS pinned to a network-collected SHA-256 fingerprint; identity not independently verified",
            evidence=EVIDENCE,
            unconfirmed=UNCONFIRMED,
        )

    def console_spec(self) -> ConsoleSpec:
        return ConsoleSpec(
            entry_path="/cgi/url_redirect.cgi?url_name=man_ikvm_html5_bootstrap",
            allowed_methods=frozenset({"GET", "HEAD", "POST"}),
            allowed_exact_paths=(
                "/cgi/login.cgi",
                "/cgi/url_redirect.cgi?url_name=mainmenu",
                "/cgi/url_redirect.cgi?url_name=topmenu",
                "/cgi/url_redirect.cgi?url_name=man_ikvm_html5",
                "/cgi/url_redirect.cgi?url_name=man_ikvm_html5_bootstrap",
            ),
            allowed_path_prefixes=("/novnc/", "/js/", "/css/", "/images/"),
            login_path="/cgi/login.cgi",
            websocket_path="/",
            websocket_scheme="wss",
            websocket_port=443,
            websocket_binary=True,
            upstream_auth=("24-char #entry_value ticket absorbed by Gateway; scheme 16 sends it as the "
                           "48-byte username response and the absorbed SID cookie plus a fixed Origin "
                           "header carry the WebSocket; neither value reaches the browser"),
            max_frame_bytes=MAX_RECT_DATA_BYTES,
            codec="AST2100 encoding 87 over RFB 055.008 with a 20-byte vendor rect header and mode 0; proprietary bitstream, no decoder",
            close_rule=("WebSocket close 1000 then POST /cgi/logout.cgi; both measured gateway sessions "
                        "reported cleanup=ok and the console page stopped injecting a ticket"),
        )
