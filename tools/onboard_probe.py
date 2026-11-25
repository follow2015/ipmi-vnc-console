#!/usr/bin/env python3
"""One-shot, out-of-band onboarding of one real BMC."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import asyncio
import contextlib
import io
import json
import os
import re
import time
from types import SimpleNamespace

from kvmhub.platform import brand_onboarding, vendor_registry

_PROFILE_BY_GREETING = {
    "RFB 055.008": "smci-x10-ast2100-rfb055008",
    "RFB 003.008": "smci-x10-ast2100-rfb003008",
}
_TEMPLATE_BY_GREETING = {
    greeting: next(p for p in vendor_registry.BUILTIN_PROFILES
                   if p["code"] == code)
    for greeting, code in _PROFILE_BY_GREETING.items()
}
_MESSAGE_BY_GREETING = {"RFB 055.008": "smc", "RFB 003.008": "insyde"}
_GENERIC_ASSET_PATHS = ["/novnc/include/*.js", "/js/*.js", "/css/*.css",
                        "/images/**/*.png", "/images/**/*.gif", "/images/**/*.jpg",
                        "/images/**/*.svg", "/favicon.ico"]
_SPEC_WIRE_FIELDS = frozenset({
    "code", "vendor", "vendor_aliases", "model_pattern", "firmware_min",
    "firmware_max", "rfb_version", "message_profile", "asset_paths",
    "login_path", "logout_path", "console_impl", "licence",
    "concurrency_limit", "priority", "input_shaping",
})

_SYSTEM_PATH_RE = re.compile(r"^/redfish/v1/Systems/[A-Za-z0-9_.:-]+$")
_RESET_TYPES = frozenset({"On", "ForceOff"})
_IPMI_ACTIONS = {"On": "on", "ForceOff": "off"}
_POWER_TRANSPORTS = frozenset({"redfish", "ipmi", "auto"})


class PowerControlError(RuntimeError):

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _detection(probe: dict) -> dict:
    return vendor_registry.detect_from_redfish(probe["inventory"])


def _code_slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return (slug or "generic")[:24]


def build_spec(probe: dict, *, actor: str) -> tuple[dict, bool]:
    detection = _detection(probe)
    greeting = str(probe.get("greeting") or "").strip()
    vendor = detection.get("vendor") or ""
    model = detection.get("model") or ""
    firmware = detection.get("firmware") or ""
    message = _MESSAGE_BY_GREETING.get(greeting, "standard")
    template = _TEMPLATE_BY_GREETING.get(greeting)
    measured = template is not None

    spec: dict
    if template is not None:
        spec = {k: v for k, v in template.items() if k in _SPEC_WIRE_FIELDS}
    else:
        spec = {
            "code": f"{_code_slug(vendor)}-{_code_slug(model)}-rfb{greeting[-6:].replace('.', '')}"
            if greeting else f"{_code_slug(vendor)}-{_code_slug(model)}",
            "vendor": vendor,
            "vendor_aliases": [vendor] if vendor else [],
            "model_pattern": re.escape(model) if model else ".*",
            "firmware_min": "",
            "firmware_max": "",
            "rfb_version": greeting,
            "message_profile": message,
            "asset_paths": list(_GENERIC_ASSET_PATHS),
            "login_path": "/cgi/login.cgi",
            "logout_path": "/cgi/logout.cgi",
            "console_impl": "passthrough",
            "licence": "IKVM HTML5",
            "concurrency_limit": 1,
            "priority": 100,
        }
    return spec, measured


def build_evidence(probe: dict, *, actor: str, power: dict | None = None) -> dict:
    evidence = {
        "scope": "one-shot onboard probe (bounded Redfish + RFB handshake; "
                 "temporary power lifecycle when host is Off)",
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "recorded_by": actor,
        "host": probe.get("host", ""),
        "fingerprint": probe.get("fingerprint", ""),
        "fingerprint_note": "measured and pinned on every connection; not independently verified (closed network)",
        "gathered": {
            "greeting": probe.get("greeting", ""),
            "greeting_error": probe.get("greeting_error", ""),
            "redfish_auth": probe.get("redfish_auth", ""),
            "inventory": probe.get("inventory", {}),
        },
    }
    if power is not None:
        evidence["power"] = power
    return evidence


def plan_steps(*, asset_id: str, profile_id: str, capability_id: str,
               credential_id: str, approver: str) -> list[dict]:
    return [
        {"verb": "brand-onboard", "actor": approver},
        {"verb": "approve-profile", "actor": approver, "id": profile_id},
        {"verb": "approve-capability", "actor": approver, "id": capability_id},
        {"verb": "add-credential", "actor": approver},
        {"verb": "add-asset", "actor": approver, "id": asset_id,
         "credential_id": credential_id, "profile_id": profile_id,
         "capability_id": capability_id},
        {"verb": "grant", "actor": approver, "asset": asset_id},
        {"verb": "sync-data-plane", "actor": approver},
    ]


def _ns(args, **overrides):
    data = {"env_file": args.env_file, "actor": args.approver,
            "approver": args.approver}
    data.update(overrides)
    return SimpleNamespace(**data)


def _read_inventory(args, fingerprint: str) -> tuple[dict, str, str]:
    from demos.redfish_probe import Redfish, RedfishError, inventory as redfish_inventory

    basic = (os.environ["BMC_USER"], os.environ["BMC_PASSWORD"])
    client = Redfish(args.host, args.port, None, args.timeout, fingerprint,
                     max_requests=20, basic_auth=basic)
    try:
        root = client.json("/redfish/v1/")
        inv = redfish_inventory(client, root, 12)
        return inv, "basic", ""
    except RedfishError:
        pass

    client = Redfish(args.host, args.port, None, args.timeout, fingerprint, max_requests=20)
    try:
        client.login(basic[0], basic[1])
        root = client.json("/redfish/v1/")
        inv = redfish_inventory(client, root, 12)
        return inv, "session", ""
    except RedfishError as exc:
        return {}, "none", str(exc)
    finally:
        try:
            client.logout()
        except Exception:
            pass


def _probe_greeting_and_video(args, fingerprint: str, *, make_upstream=None,
                              wait_for_frame: bool = False,
                              frame_timeout: float = 5.0) -> dict:
    from kvmhub.rfb_upstream import RfbUpstream, UpstreamConfig

    factory = make_upstream or (lambda cfg: RfbUpstream(cfg))
    cfg = UpstreamConfig(host=args.host, port=args.port, scheme="https",
                         cert_sha256=fingerprint,
                         handshake_timeout=args.timeout, request_timeout=args.timeout)

    async def _probe() -> dict:
        up = factory(cfg)
        video = {"source_present": False, "frames": 0, "payload_bytes": 0}
        try:
            await up.login(os.environ["BMC_USER"], os.environ["BMC_PASSWORD"])
            await up.open()
            greeting = getattr(up, "protocol_version", "") or ""
            if wait_for_frame:
                updates = await up.wait_frames(count=1, timeout=frame_timeout)
                stats = getattr(up, "stats", None)
                frames = int(getattr(stats, "frames", 0) or 0)
                payload = int(getattr(stats, "payload_bytes", 0) or 0)
                video = {"source_present": bool(updates > 0 and payload > 0),
                         "frames": frames, "payload_bytes": payload}
            return {"greeting": greeting, "error": "", "video": video}
        except Exception as exc:
            reason = getattr(exc, "code", None) or type(exc).__name__
            return {"greeting": "", "error": str(reason), "video": video}
        finally:
            try:
                await up.close()
            except Exception:
                pass

    return asyncio.run(_probe())


def _measure_greeting(args, fingerprint: str, *, make_upstream=None) -> tuple[str, str]:
    result = _probe_greeting_and_video(args, fingerprint, make_upstream=make_upstream)
    return result["greeting"], result["error"]


def _validate_power_request(fingerprint: str, system_path: str,
                            reset_type: str | None = None) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint or ""):
        raise PowerControlError("invalid_fingerprint")
    if not _SYSTEM_PATH_RE.fullmatch(system_path or ""):
        raise PowerControlError("invalid_system_path")
    if reset_type is not None and reset_type not in _RESET_TYPES:
        raise PowerControlError("invalid_reset_type")


async def _redfish_request(host: str, port: int, fingerprint: str, timeout: float,
                           method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    import aiohttp

    if method not in ("GET", "POST"):
        raise PowerControlError("method_denied")
    connector = aiohttp.TCPConnector(
        ssl=aiohttp.Fingerprint(bytes.fromhex(fingerprint)))
    auth = aiohttp.BasicAuth(os.environ["BMC_USER"], os.environ["BMC_PASSWORD"])
    url = f"https://{host}:{port}{path}"
    async with aiohttp.ClientSession(
            connector=connector, timeout=aiohttp.ClientTimeout(total=timeout),
            trust_env=False) as session:
        async with session.request(method, url, auth=auth, json=payload,
                                   allow_redirects=False) as response:
            body = await response.read()
            if response.status not in (200, 202, 204):
                raise PowerControlError(f"http_{response.status}")
            return response.status, json.loads(body) if body else {}


def _power_transport(args) -> str:
    transport = getattr(args, "power_transport", "auto") or "auto"
    if transport not in _POWER_TRANSPORTS:
        raise PowerControlError("invalid_power_transport")
    return transport


def _ipmi_command(args):
    from pyghmi.ipmi import command as ipmi_command

    return ipmi_command.Command(
        bmc=args.host, userid=os.environ["BMC_USER"],
        password=os.environ["BMC_PASSWORD"], timeout=args.timeout)


def _read_power_state_redfish(args, fingerprint: str) -> dict:
    try:
        _validate_power_request(fingerprint, args.system_path)
        _, data = asyncio.run(_redfish_request(
            args.host, args.port, fingerprint, args.timeout, "GET", args.system_path, None))
        state = str(data.get("PowerState", "")).strip()
        return {"state": state, "error": "" if state else "power_state_missing",
                "transport": "redfish"}
    except PowerControlError as exc:
        return {"state": "", "error": exc.code, "transport": "redfish"}
    except Exception as exc:
        return {"state": "", "error": getattr(exc, "code", None) or type(exc).__name__,
                "transport": "redfish"}


def _read_power_state_ipmi(args) -> dict:
    try:
        result = _ipmi_command(args).get_power() or {}
        raw = str(result.get("powerstate", "")).strip().lower()
        state = {"on": "On", "off": "Off"}.get(raw, raw)
        return {"state": state, "error": "" if state else "power_state_missing",
                "transport": "ipmi"}
    except Exception as exc:
        return {"state": "", "error": getattr(exc, "code", None) or type(exc).__name__,
                "transport": "ipmi"}


def read_power_state(args, fingerprint: str) -> dict:
    transport = _power_transport(args)
    if transport in ("redfish", "auto"):
        result = _read_power_state_redfish(args, fingerprint)
        if result["state"] or transport == "redfish":
            return result
    return _read_power_state_ipmi(args)


def _send_power_reset_redfish(args, fingerprint: str, reset_type: str) -> dict:
    _validate_power_request(fingerprint, args.system_path, reset_type)
    path = args.system_path.rstrip("/") + "/Actions/ComputerSystem.Reset"
    try:
        status, _ = asyncio.run(_redfish_request(
            args.host, args.port, fingerprint, args.timeout, "POST", path,
            {"ResetType": reset_type}))
        return {"action": reset_type, "status": status, "accepted": True,
                "error": "", "transport": "redfish"}
    except PowerControlError as exc:
        return {"action": reset_type, "status": 0, "accepted": False,
                "error": exc.code, "transport": "redfish"}
    except Exception as exc:
        return {"action": reset_type, "status": 0, "accepted": False,
                "error": getattr(exc, "code", None) or type(exc).__name__,
                "transport": "redfish"}


def _send_power_reset_ipmi(args, reset_type: str) -> dict:
    if reset_type not in _IPMI_ACTIONS:
        raise PowerControlError("invalid_reset_type")
    try:
        _ipmi_command(args).set_power(_IPMI_ACTIONS[reset_type], wait=False)
        return {"action": reset_type, "status": 0, "accepted": True,
                "error": "", "transport": "ipmi"}
    except Exception as exc:
        return {"action": reset_type, "status": 0, "accepted": False,
                "error": getattr(exc, "code", None) or type(exc).__name__,
                "transport": "ipmi"}


def send_power_reset(args, fingerprint: str, reset_type: str) -> dict:
    if reset_type not in _RESET_TYPES:
        raise PowerControlError("invalid_reset_type")
    transport = _power_transport(args)
    if transport in ("redfish", "auto"):
        _validate_power_request(fingerprint, args.system_path, reset_type)
        result = _send_power_reset_redfish(args, fingerprint, reset_type)
        if result["accepted"] or transport == "redfish":
            return result
    return _send_power_reset_ipmi(args, reset_type)


def wait_for_video_source(args, fingerprint: str, *, measure=None,
                          sleep=time.sleep, clock=time.monotonic) -> dict:
    measure = measure or (lambda: _probe_greeting_and_video(
        args, fingerprint, wait_for_frame=True,
        frame_timeout=min(10.0, max(1.0, args.timeout))))
    started = clock()
    attempts = []
    last_error = ""
    while True:
        result = measure()
        last_error = result.get("error", "")
        attempts.append({"greeting": result.get("greeting", ""),
                         "error": last_error,
                         "video": result.get("video", {})})
        if result.get("greeting") and result.get("video", {}).get("source_present"):
            return {"present": True, "seconds": round(clock() - started, 1),
                    "last_error": last_error, "attempts": attempts}
        if clock() - started >= args.power_on_timeout:
            return {"present": False, "seconds": round(clock() - started, 1),
                    "last_error": last_error, "attempts": attempts}
        sleep(args.power_poll_interval)


@contextlib.contextmanager
def temporary_power(args, fingerprint: str, report: dict, *, read=None, reset=None,
                    wait=None):
    read = read or (lambda: read_power_state(args, fingerprint))
    reset = reset or (lambda action: send_power_reset(args, fingerprint, action))
    wait = wait or (lambda: wait_for_video_source(args, fingerprint))
    report.update({"enabled": not args.no_power_control, "state_before": "",
                   "action": "none", "commands": [], "video": {}, "restore": {}})
    should_restore = False
    try:
        if not report["enabled"]:
            report["action"] = "disabled"
            yield report
            return
        state = read()
        report["state_before"] = state.get("state", "")
        if state.get("error"):
            report["read_error"] = state["error"]
        if state.get("state", "").upper() != "OFF":
            yield report
            return
        on = reset("On")
        report["commands"].append(on)
        if not on.get("accepted"):
            report["action"] = "power_on_rejected"
            raise PowerControlError("power_on_rejected")
        should_restore = True
        report["action"] = "temporary_on"
        video = wait()
        report["video"] = {"present": video.get("present", False),
                           "seconds": video.get("seconds", 0),
                           "last_error": video.get("last_error", ""),
                           "attempt_count": len(video.get("attempts", []))}
        if not video.get("present"):
            raise PowerControlError("video_source_timeout")
        yield report
    finally:
        if should_restore:
            try:
                off = reset("ForceOff")
                report["commands"].append(off)
                report["restore"] = {"confirmed": bool(off.get("accepted")),
                                     "error": off.get("error", "")}
            except Exception as exc:
                report["restore"] = {
                    "confirmed": False,
                    "error": getattr(exc, "code", None) or type(exc).__name__,
                }


def _measure_fingerprint(args) -> str:
    import hashlib
    import socket
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((args.host, args.port), timeout=args.timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=args.host) as tls:
            return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


def _run_probes(args, fingerprint: str | None = None) -> dict:
    fingerprint = fingerprint or _measure_fingerprint(args)

    inv, auth_mode, inventory_error = _read_inventory(args, fingerprint)
    if inventory_error:
        raise RuntimeError(f"redfish inventory failed after basic/session negotiation: {inventory_error}")

    greeting, greeting_error = "", ""
    if not args.no_greeting:
        greeting, greeting_error = _measure_greeting(args, fingerprint)

    return {"host": args.host, "inventory": inv, "fingerprint": fingerprint,
            "greeting": greeting, "redfish_auth": auth_mode,
            "greeting_error": greeting_error}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--env-file", help="path to control-plane .env; defaults to CWD/.env")
    p.add_argument("--store", help="data-plane store DSN (required unless --dry-run)")
    p.add_argument("--user", help="platform user id to grant the asset to")
    p.add_argument("--approver", default="auto-onboard")
    p.add_argument("--out-dir", help="directory for generated JSON evidence")
    p.add_argument("--timeout", type=float, default=5)
    p.add_argument("--no-greeting", action="store_true",
                   help="skip the RFB greeting probe (inventory only; spec greeting left blank)")
    p.add_argument("--no-power-control", action="store_true",
                   help="never send power commands (host stays as found)")
    p.add_argument("--power-transport", choices=sorted(_POWER_TRANSPORTS), default="auto",
                   help="power state/control transport: pinned Redfish, IPMI, or auto fallback")
    p.add_argument("--system-path", default="/redfish/v1/Systems/1",
                   help="Redfish System resource used for PowerState and Reset")
    p.add_argument("--power-on-timeout", type=float, default=240.0,
                   help="seconds to wait for a non-empty video frame after power on")
    p.add_argument("--power-poll-interval", type=float, default=8.0,
                   help="seconds between video probes while waiting for the source")
    p.add_argument("--dry-run", action="store_true",
                   help="print the plan and generated JSON without touching any database")
    args = p.parse_args(argv)

    if not os.environ.get("BMC_USER") or not os.environ.get("BMC_PASSWORD"):
        p.error("BMC_USER and BMC_PASSWORD must be set (credentials are never CLI arguments)")
    if not args.dry_run and not args.store:
        p.error("--store is required unless --dry-run")
    if not args.dry_run and not args.user:
        p.error("--user is required unless --dry-run (the asset is granted to this user)")
    if args.timeout <= 0 or args.power_on_timeout <= 0 or args.power_poll_interval <= 0:
        p.error("--timeout, --power-on-timeout and --power-poll-interval must be positive")
    if not _SYSTEM_PATH_RE.fullmatch(args.system_path):
        p.error("--system-path must be /redfish/v1/Systems/<id>")

    fingerprint = _measure_fingerprint(args)
    power: dict = {}
    result: dict = {}
    probe: dict = {}
    try:
        with temporary_power(args, fingerprint, power):
            probe = _run_probes(args, fingerprint=fingerprint)
            spec, measured = build_spec(probe, actor=args.approver)
            evidence = build_evidence(probe, actor=args.approver, power=power)

            out = Path(args.out_dir) if args.out_dir else Path(".local-onboard") / _code_slug(args.host)
            out.mkdir(parents=True, exist_ok=True)
            inv_path = out / "inventory.json"
            spec_path = out / "spec.json"
            evid_path = out / "evidence.json"
            inv_path.write_text(json.dumps(probe["inventory"], ensure_ascii=False, indent=1), encoding="utf-8")
            spec_path.write_text(json.dumps(spec, ensure_ascii=False, indent=1), encoding="utf-8")
            evid_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=1), encoding="utf-8")

            result = {
                "measured_template": measured,
                "greeting": probe["greeting"],
                "greeting_error": probe.get("greeting_error", ""),
                "redfish_auth": probe.get("redfish_auth", ""),
                "fingerprint": probe["fingerprint"],
                "files": {"inventory": str(inv_path), "spec": str(spec_path), "evidence": str(evid_path)},
                "warning": ("" if measured else
                            "unmeasured brand: generic iKVM spec generated; console path not verified"),
                "power": power,
            }
            if args.dry_run:
                result["plan"] = ["draft(brand-onboard)", "approve-profile", "approve-capability",
                                  "add-credential", "add-asset", "grant", "sync-data-plane"]
            else:
                from tools import platform_admin as pa

                common = _ns(args)
                draft = SimpleNamespace(**{**vars(common), "spec": str(spec_path),
                                           "inventory": str(inv_path), "evidence": str(evid_path),
                                           "greeting": probe["greeting"]})
                with contextlib.redirect_stdout(io.StringIO()):
                    pa.cmd_brand_onboard(draft)
                from kvmhub.platform.db import transaction
                from kvmhub.platform.models import Capability, VendorProfile
                from kvmhub.platform.models import PROFILE_APPROVED
                _, _, factory, _ = pa._context(common)
                with transaction(factory) as db:
                    profile = db.query(VendorProfile).filter_by(code=spec["code"]).one()
                    cap = (db.query(Capability).filter_by(profile_id=profile.id)
                           .order_by(Capability.created.desc()).first())
                    profile_renew = profile.status == PROFILE_APPROVED
                    cipher = pa.CredentialCipher(pa.settings(args.env_file).credential_key)
                    cred = pa.services.save_credential(
                        db, cipher, label=f"{args.host}-bmc",
                        username=os.environ["BMC_USER"], password=os.environ["BMC_PASSWORD"],
                        actor=args.approver)
                    detection = _detection(probe)
                    asset = pa.services.upsert_asset(
                        db, name=f"{detection.get('model') or args.host} ({args.host})",
                        address=args.host, vendor=detection.get("vendor") or "",
                        model=detection.get("model") or "", firmware=detection.get("firmware") or "",
                        fingerprint=probe["fingerprint"], credential_id=cred.id,
                        profile_id=profile.id, capability_id=cap.id if cap else None,
                        licence=spec["licence"], actor=args.approver)

                plan = plan_steps(asset_id=asset.id, profile_id=profile.id,
                                  capability_id=cap.id if cap else "", credential_id=cred.id,
                                  approver=args.approver)
                with contextlib.redirect_stdout(io.StringIO()):
                    pa.cmd_approve_profile(_ns(args, id=profile.id, approver=args.approver,
                                               evidence=str(evid_path), review_days=180,
                                               renew=profile_renew))
                    if cap:
                        pa.cmd_approve_capability(_ns(args, id=cap.id, approver=args.approver,
                                                      evidence=str(evid_path),
                                                      review_days=180, valid_days=365))
                    if args.user:
                        pa.cmd_grant(_ns(args, user=args.user, asset=asset.id, ttl=86400 * 30))
                    pa.cmd_sync_data_plane(_ns(args, store=args.store, evidence=str(evid_path),
                                               approver=args.approver, asset=asset.id,
                                               user=args.user, valid_days=365, review_days=180,
                                               grant_days=30, dry_run=False))
                result["plan"] = plan
                result["approved"] = {
                    "profile": profile.id, "capability": cap.id if cap else None,
                    "granted_to": args.user or None,
                }
    except PowerControlError as exc:
        print(json.dumps({"error": exc.code, "power": power}, ensure_ascii=False, indent=1))
        return 2

    if result.get("files", {}).get("evidence"):
        Path(result["files"]["evidence"]).write_text(
            json.dumps(build_evidence(probe, actor=args.approver, power=power),
                       ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
