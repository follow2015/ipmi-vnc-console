#!/usr/bin/env python3
"""One-shot, out-of-band onboarding of one real BMC."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
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


def build_evidence(probe: dict, *, actor: str) -> dict:
    return {
        "scope": "one-shot onboard probe (read-only Redfish + bounded RFB handshake)",
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


def _measure_greeting(args, fingerprint: str, *, make_upstream=None) -> tuple[str, str]:
    import asyncio
    from kvmhub.rfb_upstream import RfbUpstream, UpstreamConfig

    factory = make_upstream or (lambda cfg: RfbUpstream(cfg))
    cfg = UpstreamConfig(host=args.host, port=args.port, scheme="https",
                         cert_sha256=fingerprint,
                         handshake_timeout=args.timeout, request_timeout=args.timeout)
    async def _probe() -> str:
        up = factory(cfg)
        try:
            await up.login(os.environ["BMC_USER"], os.environ["BMC_PASSWORD"])
            await up.open()
            return getattr(up, "protocol_version", "") or ""
        finally:
            try:
                await up.close()
            except Exception:
                pass

    try:
        return asyncio.run(_probe()), ""
    except Exception as exc:
        reason = getattr(exc, "code", None) or type(exc).__name__
        return "", str(reason)


def _run_probes(args) -> dict:
    import hashlib
    import socket
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((args.host, args.port), timeout=args.timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=args.host) as tls:
            fingerprint = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()

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
    p.add_argument("--dry-run", action="store_true",
                   help="print the plan and generated JSON without touching any database")
    args = p.parse_args(argv)

    if not os.environ.get("BMC_USER") or not os.environ.get("BMC_PASSWORD"):
        p.error("BMC_USER and BMC_PASSWORD must be set (credentials are never CLI arguments)")
    if not args.dry_run and not args.store:
        p.error("--store is required unless --dry-run")
    if not args.dry_run and not args.user:
        p.error("--user is required unless --dry-run (the asset is granted to this user)")

    probe = _run_probes(args)
    spec, measured = build_spec(probe, actor=args.approver)
    evidence = build_evidence(probe, actor=args.approver)

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
    }
    if args.dry_run:
        result["plan"] = ["draft(brand-onboard)", "approve-profile", "approve-capability",
                          "add-credential", "add-asset", "grant", "sync-data-plane"]
        print(json.dumps(result, ensure_ascii=False, indent=1))
        return 0

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
    result["approved"] = {"profile": profile.id, "capability": cap.id if cap else None,
                          "granted_to": args.user or None}
    print(json.dumps(result, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
