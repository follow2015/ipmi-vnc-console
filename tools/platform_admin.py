"""Out-of-band administration for the production control plane."""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402
from kvmhub.platform.config import settings  # noqa: E402
from kvmhub.platform.db import (bootstrap_admin, init_schema, make_engine,  # noqa: E402
                                seed_roles, session_factory, transaction)
from kvmhub.platform.models import (AccessGrant, Asset as PlatformAsset,  # noqa: E402
                                    Capability, Credential, User, VendorProfile)
from kvmhub.platform.security import CredentialCipher  # noqa: E402
from kvmhub.platform import connection, services, vendor_registry  # noqa: E402
from kvmhub.platform.bus import AssemblyBus  # noqa: E402
from kvmhub.platform.redis_state import create_state  # noqa: E402
from kvmhub.store import Store  # noqa: E402


def _context(args):
    cfg = settings(args.env_file)
    engine = make_engine(cfg.db_url)
    return cfg, engine, session_factory(engine), CredentialCipher(cfg.credential_key)


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} must be set (secrets are never CLI arguments)")
    return value


def cmd_init_db(args):
    cfg, engine, factory, _ = _context(args)
    init_schema(engine)
    with transaction(factory) as db:
        roles = seed_roles(db)
        created = None
        if cfg.bootstrap_admin and cfg.bootstrap_password:
            created = bootstrap_admin(db, cfg.bootstrap_admin, cfg.bootstrap_password)
        profiles = vendor_registry.seed_builtin_profiles(db)
    print(json.dumps({"db": cfg.db_url.split("?")[0], "roles": roles,
                      "admin_created": created.username if created else None,
                      "profiles_seeded": profiles,
                      "profiles_status": "draft (approval required)"}, ensure_ascii=False))
    engine.dispose()


def cmd_create_user(args):
    _, _, factory, _ = _context(args)
    password = _required_env("KVMHUB_NEW_PASSWORD")
    with transaction(factory) as db:
        user = services.create_user(db, args.username, password, args.role,
                                    actor=args.actor, display_name=args.display_name or "")
        print(json.dumps(user.public(), ensure_ascii=False))


def cmd_add_credential(args):
    _, _, factory, cipher = _context(args)
    with transaction(factory) as db:
        cred = services.save_credential(db, cipher, label=args.label,
                                        username=_required_env("BMC_USER"),
                                        password=_required_env("BMC_PASSWORD"),
                                        actor=args.actor)
        print(json.dumps(cred.public(), ensure_ascii=False))


def cmd_add_asset(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        asset = services.upsert_asset(
            db, name=args.name, address=args.address, vendor=args.vendor or "",
            model=args.model or "", firmware=args.firmware or "",
            fingerprint=args.fingerprint or "", credential_id=args.credential_id,
            profile_id=args.profile_id, capability_id=args.capability_id,
            licence=args.licence or "", actor=args.actor)
        print(json.dumps(asset.public(), ensure_ascii=False))


def cmd_grant(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        services.grant_asset(db, user_id=args.user, asset_id=args.asset,
                             actor=args.actor, ttl_seconds=args.ttl)
    print(json.dumps({"ok": True, "user_id": args.user, "asset_id": args.asset}))


def cmd_profiles(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        rows = [r.public() for r in db.scalars(select(VendorProfile).order_by(VendorProfile.priority)).all()]
    print(json.dumps(rows, ensure_ascii=False, indent=1))


def cmd_approve_profile(args):
    if not args.evidence or not Path(args.evidence).exists():
        raise SystemExit("--evidence must point at an existing measured evidence file")
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        profile = db.get(VendorProfile, args.id)
        if profile is None:
            raise SystemExit("profile not found")
        if profile.status == "approved":
            raise SystemExit("profile is already approved")
        stamp = time.time()
        profile.status = "approved"
        profile.approver = args.approver
        profile.evidence = str(args.evidence)
        profile.approved_at = stamp
        profile.review_due = stamp + args.review_days * 86400
        profile.revision = int(profile.revision or 0) + 1
        services.audit(db, args.approver, "vendor_profile_approved",
                       detail={"profile_id": profile.id, "code": profile.code,
                               "evidence": str(args.evidence), "review_due": profile.review_due}, now=stamp)
        print(json.dumps({"ok": True, "code": profile.code, "approver": args.approver,
                          "review_due": profile.review_due}, ensure_ascii=False))


def cmd_capabilities(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        rows = [{"id": r.id, "vendor": r.vendor, "model": r.model,
                 "firmware": r.firmware, "status": r.status,
                 "profile_id": r.profile_id, "evidence": r.evidence}
                for r in db.scalars(select(Capability)).all()]
    print(json.dumps(rows, ensure_ascii=False, indent=1))


def cmd_approve_capability(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        row = db.get(Capability, args.id)
        if row is None:
            raise SystemExit("capability not found")
        stamp = time.time()
        row.status = "verified"
        row.approver = args.approver
        row.evidence = args.evidence
        row.approved_at = stamp
        row.effective_from = stamp
        row.review_due = stamp + args.review_days * 86400
        row.expires = stamp + args.valid_days * 86400
        row.revision = int(row.revision or 0) + 1
        services.audit(db, args.approver, "capability_approved",
                       detail={"capability_id": row.id, "evidence": args.evidence}, now=stamp)
        print(json.dumps({"ok": True, "id": row.id, "status": row.status}))


def cmd_detect(args):
    payload = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
    inventory = payload.get("inventory", payload)
    detection = vendor_registry.detect_from_redfish(inventory)
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        match = vendor_registry.identify(db, detection)
        result = match.as_dict()
        result["detection"] = detection
        if match.usable:
            result["connection_plan"] = vendor_registry.connection_plan(match.profile)
        if args.make_draft and match.profile is not None:
            row = services.capability_draft(db, match.profile, detection=detection, actor=args.actor)
            result["capability_draft_id"] = row.id
    print(json.dumps(result, ensure_ascii=False, indent=1))


def cmd_worker_drain(args):
    cfg = settings(args.env_file)
    if not cfg.redis_url:
        raise SystemExit("worker drain requires shared Redis state")

    async def change():
        state = create_state(cfg.redis_url)
        try:
            await AssemblyBus(state).set_draining(args.worker_id, not args.resume, actor=args.actor)
        finally:
            await state.close()
    asyncio.run(change())
    engine = make_engine(cfg.db_url)
    try:
        with transaction(session_factory(engine)) as db:
            services.audit(db, args.actor, 'worker_drain_changed',
                           detail={'worker_id': args.worker_id, 'draining': not args.resume})
    finally:
        engine.dispose()
    print(json.dumps({"worker_id": args.worker_id, "draining": not args.resume}))


def cmd_users(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        print(json.dumps(services.list_users(db), ensure_ascii=False, indent=1))


def cmd_audit(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        print(json.dumps(services.recent_audit(db, args.limit), ensure_ascii=False, indent=1))


def cmd_sync_data_plane(args):
    if not args.evidence or not Path(args.evidence).exists():
        raise SystemExit("--evidence must point at an existing measured evidence file")
    _, engine, factory, cipher = _context(args)
    data_key = base64.b64decode(_required_env("KVMHUB_DATA_PLANE_KEY"), validate=True)
    if len(data_key) != 32:
        raise SystemExit("KVMHUB_DATA_PLANE_KEY must decode to 32 bytes")
    stamp = time.time()
    plan, skipped, targets = [], [], []
    with transaction(factory) as db:
        query = select(PlatformAsset)
        if args.asset:
            query = query.where(PlatformAsset.id == args.asset)
        for asset in db.scalars(query).all():
            profile = db.get(VendorProfile, asset.profile_id) if asset.profile_id else None
            cap = db.get(Capability, asset.capability_id) if asset.capability_id else None
            if (profile is None or cap is None or not asset.credential_id
                    or profile.status != "approved" or cap.status != "verified"
                    or float(cap.expires or 0) <= stamp
                    or profile.review_due and profile.review_due < stamp):
                skipped.append({"asset": asset.id, "reason": "approval_gate_open"})
                continue
            try:
                entry = connection.capability_entry(
                    profile, asset=asset,
                    detection={"model": asset.model, "firmware": asset.firmware,
                               "raw": {"Manufacturer": asset.vendor}})
            except connection.ConnectionRefused as exc:
                skipped.append({"asset": asset.id, "reason": exc.code})
                continue
            grants = [row[0] for row in db.execute(
                select(AccessGrant.user_id).where(
                    AccessGrant.asset_id == asset.id, AccessGrant.expires > stamp)).all()]
            if not grants and not args.user:
                skipped.append({"asset": asset.id, "reason": "no_active_grant"})
                continue
            users = [args.user] if args.user else grants
            target = asset.address if "://" in asset.address else f"https://{asset.address}"
            targets.append(target)
            plan.append({"asset_id": asset.id, "name": asset.name,
                         "vendor": asset.vendor, "model": asset.model,
                         "firmware": asset.firmware, "fingerprint": asset.fingerprint,
                         "target": target, "entry": entry, "users": users,
                         "secret": services.read_credential(db, cipher, asset.credential_id),
                         "licence": profile.licence,
                         "console_impl": profile.console_impl or "passthrough"})
            services.audit(db, args.actor, "data_plane_sync_planned", asset_id=asset.id,
                           detail={"capability_entry": entry["id"], "users": users}, now=stamp)
    summary = {"dry_run": bool(args.dry_run), "store": str(args.store),
               "synced": [{"asset": p["asset_id"], "capability": p["entry"]["id"],
                           "users": len(p["users"]), "target": p["target"]} for p in plan],
               "skipped": skipped}
    if args.dry_run:
        print(json.dumps(summary, ensure_ascii=False, indent=1))
        engine.dispose()
        return
    store = Store(str(args.store), data_key, passthrough_targets=tuple(targets))
    try:
        for item in plan:
            cid = item["entry"]["id"]
            if store.db.execute("SELECT 1 FROM adapter_capability WHERE id=?", (cid,)).fetchone() is None:
                store.register_capability(item["entry"], args.actor)
            row = store.capability(cid)
            if row["status"] != "verified":
                store.approve_capability(
                    cid, actor=args.actor, approver=args.approver,
                    evidence=str(args.evidence), licence=item["licence"],
                    console_impl=item["console_impl"],
                    expires=stamp + args.valid_days * 86400,
                    review_due=stamp + args.review_days * 86400)
            for user_id in item["users"]:
                store.register_asset(
                    asset_id=item["asset_id"], name=item["name"], vendor=item["vendor"],
                    model=item["model"], firmware=item["firmware"],
                    capability_id=cid, target=item["target"],
                    fingerprint=item["fingerprint"],
                    username=item["secret"]["username"],
                    password=item["secret"]["password"], user_id=user_id,
                    grant_ttl=args.grant_days * 86400, actor=args.actor)
    finally:
        store.close()
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    engine.dispose()


def cmd_register_worker(args):
    cfg, engine, _, _ = _context(args)
    state = create_state(cfg.redis_url)
    bus = AssemblyBus(state)

    async def run():
        try:
            return await bus.register_worker(args.worker_id, instance_id=args.instance_id,
                                             capacity=args.capacity, ttl=args.ttl)
        finally:
            await state.close()

    row = asyncio.run(run())
    print(json.dumps({"ok": True, **row, "backend": "redis" if cfg.redis_url else "memory"},
                     ensure_ascii=False))
    engine.dispose()


def parser():
    p = argparse.ArgumentParser(description="KVM Hub 控制面带外管理")
    p.add_argument("--env-file", help="path to .env; defaults to CWD/.env")
    p.add_argument("--actor", default="cli")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="create schema, RBAC, first admin, measured profiles").set_defaults(fn=cmd_init_db)
    q = sub.add_parser("create-user"); q.add_argument("--username", required=True); q.add_argument("--role", default="viewer"); q.add_argument("--display-name"); q.set_defaults(fn=cmd_create_user)
    q = sub.add_parser("add-credential"); q.add_argument("--label", required=True); q.set_defaults(fn=cmd_add_credential)
    q = sub.add_parser("add-asset")
    for name in ("name", "address"):
        q.add_argument("--" + name, required=True)
    for name in ("vendor", "model", "firmware", "fingerprint", "credential-id", "profile-id", "capability-id", "licence"):
        q.add_argument("--" + name)
    q.set_defaults(fn=cmd_add_asset)
    q = sub.add_parser("grant"); q.add_argument("--user", required=True); q.add_argument("--asset", required=True); q.add_argument("--ttl", type=int, default=86400 * 30); q.set_defaults(fn=cmd_grant)
    sub.add_parser("profiles").set_defaults(fn=cmd_profiles)
    q = sub.add_parser("approve-profile"); q.add_argument("--id", required=True); q.add_argument("--approver", required=True); q.add_argument("--evidence", required=True); q.add_argument("--review-days", type=int, default=180); q.set_defaults(fn=cmd_approve_profile)
    sub.add_parser("capabilities").set_defaults(fn=cmd_capabilities)
    q = sub.add_parser("approve-capability"); q.add_argument("--id", required=True); q.add_argument("--approver", required=True); q.add_argument("--evidence", required=True); q.add_argument("--review-days", type=int, default=180); q.add_argument("--valid-days", type=int, default=365); q.set_defaults(fn=cmd_approve_capability)
    q = sub.add_parser("detect"); q.add_argument("--inventory", required=True); q.add_argument("--make-draft", action="store_true"); q.set_defaults(fn=cmd_detect)
    sub.add_parser("users").set_defaults(fn=cmd_users)
    q = sub.add_parser("audit"); q.add_argument("--limit", type=int, default=50); q.set_defaults(fn=cmd_audit)
    q = sub.add_parser("sync-data-plane", help="import approved assets into the Worker's SQLite store")
    q.add_argument("--store", required=True, help="path to the PoC data-plane SQLite file")
    q.add_argument("--asset", help="sync only this control-plane asset id")
    q.add_argument("--user", help="sync only this control-plane user id (default: every active grant)")
    q.add_argument("--evidence", required=True)
    q.add_argument("--approver", default="cli")
    q.add_argument("--valid-days", type=int, default=365)
    q.add_argument("--review-days", type=int, default=180)
    q.add_argument("--grant-days", type=int, default=30)
    q.add_argument("--dry-run", action="store_true")
    q.set_defaults(fn=cmd_sync_data_plane)
    q = sub.add_parser("register-worker", help="register/refresh a Worker in the shared roster")
    q.add_argument("--worker-id", required=True)
    q.add_argument("--instance-id", required=True)
    q.add_argument("--capacity", type=int, default=4)
    q.add_argument("--ttl", type=int, default=45)
    q.set_defaults(fn=cmd_register_worker)
    q = sub.add_parser("worker-drain", help="stop new scheduling while preserving existing worker sessions")
    q.add_argument("--worker-id", required=True)
    q.add_argument("--resume", action="store_true")
    q.set_defaults(fn=cmd_worker_drain)
    return p


if __name__ == "__main__":
    args = parser().parse_args()
    args.fn(args)
