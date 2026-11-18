#!/usr/bin/env -S .venv/bin/python
"""Out-of-band administration for the production control plane."""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import secrets
import shlex
import string
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402
from kvmhub.platform.config import settings  # noqa: E402
from kvmhub.platform.db import (bootstrap_admin, bootstrap_platform_admin,  # noqa: E402
                                init_schema, make_engine, seed_roles,
                                session_factory, transaction)
from kvmhub.platform.models import (AccessGrant, Asset as PlatformAsset,  # noqa: E402
                                    PROFILE_APPROVED, Capability, Credential, User,
                                    VendorProfile)
from kvmhub.platform.security import CredentialCipher  # noqa: E402
from kvmhub.platform import (brand_onboarding, connection, governance,  # noqa: E402
                             services, vendor_registry)
from kvmhub.platform.bus import AssemblyBus  # noqa: E402
from kvmhub.platform.redis_state import SESSION_PREFIX, create_state  # noqa: E402
from kvmhub.store import TENANT_GRANT, Store  # noqa: E402


def _context(args):
    cfg = settings(args.env_file)
    engine = make_engine(cfg.db_url)
    return cfg, engine, session_factory(engine), CredentialCipher(cfg.credential_key)


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} must be set (secrets are never CLI arguments)")
    return value


def _generated_password(length: int = 20) -> str:
    special = "-_!@#$%^&*"
    alphabet = string.ascii_letters + string.digits + special
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in group for c in password) for group in
               (string.ascii_lowercase, string.ascii_uppercase, string.digits, special)):
            return password


def _load_json(path: str, label: str) -> dict:
    target = Path(path)
    if not target.is_file():
        raise SystemExit(f"{label} must point at an existing JSON file: {path}")
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"{label} is not readable JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"{label} must contain a JSON object")
    return payload


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
        tenant = services.resolve_tenant(db, args.tenant)
        user = services.create_user(db, args.username, password, args.role,
                                    actor=args.actor, display_name=args.display_name or "",
                                    tenant_id=tenant.id)
        print(json.dumps(user.public(), ensure_ascii=False))


def cmd_create_platform_admin(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        seed_roles(db)
        created = bootstrap_platform_admin(db, args.username,
                                           _required_env("KVMHUB_NEW_PASSWORD"))
    if created is None:
        raise SystemExit("a platform account already exists")
    print(json.dumps(created.public(), ensure_ascii=False))


def cmd_reset_password(args):
    generated = bool(getattr(args, "generate", False))
    password = _generated_password() if generated else _required_env("KVMHUB_NEW_PASSWORD")
    cfg, engine, factory, _ = _context(args)
    with transaction(factory) as db:
        stmt = select(User).where(User.username == args.username)
        if args.tenant:
            tenant = services.resolve_tenant(db, args.tenant)
            stmt = stmt.where(User.tenant_id == tenant.id)
        else:
            stmt = stmt.where(User.tenant_id.is_(None))
        user = db.scalar(stmt)
        if user is None:
            raise SystemExit("user not found (check --username and --tenant)")
        target = user.id
        services.set_user_password(db, target, password,
                                   actor=args.actor, tenant_id=None)
        public = user.public()

    async def drop_sessions():
        state = create_state(cfg.redis_url)
        try:
            for key in await state.keys(SESSION_PREFIX):
                session = await state.get(key)
                if session and session.get("user_id") == target:
                    await state.delete(key)
        finally:
            await state.close()

    asyncio.run(drop_sessions())
    engine.dispose()
    result = {"ok": True, "user": public["username"],
              "tenant_id": public.get("tenant_id"),
              "sessions_revoked": True}
    if generated:
        result["new_password"] = password
    print(json.dumps(result, ensure_ascii=False))


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
        user = db.get(User, args.user)
        if user is None:
            raise SystemExit(f"user not found: {args.user}")
        services.grant_asset(db, user_id=args.user, asset_id=args.asset,
                             actor=args.actor, ttl_seconds=args.ttl,
                             tenant_id=user.tenant_id)
    print(json.dumps({"ok": True, "user_id": args.user, "asset_id": args.asset,
                      "tenant_id": user.tenant_id}))


def cmd_profiles(args):
    _, _, factory, _ = _context(args)
    stamp = time.time()
    with transaction(factory) as db:
        rows = [governance.profile_view(row.public(), now=stamp, approver=args.actor)
                for row in db.scalars(select(VendorProfile)
                                      .order_by(VendorProfile.priority)).all()]
    print(json.dumps(rows, ensure_ascii=False, indent=1))


def cmd_create_profile(args):
    spec = _load_json(args.spec, "--spec")
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        try:
            row = brand_onboarding.create_draft_profile(
                db, spec=spec, evidence=args.evidence, actor=args.actor)
        except brand_onboarding.SpecError as exc:
            raise SystemExit(str(exc)) from exc
    print(json.dumps({**row.public(),
                      "approve_command": governance.approve_profile_command(
                          row.id, approver=args.actor, evidence=args.evidence)},
                     ensure_ascii=False, indent=1))


def cmd_brand_onboard(args):
    spec = _load_json(args.spec, "--spec")
    payload = _load_json(args.inventory, "--inventory")
    inventory = payload.get("inventory", payload)
    _, _, factory, _ = _context(args)

    with transaction(factory) as db:
        existing = db.scalar(select(VendorProfile).where(VendorProfile.code == spec.get("code")))
        if existing is not None:
            profile = existing
            try:
                if not brand_onboarding.profile_matches_spec(
                        existing, spec, evidence=args.evidence):
                    raise SystemExit("profile code exists with different wire settings; "
                                     "refusing to reuse it")
            except brand_onboarding.SpecError as exc:
                raise SystemExit(str(exc)) from exc
            created = False
        else:
            try:
                profile = brand_onboarding.create_draft_profile(
                    db, spec=spec, evidence=args.evidence, actor=args.actor)
            except brand_onboarding.SpecError as exc:
                raise SystemExit(str(exc)) from exc
            created = True

        detection = vendor_registry.detect_from_redfish(inventory)
        match = vendor_registry.identify(db, detection, greeting=args.greeting or "")
        if match.profile is None or match.profile.id != profile.id:
            raise SystemExit("inventory did not match the new profile "
                             f"({match.reason or 'matched_a_different_profile'}); "
                             "no capability draft was created")

        draft = services.capability_draft(db, profile, detection=detection, actor=args.actor)
        services.audit(db, args.actor, "brand_onboard_prepared",
                       detail={"profile_id": profile.id, "code": profile.code,
                               "capability_id": draft.id,
                               "detection": {k: detection.get(k)
                                             for k in ("vendor", "model", "firmware")}})

    commands = []
    if profile.status != PROFILE_APPROVED:
        commands.append(governance.approve_profile_command(
            profile.id, approver=args.actor, evidence=args.evidence))
    commands.append(governance.approve_capability_command(
        draft.id, approver=args.actor, evidence=args.evidence))
    commands.append("tools/platform_admin.py sync-data-plane "
                    f"--store '/path/to/data-plane-dsn' --evidence {shlex.quote(args.evidence)} "
                    f"--approver {shlex.quote(args.actor)}")
    print(json.dumps({"profile": profile.public(), "profile_created": created,
                      "capability": {"id": draft.id, "status": draft.status},
                      "match": match.as_dict(), "detection": detection,
                      "commands": commands},
                     ensure_ascii=False, indent=1))


def cmd_approve_profile(args):
    if not args.evidence or not Path(args.evidence).exists():
        raise SystemExit("--evidence must point at an existing measured evidence file")
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        profile = db.get(VendorProfile, args.id)
        if profile is None:
            raise SystemExit("profile not found")
        renewing = profile.status == PROFILE_APPROVED
        if renewing and not args.renew:
            raise SystemExit("profile is already approved; pass --renew to record a new review")
        stamp = time.time()
        profile.status = PROFILE_APPROVED
        profile.approver = args.approver
        profile.evidence = str(args.evidence)
        profile.approved_at = stamp
        profile.review_due = stamp + args.review_days * 86400
        profile.revision = int(profile.revision or 0) + 1
        services.audit(db, args.approver,
                       "vendor_profile_reapproved" if renewing else "vendor_profile_approved",
                       detail={"profile_id": profile.id, "code": profile.code,
                               "evidence": str(args.evidence), "review_due": profile.review_due,
                               "revision": profile.revision}, now=stamp)
        print(json.dumps({"ok": True, "code": profile.code, "approver": args.approver,
                          "renewed": renewing, "review_due": profile.review_due},
                         ensure_ascii=False))


def cmd_capabilities(args):
    _, _, factory, _ = _context(args)
    stamp = time.time()
    with transaction(factory) as db:
        rows = [governance.capability_view(
                    {"id": row.id, "tenant_id": row.tenant_id, "vendor": row.vendor,
                     "model": row.model, "firmware": row.firmware, "adapter": row.adapter,
                     "status": row.status, "profile_id": row.profile_id,
                     "evidence": row.evidence, "expires": row.expires,
                     "review_due": row.review_due, "approver": row.approver},
                    now=stamp, approver=args.actor)
                for row in db.scalars(select(Capability)).all()]
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
        match = vendor_registry.identify(db, detection, greeting=args.greeting or "")
        result = match.as_dict()
        result["detection"] = detection
        if args.greeting:
            result["measured_greeting"] = args.greeting
        if match.usable:
            result["connection_plan"] = vendor_registry.connection_plan(match.profile)
        if args.make_draft and match.profile is not None:
            row = services.capability_draft(db, match.profile, detection=detection, actor=args.actor)
            result["capability_draft_id"] = row.id
    print(json.dumps(result, ensure_ascii=False, indent=1))


def cmd_rebind_asset(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        asset = db.get(PlatformAsset, args.id)
        if asset is None:
            raise SystemExit("asset not found")
        profile = connection.approved_profile(db, args.profile)
        if profile is None:
            raise SystemExit(f"profile {args.profile} not found")
        if profile.status != PROFILE_APPROVED:
            raise SystemExit(f"profile {args.profile} is {profile.status}; approve it first")
        detection = {"vendor": asset.vendor, "model": asset.model,
                     "firmware": asset.firmware, "raw": {"Manufacturer": asset.vendor}}
        draft = services.capability_draft(db, profile, detection=detection, actor=args.actor,
                                          tenant_id=asset.tenant_id)
        before = {"profile_id": asset.profile_id, "capability_id": asset.capability_id}
        asset.profile_id = profile.id
        asset.capability_id = draft.id
        asset.updated = time.time()
        services.audit(db, args.actor, "asset_rebound", asset_id=asset.id,
                       tenant_id=asset.tenant_id,
                       detail={**before, "profile_id": profile.id,
                               "capability_id": draft.id, "rfb_version": profile.rfb_version},
                       now=time.time())
        print(json.dumps({"asset": asset.id, "address": asset.address,
                          "profile": profile.code, "rfb_version": profile.rfb_version,
                          "message_profile": profile.message_profile,
                          "capability": draft.id, "capability_status": draft.status},
                         ensure_ascii=False))


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
        if args.tenant:
            rows = services.list_users(db, tenant_id=services.resolve_tenant(db, args.tenant).id)
        else:
            rows = []
            for user in db.scalars(select(User).order_by(User.created)).all():
                item = user.public()
                item["roles"] = services.roles_of(db, user.id)
                rows.append(item)
        print(json.dumps(rows, ensure_ascii=False, indent=1))


def cmd_audit(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        print(json.dumps(services.recent_audit(db, args.limit), ensure_ascii=False, indent=1))


def cmd_create_service_token(args):
    _, _, factory, _ = _context(args)
    allowlist = [item.strip() for item in args.allow.split(",") if item.strip()]
    with transaction(factory) as db:
        result = services.create_service_token(
            db, tenant_code=args.tenant, label=args.label, allowlist=allowlist,
            actor=args.actor, expires_days=args.expires_days)
    print(json.dumps(result, ensure_ascii=False, indent=1))


def cmd_list_service_tokens(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        rows = services.list_service_tokens(db, tenant_code=args.tenant)
    print(json.dumps(rows, ensure_ascii=False, indent=1))


def cmd_revoke_service_token(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        row = services.revoke_service_token(db, args.id, actor=args.actor)
    print(json.dumps(row, ensure_ascii=False, indent=1))


def cmd_quota_usage(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        rows = services.quota_usage_view(db, args.period)
    print(json.dumps(rows, ensure_ascii=False, indent=1))


def cmd_rebuild_quota_usage(args):
    _, engine, factory, _ = _context(args)
    with transaction(factory) as db:
        result = services.rebuild_quota_usage(
            db, plane_db=args.data_plane_db, period=args.period)
    engine.dispose()
    print(json.dumps(result, ensure_ascii=False, indent=1))


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
            if asset.tenant_id:
                grants = [TENANT_GRANT, *grants]
            if not grants and not args.user:
                skipped.append({"asset": asset.id, "reason": "no_owner_no_grant"})
                continue
            users = [args.user] if args.user else grants
            target = asset.address if "://" in asset.address else f"https://{asset.address}"
            targets.append(target)
            plan.append({"asset_id": asset.id, "name": asset.name,
                         "vendor": asset.vendor, "model": asset.model,
                         "firmware": asset.firmware, "fingerprint": asset.fingerprint,
                         "target": target, "entry": entry, "users": users,
                         "secret": services.read_credential(db, cipher, asset.credential_id,
                                                            tenant_id=asset.tenant_id),
                         "licence": profile.licence,
                         "console_impl": profile.console_impl or "passthrough"})
            services.audit(db, args.actor, "data_plane_sync_planned", asset_id=asset.id,
                           tenant_id=asset.tenant_id,
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
    q = sub.add_parser("create-user"); q.add_argument("--username", required=True); q.add_argument("--role", default="viewer"); q.add_argument("--display-name"); q.add_argument("--tenant", default="default"); q.set_defaults(fn=cmd_create_user)
    q = sub.add_parser("create-platform-admin", help="create the cross-tenant operator (tenant_id NULL)")
    q.add_argument("--username", required=True); q.set_defaults(fn=cmd_create_platform_admin)
    q = sub.add_parser("reset-password", help="reset an existing account's password out of band and revoke its sessions")
    q.add_argument("--username", required=True, help="account to reset (platform or tenant)")
    q.add_argument("--tenant", help="tenant code; omit for the platform (tenant_id NULL) account")
    q.add_argument("--generate", action="store_true",
                   help="mint a strong password locally and print it once; no env var needed")
    q.set_defaults(fn=cmd_reset_password)
    q = sub.add_parser("add-credential"); q.add_argument("--label", required=True); q.set_defaults(fn=cmd_add_credential)
    q = sub.add_parser("add-asset")
    for name in ("name", "address"):
        q.add_argument("--" + name, required=True)
    for name in ("vendor", "model", "firmware", "fingerprint", "credential-id", "profile-id", "capability-id", "licence"):
        q.add_argument("--" + name)
    q.set_defaults(fn=cmd_add_asset)
    q = sub.add_parser("grant"); q.add_argument("--user", required=True); q.add_argument("--asset", required=True); q.add_argument("--ttl", type=int, default=86400 * 30); q.set_defaults(fn=cmd_grant)
    sub.add_parser("profiles").set_defaults(fn=cmd_profiles)
    q = sub.add_parser("create-profile", help="create a draft vendor profile from a measured spec")
    q.add_argument("--spec", required=True, help="JSON file with the measured brand spec")
    q.add_argument("--evidence", required=True, help="existing measured evidence file")
    q.set_defaults(fn=cmd_create_profile)
    q = sub.add_parser("brand-onboard", help="prepare a new brand through drafts; never approves")
    q.add_argument("--spec", required=True, help="JSON file with the measured brand spec")
    q.add_argument("--inventory", required=True, help="saved Redfish inventory JSON")
    q.add_argument("--evidence", required=True, help="existing measured evidence file")
    q.add_argument("--greeting", help="measured RFB greeting, e.g. 'RFB 003.008'")
    q.set_defaults(fn=cmd_brand_onboard)
    q = sub.add_parser("approve-profile"); q.add_argument("--id", required=True); q.add_argument("--approver", required=True); q.add_argument("--evidence", required=True); q.add_argument("--review-days", type=int, default=180); q.add_argument("--renew", action="store_true", help="record a new review of an already-approved profile"); q.set_defaults(fn=cmd_approve_profile)
    sub.add_parser("capabilities").set_defaults(fn=cmd_capabilities)
    q = sub.add_parser("approve-capability"); q.add_argument("--id", required=True); q.add_argument("--approver", required=True); q.add_argument("--evidence", required=True); q.add_argument("--review-days", type=int, default=180); q.add_argument("--valid-days", type=int, default=365); q.set_defaults(fn=cmd_approve_capability)
    q = sub.add_parser("detect"); q.add_argument("--inventory", required=True); q.add_argument("--make-draft", action="store_true"); q.add_argument("--greeting", help="RFB greeting measured by a probe, e.g. 'RFB 055.008'"); q.set_defaults(fn=cmd_detect)
    q = sub.add_parser("rebind-asset", help="bind an asset to a measured profile and mint its capability draft")
    q.add_argument("--id", required=True); q.add_argument("--profile", required=True, help="profile code")
    q.set_defaults(fn=cmd_rebind_asset)
    q = sub.add_parser("users"); q.add_argument("--tenant", help="filter by tenant code"); q.set_defaults(fn=cmd_users)
    q = sub.add_parser("audit"); q.add_argument("--limit", type=int, default=50); q.set_defaults(fn=cmd_audit)
    q = sub.add_parser("create-service-token", help="issue a DCIM bearer token with a source-IP allowlist")
    q.add_argument("--tenant", required=True, help="tenant code the token is bound to")
    q.add_argument("--label", required=True, help="operator-facing name, unique per tenant")
    q.add_argument("--allow", required=True,
                    help="comma-separated source CIDRs, e.g. 192.0.2.0/24,192.0.2.5/32")
    q.add_argument("--expires-days", type=int, default=None, help="omit for a non-expiring token")
    q.add_argument("--actor", default="platform")
    q.set_defaults(fn=cmd_create_service_token)
    q = sub.add_parser("list-service-tokens", help="list token metadata (never the secret)")
    q.add_argument("--tenant", default="")
    q.set_defaults(fn=cmd_list_service_tokens)
    q = sub.add_parser("revoke-service-token", help="invalidate a token immediately")
    q.add_argument("--id", required=True)
    q.add_argument("--actor", default="platform")
    q.set_defaults(fn=cmd_revoke_service_token)
    q = sub.add_parser("quota-usage", help="read a rebuilt monthly usage snapshot")
    q.add_argument("--period", required=True, help="UTC month, YYYY-MM")
    q.set_defaults(fn=cmd_quota_usage)
    q = sub.add_parser("rebuild-quota-usage", help="rebuild a month from raw audit/session rows")
    q.add_argument("--period", required=True, help="UTC month, YYYY-MM")
    q.add_argument("--data-plane-db", required=True,
                   help="data-plane store DSN: sqlite path or mysql://user:password@host:3306/db")
    q.set_defaults(fn=cmd_rebuild_quota_usage)
    q = sub.add_parser("sync-data-plane", help="import approved assets into the data-plane store")
    q.add_argument("--store", required=True,
                   help="data-plane store DSN: sqlite path or mysql://user:password@host:3306/db")
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
