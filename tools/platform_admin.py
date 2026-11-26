#!/usr/bin/env -S .venv/bin/python
"""Out-of-band administration for the production control plane."""
from __future__ import annotations

import argparse
import asyncio
import base64
import ipaddress
import json
import os
import secrets
import shlex
import string
import sys
import time
import uuid
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from kvmhub.platform.config import settings  # noqa: E402
from kvmhub.platform.db import (bootstrap_admin, bootstrap_platform_admin,  # noqa: E402
                                init_schema, make_engine, seed_roles,
                                session_factory, transaction)
from kvmhub.platform.models import (AccessGrant, Asset as PlatformAsset,  # noqa: E402
                                    AssetConnection, ClockWatermark, DeviceAdmission,
                                    ExecutionDomain, PlaneProjection,
                                    PROFILE_APPROVED, ROLE_ADMIN, Capability,
                                    Credential, Role, User, UserRole, VendorProfile)
from kvmhub.platform.security import CredentialCipher  # noqa: E402
from kvmhub.platform import (brand_onboarding, clockguard, connection,  # noqa: E402
                             governance, services, vendor_registry)
from kvmhub.platform.bus import AssemblyBus  # noqa: E402
from kvmhub.platform.redis_state import SESSION_PREFIX, create_state  # noqa: E402
from kvmhub.store import TENANT_GRANT, Store  # noqa: E402


def _context(args):
    cfg = settings(args.env_file)
    engine = make_engine(cfg.db_url)
    return cfg, engine, session_factory(engine), CredentialCipher(cfg.credential_key, previous_key=cfg.previous_credential_key)


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} must be set (secrets are never CLI arguments)")
    return value


def cmd_attest_overlay_identity(args):
    from kvmhub.platform import overlays
    path = Path(args.evidence)
    if not path.is_file() or not path.stat().st_size:
        raise SystemExit('evidence must be a non-empty measured report file')
    cfg, engine, factory, _ = _context(args)
    try:
        with transaction(factory) as db:
            row = overlays.attest(db, asset_id=args.asset, model_id=args.model_id,
                firmware=args.firmware, actor=args.approver, evidence=str(path.resolve()),
                expires=args.expires)
            print(json.dumps({'asset_id': row.asset_id,
                'admission_revision': row.admission_revision, 'model_id': row.model_id}))
    finally:
        engine.dispose()


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


def cmd_set_vnc_secret(args):
    _, _, factory, cipher = _context(args)
    with transaction(factory) as db:
        asset = services.save_vnc_secret(
            db, cipher, asset_id=args.asset,
            username=_required_env("VNC_USER"),
            password=_required_env("VNC_PASSWORD"),
            actor=args.actor, tenant_id=None)
        print(json.dumps({"ok": True, "asset_id": asset.id,
                          "vnc_secret_set": True, "credential_id": asset.credential_id},
                         ensure_ascii=False))


def cmd_clear_vnc_secret(args):
    _, _, factory, _ = _context(args)
    with transaction(factory) as db:
        asset = services.clear_vnc_secret(db, asset_id=args.asset,
                                          actor=args.actor, tenant_id=None)
        print(json.dumps({"ok": True, "asset_id": asset.id,
                          "vnc_secret_set": False}, ensure_ascii=False))


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


def _emit_source_change(db, *, profile_id: str | None = None,
                        capability_id: str | None = None, reason: str,
                        actor: str, now: float) -> list[str]:
    from kvmhub.platform import overlays
    overlays.invalidate_sources(db, profile_id=profile_id, capability_id=capability_id,
                                actor=actor, now=now)
    query = select(PlatformAsset.id)
    if profile_id:
        query = query.where(PlatformAsset.profile_id == profile_id)
    if capability_id:
        query = query.where(PlatformAsset.capability_id == capability_id)
    ids = list(db.scalars(query).all())
    if not ids:
        return []
    from kvmhub.platform.connection_config import record_change

    return record_change(db, asset_ids=ids, reason=reason, actor=actor, now=now)


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
        _emit_source_change(db, profile_id=profile.id,
                            reason="vendor_profile_approved",
                            actor=args.approver, now=stamp)
        print(json.dumps({"ok": True, "code": profile.code, "approver": args.approver,
                          "renewed": renewing, "review_due": profile.review_due},
                         ensure_ascii=False))


def cmd_set_pipeline_identity(args):
    if not args.evidence or not Path(args.evidence).exists():
        raise SystemExit("--evidence must point at an existing measured evidence file")
    recipe_id = (args.recipe_id or "").strip()
    schema = (args.schema or "").strip()
    if not recipe_id or not schema:
        raise SystemExit("--recipe-id and --schema are required for the video lane")
    if args.recipe_revision < 1:
        raise SystemExit("--recipe-revision must be a positive integer")
    if not args.capability and args.bundle:
        raise SystemExit("--bundle requires --capability: the bundle is per capability")
    if args.bundle is not None and not args.bundle.strip():
        raise SystemExit("--bundle must not be empty when given")

    _, _, factory, _ = _context(args)
    stamp = time.time()
    with transaction(factory) as db:
        profile = db.get(VendorProfile, args.profile)
        if profile is None:
            raise SystemExit("profile not found")
        capability = None
        if args.capability:
            capability = db.get(Capability, args.capability)
            if capability is None:
                raise SystemExit("capability not found")
            if capability.profile_id != profile.id:
                raise SystemExit("capability does not belong to that profile")
        previous = {"recipe_id": profile.recipe_id,
                    "recipe_revision": profile.recipe_revision,
                    "config_schema_version": profile.config_schema_version,
                    "bundle_revision": capability.bundle_revision if capability else ""}
        bundle = args.bundle.strip() if args.bundle is not None else None
        recipe_changed = (str(profile.recipe_id or "") != recipe_id
                          or int(profile.recipe_revision or 0) != int(args.recipe_revision)
                          or str(profile.config_schema_version or "") != schema)
        bundle_changed = bool(capability is not None and bundle is not None
                              and str(capability.bundle_revision or "") != bundle)
        if not recipe_changed and not bundle_changed:
            print(json.dumps({"ok": True, "unchanged": True,
                              "profile_id": profile.id, "code": profile.code},
                             ensure_ascii=False, indent=1))
            return
        profile.recipe_id = recipe_id
        profile.recipe_revision = int(args.recipe_revision)
        profile.config_schema_version = schema
        if recipe_changed:
            profile.revision = int(profile.revision or 0) + 1
        if capability is not None and bundle is not None:
            capability.bundle_revision = bundle
            if recipe_changed:
                capability.revision = int(capability.revision or 0) + 1
        services.audit(db, args.approver, "pipeline_identity_recorded",
                       detail={"profile_id": profile.id, "code": profile.code,
                               "capability_id": capability.id if capability else None,
                               "evidence": str(args.evidence),
                               "previous": previous,
                               "recipe_id": recipe_id,
                               "recipe_revision": profile.recipe_revision,
                               "config_schema_version": schema,
                               "bundle_revision": (capability.bundle_revision
                                                   if capability else ""),
                               "bundle_only": not recipe_changed},
                       now=stamp)
        reissued = []
        if recipe_changed:
            reissued = _emit_source_change(
                db, profile_id=profile.id,
                capability_id=capability.id if capability else None,
                reason="pipeline_identity_recorded", actor=args.approver, now=stamp)
        print(json.dumps({"ok": True, "profile_id": profile.id,
                          "recipe_id": recipe_id,
                          "recipe_revision": profile.recipe_revision,
                          "config_schema_version": schema,
                          "bundle_revision": capability.bundle_revision if capability else "",
                          "bundle_only": not recipe_changed,
                          "profile_revision": profile.revision,
                          "reprojected_assets": len(reissued)},
                         ensure_ascii=False, indent=1))


def cmd_refresh_lane_contract(args):
    from kvmhub.platform import connection_config
    from kvmhub.platform.models import parse_json
    from kvmhub.video.client_v2 import protocol_contract

    contract = protocol_contract()
    _, _, factory, _ = _context(args)
    stamp = time.time()
    with transaction(factory) as db:
        query = (select(PlatformAsset.id)
                 .join(VendorProfile, PlatformAsset.profile_id == VendorProfile.id)
                 .where(VendorProfile.recipe_id != ""))
        if args.asset:
            query = query.where(PlatformAsset.id == args.asset)
        if args.profile:
            query = query.where(PlatformAsset.profile_id == args.profile)
        candidates = list(db.scalars(query).all())
        ids = []
        for aid in candidates:
            row = db.scalar(select(AssetConnection)
                            .where(AssetConnection.asset_id == aid)
                            .order_by(AssetConnection.revision.desc()).limit(1))
            stored = parse_json(row.source_versions_json, {}) if row is not None else {}
            if not isinstance(stored, dict) or stored.get("protocol_contract") != contract:
                ids.append(aid)
        if not ids:
            print(json.dumps({"ok": True, "assets": 0, "candidates": len(candidates),
                              "contract": contract,
                              "note": "车道资产的快照已绑定当前契约，无需重投影"},
                             ensure_ascii=False, indent=1))
            return
        events = connection_config.record_change(
            db, asset_ids=ids, reason="lane_contract_refresh",
            actor=args.actor, now=stamp)
        print(json.dumps({"ok": True, "assets": len(ids), "candidates": len(candidates),
                          "events": len(events), "contract": contract,
                          "note": "投影确认前车道保持关闭：等待 G1 投影 ack 后 g0.reason 才会清空"},
                         ensure_ascii=False, indent=1))


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
        _emit_source_change(db, capability_id=row.id,
                            reason="capability_approved",
                            actor=args.approver, now=stamp)
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


def cmd_clock_reset(args):
    if not args.confirm:
        raise SystemExit("clock-reset requires --confirm; verify NTP on this host first")
    target = args.to if args.to is not None else time.time()
    if abs(target - time.time()) > 86400:
        raise SystemExit("refusing a reset more than a day away from the host clock")
    _, engine, factory, _ = _context(args)
    with transaction(factory) as db:
        row = db.get(ClockWatermark, clockguard.WATERMARK_ID)
        floor = float(row.high_water or 0.0) if row else 0.0
        if floor and target - floor > clockguard.FORWARD_JUMP_LIMIT and not args.ack_forward_jump:
            raise SystemExit(
                "this looks like a forward-jump recovery: verify NTP again and "
                "re-run with --ack-forward-jump")
        result = services.reset_clock_watermark(
            db, now=target, actor=args.actor, trace="clock-reset-cli")
    engine.dispose()
    print(json.dumps(result, ensure_ascii=False, indent=1))


def cmd_rotate_vnc_key(args):
    if not args.confirm:
        raise SystemExit("rotate-vnc-key requires --confirm")
    raw = os.environ.get("KVMHUB_NEW_CREDENTIAL_KEY", "")
    if not raw:
        raise SystemExit("KVMHUB_NEW_CREDENTIAL_KEY must be set (secrets are never CLI args)")
    try:
        new_key = base64.b64decode(raw, validate=True)
    except Exception:
        raise SystemExit("KVMHUB_NEW_CREDENTIAL_KEY must be base64")
    if len(new_key) != 32:
        raise SystemExit("KVMHUB_NEW_CREDENTIAL_KEY must decode to 32 bytes")
    cfg, engine, factory, cipher = _context(args)
    new_cipher = CredentialCipher(new_key)
    with transaction(factory) as db:
        result = services.rotate_vnc_secret_key(db, cipher, new_cipher, actor=args.actor)
    engine.dispose()
    result["next"] = ("deploy the new key as KVMHUB_CREDENTIAL_KEY and the old one as "
                      "KVMHUB_CREDENTIAL_KEY_PREVIOUS, then restart; remove the previous "
                      "key only after no rows report the old version")
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
                admins = [row[0] for row in db.execute(
                    select(UserRole.user_id)
                    .join(Role, Role.id == UserRole.role_id)
                    .join(User, User.id == UserRole.user_id)
                    .where(Role.code == ROLE_ADMIN, User.tenant_id == asset.tenant_id,
                           User.is_active.is_(True))).all()]
                grants = sorted(set(grants) | set(admins))
            if not grants and not args.user:
                skipped.append({"asset": asset.id, "reason": "no_owner_no_grant"})
                continue
            users = [args.user] if args.user else grants
            target = asset.address if "://" in asset.address else f"https://{asset.address}"
            targets.append(target)
            secret, secret_source = services.select_sync_secret(
                db, cipher, asset, tenant_id=asset.tenant_id)
            plan.append({"asset_id": asset.id, "name": asset.name,
                         "vendor": asset.vendor, "model": asset.model,
                         "firmware": asset.firmware, "fingerprint": asset.fingerprint,
                         "target": target, "entry": entry, "users": users,
                         "secret": secret,
                         "licence": profile.licence,
                         "console_impl": profile.console_impl or "passthrough"})
            services.audit(db, args.actor, "data_plane_sync_planned", asset_id=asset.id,
                           tenant_id=asset.tenant_id,
                           detail={"capability_entry": entry["id"], "users": users,
                                   "secret_source": secret_source}, now=stamp)
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


MIGRATION_REPORT_CATEGORIES = (
    "db_asset_missing_target", "target_without_asset", "duplicate_endpoint",
    "noncanonical_target", "missing_approval_evidence",
    "capability_not_verified_or_expired", "cross_tenant_reference",
    "network_or_pin_denied", "config_process_mismatch",
    "admission_pending", "projection_revision_behind", "projection_digest_mismatch",
    "domain_generation_mismatch", "domain_policy_mismatch",
)


def _canonical_endpoint(value: str) -> tuple[str | None, bool]:
    raw = (value or "").strip()
    if not raw:
        return None, True
    if "://" in raw:
        try:
            parts = urlsplit(raw)
            host = parts.hostname or ""
            ipaddress.ip_address(host)
            port = parts.port or (443 if parts.scheme in ("https", "wss") else 5900)
        except ValueError:
            return raw, True
        path = parts.path.rstrip("/")
        endpoint = f"{host}:{port}" + (f":{path}" if path else "")
        bad = bool(parts.username or parts.password or parts.query or parts.fragment)
        return endpoint, bad
    try:
        ipaddress.ip_address(raw)
        return f"{raw}:443", False
    except ValueError:
        return raw, True


def build_migration_report(*, db: Session, store: Store, now: float | None = None) -> dict:
    stamp = time.time() if now is None else now
    categories: dict[str, list] = {key: [] for key in MIGRATION_REPORT_CATEGORIES}

    users = {row[0]: row[1] for row in db.execute(select(User.id, User.tenant_id)).all()}
    capabilities = {row.id: row for row in db.scalars(select(Capability)).all()}
    control: dict[str, dict] = {}
    for asset in db.scalars(select(PlatformAsset)).all():
        endpoint, bad = _canonical_endpoint(asset.address)
        control[asset.id] = {"asset": asset.id, "address": asset.address,
                             "endpoint": endpoint, "tenant_id": asset.tenant_id}
        if bad:
            categories["noncanonical_target"].append(
                {"asset": asset.id, "target": asset.address})
        cap = capabilities.get(asset.capability_id)
        if cap is None or not cap.evidence:
            categories["missing_approval_evidence"].append(
                {"asset": asset.id, "capability": asset.capability_id})
        if cap is None or cap.status != "verified" or cap.expires <= stamp:
            categories["capability_not_verified_or_expired"].append(
                {"asset": asset.id, "capability": asset.capability_id,
                 "status": getattr(cap, "status", None)})

    seen: dict[str, list[str]] = {}
    for aid, info in control.items():
        if info["endpoint"]:
            seen.setdefault(info["endpoint"], []).append(aid)
    for endpoint, aids in seen.items():
        if len(aids) > 1:
            categories["duplicate_endpoint"].append(
                {"endpoint": endpoint, "assets": sorted(aids)})

    actual: dict[str, dict] = {}
    for aid, target, fingerprint in store.db.execute(
            "SELECT id,target,fingerprint FROM asset").fetchall():
        endpoint, bad = _canonical_endpoint(target)
        actual[aid] = {"asset": aid, "target": target, "endpoint": endpoint}
        if bad:
            categories["noncanonical_target"].append({"asset": aid, "target": target})
        if len((fingerprint or "").replace(":", "").strip()) != 64:
            categories["network_or_pin_denied"].append(
                {"asset": aid, "reason": "fingerprint_missing"})
        owner = control.get(aid)
        if owner and owner["tenant_id"] is not None:
            for (uid,) in store.db.execute(
                    "SELECT user_id FROM access_grant WHERE asset_id=?", (aid,)).fetchall():
                if users.get(uid) not in (None, owner["tenant_id"]):
                    categories["cross_tenant_reference"].append(
                        {"asset": aid, "user": uid})

    control_endpoints = {info["endpoint"] for info in control.values()}
    actual_endpoints = {info["endpoint"] for info in actual.values()}
    for aid, info in control.items():
        if info["endpoint"] not in actual_endpoints:
            categories["db_asset_missing_target"].append(
                {"asset": aid, "address": info["address"]})
    for aid, info in actual.items():
        if info["endpoint"] not in control_endpoints:
            categories["target_without_asset"].append(
                {"asset": aid, "target": info["target"]})

    admissions: dict[str, DeviceAdmission] = {}
    for row in db.scalars(select(DeviceAdmission).order_by(
            DeviceAdmission.asset_id, DeviceAdmission.revision)).all():
        admissions[row.asset_id] = row
    connections: dict[str, AssetConnection] = {}
    for row in db.scalars(select(AssetConnection).order_by(
            AssetConnection.asset_id, AssetConnection.revision)).all():
        connections[row.asset_id] = row
    projections = {row.asset_id: row for row in db.scalars(select(PlaneProjection)).all()}
    domains = {row.domain_id: row for row in db.scalars(select(ExecutionDomain)).all()}
    for aid in control:
        admission = admissions.get(aid)
        if admission is None or admission.state == "pending":
            categories["admission_pending"].append(
                {"asset": aid, "state": getattr(admission, "state", None)})
        conn = connections.get(aid)
        projection = projections.get(aid)
        if conn is not None and projection is not None:
            desired_revision = max(int(conn.revision or 0),
                                   int(projection.desired_revision or 0))
            desired_digest = projection.desired_digest or conn.digest
            if projection.applied_revision < desired_revision:
                categories["projection_revision_behind"].append(
                    {"asset": aid, "desired": desired_revision,
                     "applied": projection.applied_revision})
            elif projection.applied_revision and projection.applied_digest != desired_digest:
                categories["projection_digest_mismatch"].append(
                    {"asset": aid, "desired": desired_digest,
                     "applied": projection.applied_digest})
        domain = domains.get(projection.domain_id) if projection is not None else None
        if projection is not None and domain is not None:
            if projection.generation != domain.generation:
                categories["domain_generation_mismatch"].append(
                    {"asset": aid, "projection": projection.generation,
                     "domain": domain.generation})
            if projection.policy_fingerprint != domain.policy_fingerprint:
                categories["domain_policy_mismatch"].append(
                    {"asset": aid, "projection": projection.policy_fingerprint,
                     "domain": domain.policy_fingerprint})

    return {"clean": not any(categories.values()),
            "assets": len(control), "categories": categories}


def cmd_reconcile_data_plane(args):
    _, engine, factory, _ = _context(args)
    data_key = base64.b64decode(_required_env("KVMHUB_DATA_PLANE_KEY"), validate=True)
    if len(data_key) != 32:
        raise SystemExit("KVMHUB_DATA_PLANE_KEY must decode to 32 bytes")
    if getattr(args, "migration_report", False):
        store = Store(str(args.store), data_key)
        try:
            with transaction(factory) as db:
                result = build_migration_report(db=db, store=store, now=time.time())
        finally:
            store.close()
        print(json.dumps(result, ensure_ascii=False, indent=1))
        engine.dispose()
        return result
    stamp = time.time()
    expected: dict[str, set[str]] = {}
    with transaction(factory) as db:
        for asset in db.scalars(select(PlatformAsset)).all():
            users = {row[0] for row in db.execute(
                select(AccessGrant.user_id).where(
                    AccessGrant.asset_id == asset.id, AccessGrant.expires > stamp)).all()}
            if asset.tenant_id:
                users |= {row[0] for row in db.execute(
                    select(UserRole.user_id)
                    .join(Role, Role.id == UserRole.role_id)
                    .join(User, User.id == UserRole.user_id)
                    .where(Role.code == ROLE_ADMIN, User.tenant_id == asset.tenant_id,
                           User.is_active.is_(True))).all()}
            if users:
                expected[asset.id] = users
    store = Store(str(args.store), data_key)
    try:
        actual: dict[str, set[str]] = {}
        wildcard_assets: list[str] = []
        for row in store.db.execute("SELECT asset_id,user_id,expires FROM access_grant "
                                    "WHERE expires>?", (stamp,)).fetchall():
            aid, uid = row[0], row[1]
            if uid == TENANT_GRANT:
                wildcard_assets.append(aid)
                continue
            actual.setdefault(aid, set()).add(uid)
    finally:
        store.close()
    drift = []
    for aid in sorted(set(expected) | set(actual)):
        missing = expected.get(aid, set()) - actual.get(aid, set())
        extra = actual.get(aid, set()) - expected.get(aid, set())
        if missing or extra:
            drift.append({"asset": aid, "missing": sorted(missing), "extra": sorted(extra)})
    result = {"clean": not drift, "assets": len(expected),
              "wildcard_assets": sorted(set(wildcard_assets)), "drift": drift}
    print(json.dumps(result, ensure_ascii=False, indent=1))
    engine.dispose()
    return result


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

    q = sub.add_parser('attest-overlay-identity', help='bind measured identity to an approved device admission')
    q.add_argument('--asset', required=True)
    q.add_argument('--model-id', required=True, help='exact approved Capability row ID')
    q.add_argument('--firmware', required=True)
    q.add_argument('--evidence', required=True)
    q.add_argument('--approver', required=True)
    q.add_argument('--expires', type=float, required=True, help='evidence expiry, epoch seconds')
    q.set_defaults(fn=cmd_attest_overlay_identity)
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
    q = sub.add_parser("set-vnc-secret", help="store a hidden VNC-only account on an asset (VNC_USER/VNC_PASSWORD env)")
    q.add_argument("--asset", required=True, help="asset row id")
    q.set_defaults(fn=cmd_set_vnc_secret)
    q = sub.add_parser("clear-vnc-secret", help="remove an asset's hidden VNC secret (fall back to BMC credential)")
    q.add_argument("--asset", required=True, help="asset row id")
    q.set_defaults(fn=cmd_clear_vnc_secret)
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
    q = sub.add_parser("set-pipeline-identity",
                       help="record the recipe/bundle an approved profile may run on the V1 video lane")
    q.add_argument("--profile", required=True, help="vendor profile id")
    q.add_argument("--capability", help="capability id that locks the bundle (optional)")
    q.add_argument("--recipe-id", required=True)
    q.add_argument("--recipe-revision", type=int, required=True)
    q.add_argument("--schema", required=True, help="config schema version, e.g. v1")
    q.add_argument("--bundle", help="locked client bundle revision, requires --capability")
    q.add_argument("--evidence", required=True)
    q.add_argument("--approver", required=True)
    q.set_defaults(fn=cmd_set_pipeline_identity)
    q = sub.add_parser("refresh-lane-contract",
                       help="re-snapshot lane assets after the console wire contract changed in code")
    q.add_argument("--asset", help="one asset id; omit to refresh every lane asset")
    q.add_argument("--profile", help="limit to one vendor profile id")
    q.set_defaults(fn=cmd_refresh_lane_contract)
    sub.add_parser("capabilities").set_defaults(fn=cmd_capabilities)
    q = sub.add_parser("approve-capability"); q.add_argument("--id", required=True); q.add_argument("--approver", required=True); q.add_argument("--evidence", required=True); q.add_argument("--review-days", type=int, default=180); q.add_argument("--valid-days", type=int, default=365); q.set_defaults(fn=cmd_approve_capability)
    q = sub.add_parser("detect"); q.add_argument("--inventory", required=True); q.add_argument("--make-draft", action="store_true"); q.add_argument("--greeting", help="RFB greeting measured by a probe, e.g. 'RFB 055.008'"); q.set_defaults(fn=cmd_detect)
    q = sub.add_parser("rebind-asset", help="bind an asset to a measured profile and mint its capability draft")
    q.add_argument("--id", required=True); q.add_argument("--profile", required=True, help="profile code")
    q.set_defaults(fn=cmd_rebind_asset)
    q = sub.add_parser("users"); q.add_argument("--tenant", help="filter by tenant code"); q.set_defaults(fn=cmd_users)
    q = sub.add_parser("audit"); q.add_argument("--limit", type=int, default=50); q.set_defaults(fn=cmd_audit)
    q = sub.add_parser("rotate-vnc-key", help="re-encrypt hidden VNC secrets under a new master key")
    q.add_argument("--confirm", action="store_true", help="required: new key has been escrowed")
    q.add_argument("--actor", default="platform")
    q.set_defaults(fn=cmd_rotate_vnc_key)
    q = sub.add_parser("clock-reset", help="audited recovery from a wrong clock watermark (out of band)")
    q.add_argument("--confirm", action="store_true",
                   help="required: NTP has been verified on this host")
    q.add_argument("--ack-forward-jump", action="store_true",
                   help="required when the new floor is far ahead of the stored one")
    q.add_argument("--to", type=float, default=None, help="verified epoch seconds; default now")
    q.add_argument("--actor", default="platform")
    q.set_defaults(fn=cmd_clock_reset)
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
    q = sub.add_parser("reconcile-data-plane",
                       help="read-only per-user grant drift check before enabling strict grants")
    q.add_argument("--store", required=True,
                   help="data-plane store DSN: sqlite path or mysql://user:password@host:3306/db")
    q.add_argument("--migration-report", action="store_true",
                   help="emit the read-only P0 approval/target inventory instead of grant drift")
    q.set_defaults(fn=cmd_reconcile_data_plane)
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
