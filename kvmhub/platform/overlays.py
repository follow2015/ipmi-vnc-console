"""Transactional tenant overlays; approved capabilities are the model catalog."""
import math
import time
import uuid

from sqlalchemy import select

from ..profile_overlay import (BaseScope, FirmwareWindow, OverlayError,
                               OverlayRevision, OverlaySubset, device_in_scope,
                               digest_material, effective_scope)
from . import governance, services
from .models import (Asset, AssetOverlayBinding, Capability, DeviceAdmission,
                     DeviceIdentityEvidence, ProfileOverlay, ProfileOverlayRevision,
                     Tenant, User, VendorProfile, json_field, parse_json)


def refuse(code, status=409):
    raise services.PlatformError(code, '覆盖层未通过版本、范围或可信身份校验', status)


def actor_check(db, user_id, tenant_id):
    user = db.get(User, user_id)
    tenant = db.get(Tenant, tenant_id)
    if not user or not user.is_active or user.tenant_id != tenant_id:
        refuse('permission_denied', 403)
    if not tenant or tenant.status != 'active':
        refuse('tenant_suspended', 403)
    services.require(db, user_id, 'profile.overlay.write', tenant_id=tenant_id)


def subset_payload(subset):
    return {'model_subset': list(subset.model_ids),
            'firmware_subset': {'min': subset.firmware.lower, 'max': subset.firmware.upper},
            'concurrency': subset.concurrency}


def approved_base(db, profile, subset, tenant_id, now):
    if (profile is None or profile.tenant_id not in (None, tenant_id)
            or governance.profile_refusal(profile.status, profile.review_due, now)
            or not profile.review_due or not profile.approver or not profile.evidence):
        refuse(governance.PROFILE_NOT_APPROVED)
    versions = {}
    for model_id in subset.model_ids:
        cap = db.get(Capability, model_id)
        if (cap is None or cap.profile_id != profile.id
                or cap.tenant_id not in (None, tenant_id) or cap.status != 'verified'
                or cap.expires <= now or not cap.approver or not cap.evidence
                or (cap.review_due and cap.review_due <= now)
                or (cap.effective_from and cap.effective_from > now)
                or not cap.model or cap.adapter != profile.console_impl):
            refuse('overlay_model_not_approved')
        try:
            window = FirmwareWindow(cap.firmware_min or cap.firmware,
                                    cap.firmware_max or cap.firmware)
        except OverlayError:
            refuse('overlay_firmware_incomparable')
        if not window.contains_window(subset.firmware):
            refuse('overlay_firmware_expansion')
        versions[cap.id] = cap.revision
    if profile.firmware_min or profile.firmware_max:
        try:
            window = FirmwareWindow(profile.firmware_min, profile.firmware_max)
        except OverlayError:
            refuse('overlay_firmware_incomparable')
        if not window.contains_window(subset.firmware):
            refuse('overlay_firmware_expansion')
    base = BaseScope(profile.id, profile.revision, subset.model_ids,
                     subset.firmware, profile.concurrency_limit)
    return base, versions


def latest_admission(db, asset_id):
    return db.scalar(select(DeviceAdmission).where(DeviceAdmission.asset_id == asset_id)
                     .order_by(DeviceAdmission.revision.desc()).limit(1))


def attested_identity(db, asset, now):
    from .connection_config import _identity_digest
    admission = latest_admission(db, asset.id)
    if (not admission or admission.state != 'approved'
            or admission.tenant_id not in (None, asset.tenant_id)
            or admission.expires <= now or admission.review_due <= now
            or admission.identity_digest != _identity_digest(asset)):
        refuse('overlay_identity_unverified')
    evidence = db.get(DeviceIdentityEvidence, (asset.id, admission.revision))
    if (not evidence or evidence.expires <= now
            or evidence.identity_digest != admission.identity_digest):
        refuse('overlay_identity_unverified')
    return evidence


def attest(db, *, asset_id, model_id, firmware, evidence, actor, expires, now=None):
    stamp = time.time() if now is None else now
    if (not actor or not actor.strip() or not evidence or not evidence.strip()
            or type(expires) not in (float, int) or not math.isfinite(expires)
            or expires <= stamp):
        refuse('overlay_identity_unverified', 400)
    asset = db.get(Asset, asset_id)
    admission = latest_admission(db, asset_id)
    cap = db.get(Capability, model_id)
    from ..capability import firmware_in_range
    from .connection_config import _identity_digest
    if (not asset or not admission or admission.state != 'approved'
            or admission.identity_digest != _identity_digest(asset)
            or admission.expires <= stamp or admission.review_due <= stamp
            or admission.tenant_id not in (None, asset.tenant_id)
            or not cap or cap.profile_id != asset.profile_id
            or cap.tenant_id not in (None, asset.tenant_id) or cap.status != 'verified'
            or cap.expires <= stamp or not firmware_in_range(cap.__dict__, firmware)):
        refuse('overlay_identity_unverified')
    if db.get(DeviceIdentityEvidence, (asset_id, admission.revision)):
        refuse('overlay_evidence_immutable')
    row = DeviceIdentityEvidence(
        asset_id=asset_id, admission_revision=admission.revision,
        identity_digest=admission.identity_digest, model_id=model_id,
        firmware=firmware, evidence=evidence, attested_by=actor,
        expires=min(expires, admission.expires, admission.review_due, cap.expires))
    db.add(row)
    services.audit(db, actor, 'overlay_identity_attested', asset_id=asset_id,
                   tenant_id=asset.tenant_id, now=stamp,
                   detail={'admission_revision': admission.revision, 'model_id': model_id})
    db.flush()
    return row


def snapshot_material(db, asset_id):
    binding = db.get(AssetOverlayBinding, asset_id)
    if not binding:
        return None
    overlay = db.get(ProfileOverlay, binding.overlay_id)
    rev = db.get(ProfileOverlayRevision, (binding.overlay_id, binding.revision))
    if overlay is None or rev is None:
        refuse('overlay_binding_invalid')
    return {'overlay_id': overlay.id, 'overlay_revision': rev.revision,
            'tenant_id': overlay.tenant_id, 'base_profile_id': overlay.base_profile_id,
            'base_revision': rev.base_revision, 'state': rev.state,
            'subset': parse_json(rev.subset_json, {}),
            'capability_versions': parse_json(rev.base_versions_json, {})}


def check_asset(db, asset, *, now, operation='allocate', frozen=None, require_frozen=False):
    binding = db.get(AssetOverlayBinding, asset.id)
    if not binding:
        if frozen:
            refuse('overlay_binding_invalid')
        return None
    if require_frozen and not frozen:
        refuse('overlay_binding_invalid')
    overlay = db.get(ProfileOverlay, binding.overlay_id)
    if (not overlay or overlay.tenant_id != asset.tenant_id
            or overlay.base_profile_id != asset.profile_id
            or overlay.state == 'withdrawn'):
        refuse('overlay_not_active')
    draining = operation == 'renew' and overlay.state in ('disabled', 'needs_review')
    if draining:
        if (not frozen or frozen.get('overlay_id') != overlay.id
                or frozen.get('tenant_id') != asset.tenant_id):
            refuse('overlay_binding_invalid')
        revision = frozen.get('overlay_revision')
    else:
        if overlay.state != 'active' or binding.revision != overlay.current_revision:
            refuse('overlay_not_active')
        revision = binding.revision
    rev = db.get(ProfileOverlayRevision, (overlay.id, revision))
    if not rev or rev.state != 'active':
        refuse('overlay_not_active')
    try:
        subset = OverlaySubset.parse(parse_json(rev.subset_json, {}))
        profile = db.get(VendorProfile, overlay.base_profile_id)
        base, versions = approved_base(db, profile, subset, asset.tenant_id, now)
        if versions != parse_json(rev.base_versions_json, {}):
            refuse('overlay_base_revision_mismatch')
        policy = OverlayRevision(overlay.id, overlay.tenant_id, rev.revision,
                                 overlay.base_profile_id, rev.base_revision, 'active', subset)
        scope = effective_scope(base, policy, tenant_id=asset.tenant_id)
        identity = attested_identity(db, asset, now)
        if identity.model_id != asset.capability_id or not device_in_scope(
                scope, trusted_model_id=identity.model_id, trusted_firmware=identity.firmware):
            refuse('overlay_device_out_of_scope')
        material = digest_material(base, policy, tenant_id=asset.tenant_id)
        if frozen and (frozen.get('overlay_id') != overlay.id
                       or frozen.get('overlay_revision') != rev.revision):
            refuse('overlay_binding_invalid')
        return {'material': material, 'concurrency': scope.concurrency,
                'expires': min(identity.expires, profile.review_due), 'draining': draining,
                'identity': {'model': db.get(Capability, identity.model_id).model,
                             'vendor': db.get(Capability, identity.model_id).vendor,
                             'firmware': identity.firmware}}
    except OverlayError as exc:
        refuse(exc.code)


def save(db, *, tenant_id, user_id, profile_id, payload, expected_revision, now=None):
    stamp = time.time() if now is None else now
    actor_check(db, user_id, tenant_id)
    profile = db.scalar(select(VendorProfile).where(VendorProfile.id == profile_id)
                        .with_for_update())
    try:
        subset = OverlaySubset.parse(payload)
        base, versions = approved_base(db, profile, subset, tenant_id, stamp)
        overlay = db.scalar(select(ProfileOverlay).where(
            ProfileOverlay.tenant_id == tenant_id, ProfileOverlay.base_profile_id == profile_id)
                            .with_for_update())
        actual = overlay.current_revision if overlay else 0
        if type(expected_revision) is not int or expected_revision != actual:
            refuse('overlay_revision_conflict')
        if overlay and overlay.state == 'withdrawn':
            refuse('overlay_withdrawn')
        if not overlay:
            overlay = ProfileOverlay(id=str(uuid.uuid4()), tenant_id=tenant_id,
                base_profile_id=profile_id, current_revision=0, state='active')
            db.add(overlay)
            db.flush()
        next_revision = actual + 1
        policy = OverlayRevision(overlay.id, tenant_id, next_revision, profile_id,
                                 profile.revision, 'active', subset)
        effective_scope(base, policy, tenant_id=tenant_id)
        rev = ProfileOverlayRevision(overlay_id=overlay.id, revision=next_revision,
            base_revision=profile.revision, state='active', subset_json=json_field(payload),
            base_versions_json=json_field(versions), created_by=user_id, created=stamp)
        db.add(rev)
        overlay.current_revision, overlay.state = next_revision, 'active'
        db.flush()
        changed = _advance_bindings(db, overlay, next_revision)
        _changed(db, changed, user_id, 'overlay_changed', stamp,
                 tenant_id=tenant_id, overlay_id=overlay.id)
        return public(overlay, rev)
    except OverlayError as exc:
        refuse(exc.code, 400)


def _advance_bindings(db, overlay, revision):
    rows = db.scalars(select(AssetOverlayBinding).where(
        AssetOverlayBinding.overlay_id == overlay.id).order_by(AssetOverlayBinding.asset_id)
                      .with_for_update()).all()
    for row in rows:
        row.revision = revision
    db.flush()
    return [row.asset_id for row in rows]


def _changed(db, asset_ids, actor, reason, stamp, *, tenant_id, overlay_id):
    from .connection_config import record_change
    record_change(db, asset_ids=asset_ids, reason=reason, actor=actor,
                  now=stamp, create_pending=False)
    services.audit(db, actor, reason, now=stamp,
                   tenant_id=tenant_id, detail={'assets': asset_ids, 'overlay_id': overlay_id})
    db.flush()


def change_state(db, *, overlay_id, state, expected_revision, user_id,
                 tenant_id=None, platform=False, now=None):
    stamp = time.time() if now is None else now
    if platform:
        user = db.get(User, user_id)
        if not user or not user.is_active or user.tenant_id is not None:
            refuse('permission_denied', 403)
        services.require_platform(db, user_id, 'platform.asset.admit')
        if state != 'withdrawn':
            refuse('overlay_state_invalid', 400)
    else:
        actor_check(db, user_id, tenant_id)
        if state != 'disabled':
            refuse('overlay_state_invalid', 400)
    found = db.get(ProfileOverlay, overlay_id)
    if not found or (not platform and found.tenant_id != tenant_id):
        refuse('overlay_not_found', 404)
    db.scalar(select(VendorProfile).where(VendorProfile.id == found.base_profile_id)
              .with_for_update())
    overlay = db.scalar(select(ProfileOverlay).where(ProfileOverlay.id == overlay_id)
                        .with_for_update().execution_options(populate_existing=True))
    if overlay.state == 'withdrawn':
        refuse('overlay_withdrawn')
    if type(expected_revision) is not int or overlay.current_revision != expected_revision:
        refuse('overlay_revision_conflict')
    old = db.get(ProfileOverlayRevision, (overlay.id, overlay.current_revision))
    overlay.current_revision += 1
    overlay.state = state
    rev = ProfileOverlayRevision(overlay_id=overlay.id, revision=overlay.current_revision,
        base_revision=old.base_revision, state=state, subset_json=old.subset_json,
        base_versions_json=old.base_versions_json, created_by=user_id, created=stamp)
    db.add(rev)
    db.flush()
    changed = _advance_bindings(db, overlay, overlay.current_revision)
    _changed(db, changed, user_id, 'overlay_' + state, stamp,
             tenant_id=overlay.tenant_id, overlay_id=overlay.id)
    return public(overlay, rev)


def bind(db, *, asset_id, overlay_id, revision, user_id, tenant_id, now=None):
    stamp = time.time() if now is None else now
    actor_check(db, user_id, tenant_id)
    if type(overlay_id) is not str:
        refuse('overlay_binding_invalid', 400)
    overlay = db.get(ProfileOverlay, overlay_id)
    if not overlay or overlay.tenant_id != tenant_id:
        refuse('overlay_not_found', 404)
    db.scalar(select(VendorProfile).where(VendorProfile.id == overlay.base_profile_id)
              .with_for_update())
    db.refresh(overlay)
    asset = db.scalar(select(Asset).where(Asset.id == asset_id).with_for_update())
    if not asset or asset.tenant_id != tenant_id:
        refuse('asset_not_found', 404)
    if type(revision) is not int or revision != overlay.current_revision:
        refuse('overlay_revision_conflict')
    existing = db.get(AssetOverlayBinding, asset_id)
    if existing and existing.overlay_id != overlay_id:
        refuse('overlay_binding_invalid')
    if not existing:
        existing = AssetOverlayBinding(asset_id=asset_id, overlay_id=overlay_id, revision=revision)
        db.add(existing)
    else:
        existing.revision = revision
    db.flush()
    check_asset(db, asset, now=stamp)
    _changed(db, [asset_id], user_id, 'overlay_bound', stamp,
             tenant_id=tenant_id, overlay_id=overlay.id)
    return {'asset_id': asset_id, 'overlay_id': overlay_id, 'revision': revision}


def public(overlay, rev):
    return {'id': overlay.id, 'base_profile_id': overlay.base_profile_id,
            'revision': rev.revision, 'base_revision': rev.base_revision,
            'state': rev.state, **parse_json(rev.subset_json, {})}


def invalidate_sources(db, *, profile_id=None, capability_id=None, actor, now):
    cap = db.get(Capability, capability_id) if capability_id else None
    pid = profile_id or (cap.profile_id if cap else None)
    if not pid:
        return
    profile = db.scalar(select(VendorProfile).where(VendorProfile.id == pid).with_for_update())
    rows = db.scalars(select(ProfileOverlay).where(ProfileOverlay.base_profile_id == pid)
                       .order_by(ProfileOverlay.id).with_for_update()).all()
    for overlay in rows:
        if overlay.state == 'withdrawn':
            continue
        old = db.get(ProfileOverlayRevision, (overlay.id, overlay.current_revision))
        versions = parse_json(old.base_versions_json, {})
        if capability_id and capability_id not in versions:
            continue
        revoked = (profile.status != 'approved' if profile_id else cap.status != 'verified')
        changed = (old.base_revision != profile.revision if profile_id
                   else versions.get(capability_id) != cap.revision)
        if not revoked and not changed:
            continue
        state = 'withdrawn' if revoked else 'needs_review'
        overlay.current_revision += 1
        overlay.state = state
        db.add(ProfileOverlayRevision(overlay_id=overlay.id, revision=overlay.current_revision,
            base_revision=old.base_revision, state=state, subset_json=old.subset_json,
            base_versions_json=old.base_versions_json, created_by=actor, created=now))
        db.flush()
        assets = _advance_bindings(db, overlay, overlay.current_revision)
        _changed(db, assets, actor, 'overlay_' + state, now,
                 tenant_id=overlay.tenant_id, overlay_id=overlay.id)
