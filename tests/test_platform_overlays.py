"""O1: real DB revisions, identity evidence, atomic projection and G1 gates."""
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from sqlalchemy import select, func

from kvmhub.common import Problem
from kvmhub.platform import admission_api, connection, connection_config, overlays, services
from kvmhub.platform.db import init_schema, make_engine, seed_roles, session_factory, transaction
from kvmhub.platform.models import (AccessGrant, Asset, AssetConnection, AssetOverlayBinding,
    Capability, Credential, DeviceAdmission, DEFAULT_TENANT_ID, DeviceIdentityEvidence,
    ExecutionDomain, PlaneOutbox, PlaneProjection, ProfileOverlay, ProfileOverlayRevision,
    Role, Tenant, User, UserRole, VendorProfile, parse_json)

T = DEFAULT_TENANT_ID


@pytest.fixture
def rig(tmp_path):
    engine = make_engine(f'sqlite:///{tmp_path}/overlay.db')
    init_schema(engine)
    factory = session_factory(engine)
    now = time.time()
    with transaction(factory) as db:
        seed_roles(db)
        db.add(Tenant(id='other', code='other', created=now))
        for uid, role, tenant in [('admin', 'admin', T), ('operator', 'operator', T),
                                  ('foreign', 'admin', 'other'), ('staff', 'platform_admin', None)]:
            db.add(User(id=uid, tenant_id=tenant, username=uid, password_hash='x',
                        created=now, is_active=True))
            rid = db.scalar(select(Role.id).where(Role.code == role))
            db.add(UserRole(user_id=uid, role_id=rid))
        db.add(VendorProfile(id='profile', code='test', vendor='Huawei', created=now,
            status='approved', revision=4, review_due=now+10000, approver='ops', evidence='measured',
            concurrency_limit=4, firmware_min='6.20', firmware_max='6.40',
            console_impl='huawei-ibmc-kvm-gateway', rfb_version='RFB 003.008',
            message_profile='standard'))
        db.add(Capability(id='model-a', profile_id='profile', vendor='Huawei', model='2288H V5',
            firmware='6.27', firmware_min='6.20', firmware_max='6.40', revision=3,
            adapter='huawei-ibmc-kvm-gateway', status='verified', evidence='measured',
            approver='ops', expires=now+10000, created=now))
        db.add(Credential(id='cred', tenant_id=T, label='bmc', username_cipher=b'u',
                          password_cipher=b'p', key_version=1, created=now))
        db.flush()
        db.add(Asset(id='asset', tenant_id=T, name='node', address='192.0.2.3',
            profile_id='profile', capability_id='model-a', credential_id='cred',
            vendor='Huawei', model='untrusted display', firmware='99.99',
            fingerprint='a'*64, created=now, updated=now))
        db.add(AccessGrant(user_id='admin', asset_id='asset', tenant_id=T, created=now, expires=now+10000))
        db.add(ExecutionDomain(domain_id='domain', store_id='store', endpoint='https://local.invalid',
            generation='gen', policy_fingerprint='policy', health='healthy'))
        db.flush()
        connection_config.admit_asset(db, asset_id='asset', tenant_id=T, approver='ops',
            evidence='measured', review_due=now+9000, expires=now+9000,
            domain_id='domain', actor='ops', now=now)
        overlays.attest(db, asset_id='asset', model_id='model-a', firmware='6.27',
            evidence='measured.json', actor='ops', expires=now+3000, now=now)
    key = tmp_path / 'signing.key'
    key.write_bytes(Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    yield SimpleNamespace(factory=factory, engine=engine, now=now, key=str(key))
    engine.dispose()


def payload():
    return {'model_subset': ['model-a'], 'firmware_subset': {'min': '6.25', 'max': '6.30'},
            'concurrency': 2}


def save(rig, db, **kwargs):
    args = dict(tenant_id=T, user_id='admin', profile_id='profile', payload=payload(),
                expected_revision=0, now=rig.now)
    args.update(kwargs)
    return overlays.save(db, **args)


def bound(rig):
    with transaction(rig.factory) as db:
        row = save(rig, db)
        overlays.bind(db, asset_id='asset', overlay_id=row['id'], revision=1,
                       user_id='admin', tenant_id=T, now=rig.now)
    return row['id']


def ack(db):
    conn = db.scalar(select(AssetConnection).where(AssetConnection.asset_id == 'asset')
                     .order_by(AssetConnection.revision.desc()).limit(1))
    projection = db.scalar(select(PlaneProjection).where(PlaneProjection.asset_id == 'asset'))
    projection.applied_revision = conn.revision
    projection.applied_digest = conn.digest
    projection.generation = 'gen'
    projection.policy_fingerprint = 'policy'
    projection.status = 'ready'
    db.flush()
    return conn


def auth(rig, db, conn, op='allocate'):
    adm = overlays.latest_admission(db, 'asset')
    return admission_api.authorize(db, principal='platform', operation=op, sid='s'*32,
        asset_id='asset', user_id='admin', tenant_id=T, domain_id='domain', worker_id='worker',
        instance_id='instance', connection_revision=conn.revision, admission_revision=adm.revision,
        digest=conn.digest, generation='gen', session_started_at=rig.now,
        hard_until=rig.now+10000, signing_key=rig.key, now=rig.now)


def test_revision_history_cas_and_unique_overlay(rig):
    with transaction(rig.factory) as db:
        first = save(rig, db)
        second = save(rig, db, expected_revision=1)
        assert first['id'] == second['id'] and second['revision'] == 2
        assert db.scalar(select(func.count()).select_from(ProfileOverlay)) == 1
        old = db.get(ProfileOverlayRevision, (first['id'], 1))
        assert old.state == 'active' and old.revision == 1
    with pytest.raises(services.PlatformError, match='revision_conflict'):
        with transaction(rig.factory) as db:
            save(rig, db, expected_revision=1)


@pytest.mark.parametrize('user,tenant', [('operator', T), ('foreign', T), ('admin', 'other')])
def test_service_rbac_and_cross_tenant_checks(rig, user, tenant):
    with pytest.raises(services.PlatformError, match='permission_denied'):
        with transaction(rig.factory) as db:
            save(rig, db, user_id=user, tenant_id=tenant)


def test_consumer_tenant_cannot_edit_overlay(rig):
    with transaction(rig.factory) as db:
        db.get(Tenant, T).mode = 'consumer'
    with pytest.raises(services.PlatformError, match='permission_denied'):
        with transaction(rig.factory) as db:
            save(rig, db)


def test_bind_changes_digest_and_uses_attestation_not_display_text(rig):
    with rig.factory() as db:
        old = db.scalar(select(AssetConnection.digest))
    oid = bound(rig)
    with transaction(rig.factory) as db:
        conn = ack(db)
        assert conn.digest != old
        frozen = parse_json(conn.source_versions_json, {})['overlay']
        assert frozen['overlay_id'] == oid and frozen['capability_versions'] == {'model-a': 3}
        assert auth(rig, db, conn)['permit']
        asset = db.get(Asset, 'asset')
        asset.model, asset.firmware = 'made-up-model', 'not-a-version'
        assert overlays.check_asset(db, asset, now=rig.now)['concurrency'] == 2


def test_missing_or_stale_evidence_and_endpoint_change_refuse(rig):
    oid = bound(rig)
    with transaction(rig.factory) as db:
        db.get(Asset, 'asset').address = '192.0.2.4'
    with rig.factory() as db:
        with pytest.raises(services.PlatformError, match='identity_unverified'):
            overlays.check_asset(db, db.get(Asset, 'asset'), now=rig.now)


@pytest.mark.parametrize('target,change', [
    ('profile', {'revision': 5}), ('profile', {'status': 'suspended'}),
    ('capability', {'revision': 4}), ('capability', {'status': 'retired'}),
    ('capability', {'expires': 0}),
])
def test_base_changes_or_withdrawal_never_fall_back(rig, target, change):
    bound(rig)
    with transaction(rig.factory) as db:
        obj = db.get(VendorProfile, 'profile') if target == 'profile' else db.get(Capability, 'model-a')
        for key, value in change.items():
            setattr(obj, key, value)
    with rig.factory() as db:
        with pytest.raises(services.PlatformError):
            overlays.check_asset(db, db.get(Asset, 'asset'), now=rig.now)


def test_binding_and_snapshot_and_outbox_rollback_together(rig, monkeypatch):
    with transaction(rig.factory) as db:
        row = save(rig, db)
        before = db.scalar(select(func.count()).select_from(PlaneOutbox))
    def fail(*args, **kwargs):
        raise RuntimeError('injected')
    monkeypatch.setattr(connection_config, 'audit', fail)
    with pytest.raises(RuntimeError, match='injected'):
        with transaction(rig.factory) as db:
            overlays.bind(db, asset_id='asset', overlay_id=row['id'], revision=1,
                user_id='admin', tenant_id=T, now=rig.now)
    with rig.factory() as db:
        assert db.get(AssetOverlayBinding, 'asset') is None
        assert db.scalar(select(func.count()).select_from(PlaneOutbox)) == before


def test_disable_drains_only_frozen_renewals_and_reenable_creates_revision(rig):
    oid = bound(rig)
    with transaction(rig.factory) as db:
        old = ack(db)
        auth(rig, db, old)
        overlays.change_state(db, overlay_id=oid, state='disabled', expected_revision=1,
                              user_id='admin', tenant_id=T, now=rig.now)
        ack(db)
        assert auth(rig, db, old, op='renew')['permit']
        for op in ('allocate', 'exchange', 'reconnect', 'recover'):
            with pytest.raises(Problem, match='device_not_admitted'):
                auth(rig, db, old, op=op)
        row = save(rig, db, expected_revision=2)
        assert row['revision'] == 3
        assert db.get(ProfileOverlayRevision, (oid, 2)).state == 'disabled'


def test_platform_withdrawal_blocks_old_permits_and_is_terminal(rig):
    oid = bound(rig)
    with transaction(rig.factory) as db:
        old = ack(db)
        overlays.change_state(db, overlay_id=oid, state='withdrawn', expected_revision=1,
                              user_id='staff', platform=True, now=rig.now)
        for op in ('allocate', 'renew', 'recover'):
            with pytest.raises(Problem, match='device_not_admitted'):
                auth(rig, db, old, op=op)
    with pytest.raises(services.PlatformError, match='withdrawn'):
        with transaction(rig.factory) as db:
            save(rig, db, expected_revision=2)


def test_cannot_exchange_old_unrestricted_snapshot_after_binding(rig):
    with rig.factory() as db:
        old_id = db.scalar(select(AssetConnection.id))
    bound(rig)
    with transaction(rig.factory) as db:
        ack(db)
        with pytest.raises(Problem, match='device_not_admitted'):
            auth(rig, db, db.get(AssetConnection, old_id), op='exchange')


def test_evidence_is_immutable_and_expiry_limits_permits(rig):
    with pytest.raises(services.PlatformError, match='evidence_immutable'):
        with transaction(rig.factory) as db:
            overlays.attest(db, asset_id='asset', model_id='model-a', firmware='6.27',
                evidence='another', actor='ops', expires=rig.now+20, now=rig.now)
    bound(rig)
    with transaction(rig.factory) as db:
        conn = ack(db)
        db.get(DeviceIdentityEvidence, ('asset', 1)).expires = rig.now+5
        assert auth(rig, db, conn)['lease_not_after'] == rig.now+5


def test_tenant_cannot_request_platform_withdrawal(rig):
    oid = bound(rig)
    with pytest.raises(services.PlatformError, match='permission_denied'):
        with transaction(rig.factory) as db:
            overlays.change_state(db, overlay_id=oid, state='withdrawn', expected_revision=1,
                                  user_id='admin', platform=True, now=rig.now)


def test_assembly_uses_trusted_identity_and_effective_limit(rig):
    bound(rig)
    with transaction(rig.factory) as db:
        ack(db)
        result = connection.assembly(db, asset_id='asset', user_id='admin', actor='admin',
                                     tenant_id=T, now=rig.now)
        entry = result['data_plane']['capability_entry']
        assert (entry['model'], entry['firmware']) == ('2288H V5', '6.27')
        assert entry['concurrency_limit'] == 2
        assert result['checks']['overlay'] == 'verified_subset'


def test_http_crud_csrf_and_platform_withdrawal(rig):
    from fastapi.testclient import TestClient
    from kvmhub.platform.api import create_app
    from kvmhub.platform.config import Settings
    from kvmhub.platform.redis_state import MemoryState
    from kvmhub.platform.security import hash_password
    password = 'synthetic-password'
    hashed = hash_password(password)
    with transaction(rig.factory) as db:
        for uid in ('admin', 'operator', 'staff'):
            db.get(User, uid).password_hash = hashed
    cfg = Settings(env='test', db_url=str(rig.engine.url), redis_url='',
        credential_key=b'0123456789abcdef0123456789abcdef', session_ttl=3600,
        lease_seconds=30, bootstrap_admin=None, bootstrap_password=None, strict_prod=False)
    app = create_app(cfg, state=MemoryState())
    with TestClient(app, base_url='http://testserver') as client:
        def login(uid, platform=False):
            client.cookies.clear()
            path = '/api/v2/platform/login' if platform else '/api/v2/login'
            response = client.post(path, json={'username': uid, 'password': password})
            assert response.status_code == 200, response.text
            return {'Origin': 'http://testserver', 'X-CSRF-Token': response.json()['csrf']}
        h = login('operator')
        assert client.get('/api/v2/profile-overlays', headers=h).status_code == 403
        h = login('admin')
        body = {'expected_revision': 0, 'subset': payload()}
        assert client.put('/api/v2/profile-overlays/profile', json=body).status_code == 403
        response = client.put('/api/v2/profile-overlays/profile', json=body, headers=h)
        assert response.status_code == 200, response.text
        oid = response.json()['id']
        assert client.get('/api/v2/profile-overlays', headers=h).json()[0]['id'] == oid
        assert client.put('/api/v2/assets/asset/profile-overlay', headers=h,
                          json={'overlay_id': oid, 'revision': 1}).status_code == 200
        assert client.put('/api/v2/profile-overlays/profile', json=body, headers=h).status_code == 409
        assert client.post(f'/api/v2/profile-overlays/{oid}/disable', headers=h,
                           json={'expected_revision': 1}).status_code == 200
        h = login('staff', platform=True)
        response = client.post(f'/api/v2/platform/profile-overlays/{oid}/withdraw',
                               headers=h, json={'expected_revision': 2})
        assert response.status_code == 200, response.text
        assert response.json()['state'] == 'withdrawn'


def test_overlay_cli_has_explicit_measured_identity_and_no_attest_http_route():
    from tools.platform_admin import parser
    with pytest.raises(SystemExit):
        parser().parse_args(['attest-overlay-identity', '--asset', 'asset'])
    args = parser().parse_args(['attest-overlay-identity', '--asset', 'asset',
        '--model-id', 'model-a', '--firmware', '6.27', '--approver', 'ops',
        '--evidence', 'measured.json', '--expires', '2000000000'])
    assert args.approver == 'ops' and args.model_id == 'model-a'


def test_source_changes_append_review_revision_and_require_explicit_reproof(rig):
    oid = bound(rig)
    with transaction(rig.factory) as db:
        db.get(VendorProfile, 'profile').revision += 1
        overlays.invalidate_sources(db, profile_id='profile', actor='ops', now=rig.now)
        row = db.get(ProfileOverlay, oid)
        assert row.current_revision == 2 and row.state == 'needs_review'
        assert db.get(ProfileOverlayRevision, (oid, 1)).state == 'active'
        assert db.get(AssetOverlayBinding, 'asset').revision == 2
        assert save(rig, db, expected_revision=2)['revision'] == 3


def test_base_withdrawal_appends_terminal_tombstone(rig):
    oid = bound(rig)
    with transaction(rig.factory) as db:
        db.get(Capability, 'model-a').status = 'suspended'
        overlays.invalidate_sources(db, capability_id='model-a', actor='ops', now=rig.now)
        assert db.get(ProfileOverlay, oid).state == 'withdrawn'
        conn = ack(db)
        with pytest.raises(Problem, match='device_not_admitted'):
            auth(rig, db, conn, op='renew')


def test_identity_expiry_and_revision_timestamp_retain_double_precision_on_mysql():
    from sqlalchemy.dialects import mysql
    for column in (DeviceIdentityEvidence.__table__.c.expires,
                   ProfileOverlayRevision.__table__.c.created):
        assert column.type.compile(dialect=mysql.dialect()) == 'FLOAT(53)'
