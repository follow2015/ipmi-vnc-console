"""Graded authorization: the terminal two-level chain (design 2026-11-18)."""
from __future__ import annotations

import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select

from kvmhub.common import BMC_BASE_URL, Problem
from kvmhub.platform import services
from kvmhub.platform.api import create_app
from kvmhub.platform.bus import AssemblyBus
from kvmhub.platform.config import Settings
from kvmhub.platform.console import ConsolePlane
from kvmhub.platform.db import (bootstrap_platform_admin, init_schema, seed_roles,
                                transaction)
from kvmhub.platform.models import AccessGrant, Asset
from kvmhub.platform.redis_state import MemoryState
from kvmhub.store import TENANT_GRANT, Store

KEY = b"0123456789abcdef0123456789abcdef"
BMC_PASSWORD = "synthetic-password"
FINGERPRINT = "ab1eed64" * 8
TARGET = "https://192.0.2.11"



@pytest.fixture
def plane_store(tmp_path):
    key = b"k" * 32
    path = tmp_path / "dp.sqlite"
    store = Store(path, key, clock=time.time)
    store.seed_mock(BMC_BASE_URL, FINGERPRINT, "fixture-user", BMC_PASSWORD)
    yield store
    store.close()


def test_no_per_user_grant_is_refused_in_strict_mode(plane_store):
    plane_store.strict_grants = True
    with pytest.raises(Problem, match="permission_denied"):
        plane_store.allocate("mock-1", "someone-new", "w1", "i1", "trace")
    with plane_store.tx():
        plane_store.put_grant("someone-new", "mock-1", time.time() + 3600)
    row = plane_store.allocate("mock-1", "someone-new", "w1", "i1", "trace")
    assert row["user_id"] == "someone-new"


def test_wildcard_is_inert_in_strict_mode(plane_store):
    with plane_store.tx():
        plane_store.put_grant(TENANT_GRANT, "mock-1", time.time() + 3600)
    plane_store.allocate("mock-1", "stranger", "w1", "i1", "trace")
    plane_store.strict_grants = True
    with pytest.raises(Problem, match="permission_denied"):
        plane_store.allocate("mock-1", "stranger", "w2", "i2", "trace")


def test_epoch_bump_ends_a_live_session_within_one_lease(plane_store):
    with plane_store.tx():
        plane_store.put_grant("u1", "mock-1", time.time() + 3600)
    row = plane_store.allocate("mock-1", "u1", "w1", "i1", "trace")
    sid = row["id"]
    claims = {"sid": row["id"], "sub": row["user_id"], "aid": row["asset_id"],
              "wid": row["worker_id"], "iid": row["instance_id"], "jti": row["jti"]}
    plane_store.exchange(claims, "trace")
    plane_store.renew(sid, "w1", "i1", activate=True, trace="trace")
    with plane_store.tx():
        new_epoch = plane_store.bump_subject_epoch("u1")
    assert new_epoch == 1
    with pytest.raises(Problem, match="session_revoked"):
        plane_store.renew(sid, "w1", "i1", activate=False, trace="trace")


def test_disabled_subject_is_refused_exchange(plane_store):
    with plane_store.tx():
        plane_store.put_grant("u1", "mock-1", time.time() + 3600)
        plane_store.set_subject_authz("u1", 0, 0)
    with pytest.raises(Problem, match="permission_denied"):
        plane_store.allocate("mock-1", "u1", "w1", "i1", "trace")



def _cfg(dsn: str, *, strict: bool = False) -> Settings:
    return Settings(env="test", db_url=dsn, redis_url="", credential_key=KEY,
                    session_ttl=3600, lease_seconds=30, bootstrap_admin=None,
                    bootstrap_password=None, strict_prod=False, strict_grants=strict)


@pytest.fixture
def rig(tmp_path):
    cfg = _cfg(f"sqlite:///{tmp_path}/control.db")
    state = MemoryState()
    bus = AssemblyBus(state)
    private = Ed25519PrivateKey.generate()
    data_db = tmp_path / "dp.db"

    def connect() -> Store:
        return Store(str(data_db), KEY)

    plane = ConsolePlane(store_factory=connect, private_key=private, bus=bus,
                         accept_template="https://{worker_id}-{sid}.kvm.localhost:9443/_platform/accept")
    app = create_app(cfg, state=state, plane=plane)
    platform = app.state.platform
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        tenant = services.create_tenant(db, code="acme", name="Acme", actor="t")
        other = services.create_tenant(db, code="other", name="Other", actor="t")
        admin = services.create_user(db, "acme-admin", "synthetic-password", "admin", actor="t", tenant_id=tenant.id)
        operator = services.create_user(db, "acme-op", "synthetic-password", "operator", actor="t", tenant_id=tenant.id)
        other_user = services.create_user(db, "other-user", "synthetic-password", "viewer", actor="t", tenant_id=other.id)
        asset = Asset(id=str(uuid.uuid4()), tenant_id=tenant.id, name="n1", address="10.0.0.1",
                      created=time.time(), updated=time.time())
        db.add(asset)
        db.flush()
        ids = {"tenant": tenant.id, "other": other.id, "admin": admin.id,
               "operator": operator.id, "other_user": other_user.id, "asset": asset.id}
    yield app, platform, plane, ids
    platform.engine.dispose()


class FailingPlane:
    def write_grant(self, *args, **kwargs):
        raise RuntimeError("data plane down")

    def delete_grant(self, *args, **kwargs):
        raise RuntimeError("data plane down")

    def bump_subject_epoch(self, *args, **kwargs):
        raise RuntimeError("data plane down")


def test_data_plane_failure_leaves_no_platform_grant(rig):
    app, platform, plane, ids = rig
    with transaction(platform.factory) as db:
        before = db.scalar(select(func.count()).select_from(AccessGrant))
        with pytest.raises(RuntimeError, match="data plane down"):
            services.grant_asset(db, user_id=ids["operator"], asset_id=ids["asset"],
                                 actor="acme-admin", tenant_id=ids["tenant"],
                                 plane=FailingPlane())
        after = db.scalar(select(func.count()).select_from(AccessGrant))
    assert after == before


def test_cross_tenant_grant_is_refused(rig):
    app, platform, plane, ids = rig
    with transaction(platform.factory) as db:
        with pytest.raises(services.PlatformError) as exc:
            services.grant_asset(db, user_id=ids["other_user"], asset_id=ids["asset"],
                                 actor="t", tenant_id=ids["tenant"])
        assert exc.value.code == "grant_target_missing"
        with pytest.raises(services.PlatformError) as exc:
            services.grant_asset(db, user_id=ids["operator"], asset_id=ids["asset"],
                                 actor="t", tenant_id=ids["other"])
        assert exc.value.code == "grant_target_missing"


def test_tenant_grantor_cannot_share_an_asset_it_does_not_hold(rig):
    app, platform, plane, ids = rig
    with transaction(platform.factory) as db:
        with pytest.raises(services.PlatformError) as exc:
            services.grant_asset(db, user_id=ids["operator"], asset_id=ids["asset"],
                                 actor="acme-admin", tenant_id=ids["tenant"],
                                 actor_user_id=ids["admin"])
        assert exc.value.code == "grantor_not_authorized"


def test_platform_principal_is_exempt_from_the_grantor_check(rig):
    app, platform, plane, ids = rig
    with transaction(platform.factory) as db:
        plat = bootstrap_platform_admin(db, "root", "synthetic-password")
        services.grant_asset(db, user_id=ids["operator"], asset_id=ids["asset"],
                             actor="root", tenant_id=ids["tenant"],
                             actor_user_id=plat.id)
        row = db.get(AccessGrant, (ids["operator"], ids["asset"]))
    assert row is not None


def test_reassign_clears_every_grant_on_the_asset(rig):
    app, platform, plane, ids = rig
    with transaction(platform.factory) as db:
        services.grant_asset(db, user_id=ids["admin"], asset_id=ids["asset"],
                             actor="t", tenant_id=ids["tenant"])
        services.grant_asset(db, user_id=ids["operator"], asset_id=ids["asset"],
                             actor="t", tenant_id=ids["tenant"])
        result = services.assign_asset(db, address="10.0.0.1", tenant_id=ids["other"],
                                       actor="t", reassign=True, plane=plane)
    assert result["action"] == "moved"
    with transaction(platform.factory) as db:
        remaining = db.scalars(select(AccessGrant).where(
            AccessGrant.asset_id == ids["asset"])).all()
    assert remaining == []



class SpyPlane:

    def __init__(self):
        self.disabled, self.bumped = [], []

    def revoke_subject(self, user_id, trace=""):
        self.disabled.append(user_id)

    def bump_subject_epoch(self, user_id, console_allowed=None, trace=""):
        self.bumped.append(user_id)
        return 1

    def write_grant(self, *a, **k):
        pass

    def delete_grant(self, *a, **k):
        pass


def test_disabling_a_user_cascades_revoke(rig):
    app, platform, plane, ids = rig
    spy = SpyPlane()
    with transaction(platform.factory) as db:
        services.set_user_active(db, ids["operator"], False, actor="t",
                                 tenant_id=ids["tenant"], plane=spy)
    assert ids["operator"] in spy.disabled


def test_role_downgrade_bumps_epoch_but_promotion_does_not(rig):
    app, platform, plane, ids = rig
    spy = SpyPlane()
    with transaction(platform.factory) as db:
        services.set_user_role(db, ids["operator"], "admin", actor="t", plane=spy)
    assert ids["operator"] not in spy.bumped
    with transaction(platform.factory) as db:
        services.set_user_role(db, ids["operator"], "viewer", actor="t", plane=spy)
    assert ids["operator"] in spy.bumped


def test_suspending_a_tenant_disables_all_its_subjects(rig):
    app, platform, plane, ids = rig
    spy = SpyPlane()
    with transaction(platform.factory) as db:
        row = services.set_tenant_status(db, ids["tenant"], "suspended", actor="t", plane=spy)
    assert row.status == "suspended"
    assert set(spy.disabled) == {ids["admin"], ids["operator"]}
    assert ids["other_user"] not in spy.disabled


def test_downgrade_reason_survives_worker_finish(plane_store):
    with plane_store.tx():
        plane_store.put_grant("u1", "mock-1", time.time() + 3600)
    row = plane_store.allocate("mock-1", "u1", "w1", "i1", "trace")
    claims = {"sid": row["id"], "sub": row["user_id"], "aid": row["asset_id"],
              "wid": row["worker_id"], "iid": row["instance_id"], "jti": row["jti"]}
    plane_store.exchange(claims, "trace")
    plane_store.renew(row["id"], "w1", "i1", activate=True, trace="trace")
    with plane_store.tx():
        plane_store.bump_subject_epoch("u1")
    with pytest.raises(Problem, match="session_revoked"):
        plane_store.renew(row["id"], "w1", "i1", trace="trace")
    assert plane_store.get(row["id"])["reason"] == "role_downgraded"
    plane_store.finish(row["id"], "w1", "i1", "confirmed", "revoked", trace="trace")
    assert plane_store.get(row["id"])["reason"] == "role_downgraded"
