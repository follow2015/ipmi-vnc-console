"""P3 asset groups: batch authorization expands to per-asset grants."""
from __future__ import annotations

import time
import uuid

import pytest
from sqlalchemy import func, select

from kvmhub.platform import services
from kvmhub.platform.config import Settings
from kvmhub.platform.db import init_schema, seed_roles, transaction
from kvmhub.platform.models import (AccessGrant, Asset, AssetGroup, GrantSource,
                                    Tenant, User)
from kvmhub.store import Store

KEY = b"0123456789abcdef0123456789abcdef"


class SpyPlane:
    def __init__(self):
        self.written, self.deleted = [], []

    def write_grant(self, user, asset, expires, trace=""):
        self.written.append((user, asset))

    def delete_grant(self, user, asset, trace=""):
        self.deleted.append((user, asset))


@pytest.fixture
def rig(tmp_path):
    cfg = Settings(env="test", db_url=f"sqlite:///{tmp_path}/c.db", redis_url="",
                   credential_key=KEY, session_ttl=3600, lease_seconds=30,
                   bootstrap_admin=None, bootstrap_password=None, strict_prod=False)
    from kvmhub.platform.db import make_engine, session_factory
    engine = make_engine(cfg.db_url)
    factory = session_factory(engine)
    init_schema(engine)
    with transaction(factory) as db:
        seed_roles(db)
        tenant = services.create_tenant(db, code="g", name="G", actor="t")
        user = services.create_user(db, "u", "synthetic-password", "operator",
                                    actor="t", tenant_id=tenant.id)
        assets = []
        for i in range(3):
            a = Asset(id=str(uuid.uuid4()), tenant_id=tenant.id, name=f"n{i}",
                      address=f"10.0.0.{i+1}", created=time.time(), updated=time.time())
            db.add(a)
            assets.append(a)
        db.flush()
        ids = {"tenant": tenant.id, "user": user.id, "assets": [a.id for a in assets]}
    yield factory, engine, ids
    engine.dispose()


def test_group_grant_expands_one_row_per_member(rig):
    factory, engine, ids = rig
    spy = SpyPlane()
    with transaction(factory) as db:
        group = services.create_asset_group(db, name="rack1", actor="t", tenant_id=ids["tenant"])
        services.set_group_members(db, group_id=group.id, asset_ids=ids["assets"][:2],
                                   actor="t", tenant_id=ids["tenant"])
        result = services.grant_group(db, group_id=group.id, user_id=ids["user"],
                                      actor="t", tenant_id=ids["tenant"], plane=spy)
    assert result["granted"] == 2
    assert set(spy.written) == {(ids["user"], a) for a in ids["assets"][:2]}
    with transaction(factory) as db:
        grants = db.scalars(select(AccessGrant).where(AccessGrant.user_id == ids["user"])).all()
        assert {g.asset_id for g in grants} == set(ids["assets"][:2])
        sources = db.scalars(select(GrantSource).where(GrantSource.user_id == ids["user"])).all()
        assert len(sources) == 2


def test_group_out_asset_is_never_opened_by_group_grant(rig):
    factory, engine, ids = rig
    spy = SpyPlane()
    with transaction(factory) as db:
        group = services.create_asset_group(db, name="rack1", actor="t", tenant_id=ids["tenant"])
        services.set_group_members(db, group_id=group.id, asset_ids=ids["assets"][:1],
                                   actor="t", tenant_id=ids["tenant"])
        services.grant_group(db, group_id=group.id, user_id=ids["user"],
                             actor="t", tenant_id=ids["tenant"], plane=spy)
    assert ids["assets"][2] not in [a for _, a in spy.written]


def test_reexpansion_revokes_only_group_sourced_rows(rig):
    factory, engine, ids = rig
    spy = SpyPlane()
    with transaction(factory) as db:
        group = services.create_asset_group(db, name="rack1", actor="t", tenant_id=ids["tenant"])
        services.set_group_members(db, group_id=group.id, asset_ids=ids["assets"][:2],
                                   actor="t", tenant_id=ids["tenant"])
        services.grant_group(db, group_id=group.id, user_id=ids["user"],
                             actor="t", tenant_id=ids["tenant"], plane=spy)
        services.grant_asset(db, user_id=ids["user"], asset_id=ids["assets"][1],
                             actor="t", tenant_id=ids["tenant"])
    spy.deleted.clear()
    with transaction(factory) as db:
        services.set_group_members(db, group_id=group.id, asset_ids=ids["assets"][:1],
                                   actor="t", tenant_id=ids["tenant"])
        result = services.grant_group(db, group_id=group.id, user_id=ids["user"],
                                      actor="t", tenant_id=ids["tenant"], plane=spy)
    assert result["revoked_stale"] == 1
    assert (ids["user"], ids["assets"][1]) not in spy.deleted
    with transaction(factory) as db:
        grant = db.get(AccessGrant, (ids["user"], ids["assets"][1]))
        assert grant is not None


def test_reexpansion_with_no_other_source_revokes(rig):
    factory, engine, ids = rig
    spy = SpyPlane()
    with transaction(factory) as db:
        group = services.create_asset_group(db, name="rack1", actor="t", tenant_id=ids["tenant"])
        services.set_group_members(db, group_id=group.id, asset_ids=ids["assets"][:2],
                                   actor="t", tenant_id=ids["tenant"])
        services.grant_group(db, group_id=group.id, user_id=ids["user"],
                             actor="t", tenant_id=ids["tenant"], plane=spy)
    spy.deleted.clear()
    with transaction(factory) as db:
        services.set_group_members(db, group_id=group.id, asset_ids=ids["assets"][:1],
                                   actor="t", tenant_id=ids["tenant"])
        services.grant_group(db, group_id=group.id, user_id=ids["user"],
                             actor="t", tenant_id=ids["tenant"], plane=spy)
    assert (ids["user"], ids["assets"][1]) in spy.deleted
    with transaction(factory) as db:
        assert db.get(AccessGrant, (ids["user"], ids["assets"][1])) is None


def test_cross_tenant_asset_cannot_join_group(rig):
    factory, engine, ids = rig
    with transaction(factory) as db:
        group = services.create_asset_group(db, name="rack1", actor="t", tenant_id=ids["tenant"])
        with pytest.raises(services.PlatformError) as exc:
            services.set_group_members(db, group_id=group.id,
                                       asset_ids=[str(uuid.uuid4())],
                                       actor="t", tenant_id=ids["tenant"])
        assert exc.value.code == "group_asset_foreign"


def test_delete_group_turns_grants_into_per_asset(rig):
    factory, engine, ids = rig
    with transaction(factory) as db:
        group = services.create_asset_group(db, name="rack1", actor="t", tenant_id=ids["tenant"])
        services.set_group_members(db, group_id=group.id, asset_ids=ids["assets"][:1],
                                   actor="t", tenant_id=ids["tenant"])
        services.grant_group(db, group_id=group.id, user_id=ids["user"],
                             actor="t", tenant_id=ids["tenant"])
        services.delete_asset_group(db, group_id=group.id, actor="t", tenant_id=ids["tenant"])
        grant = db.get(AccessGrant, (ids["user"], ids["assets"][0]))
        assert grant is not None
        src = db.scalar(select(GrantSource).where(GrantSource.asset_id == ids["assets"][0]))
        assert src.group_id is None
