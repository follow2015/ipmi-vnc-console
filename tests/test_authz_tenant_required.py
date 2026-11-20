"""Tenant-namespace permission checks must always carry a tenant."""
from __future__ import annotations

import ast
import pathlib

import pytest

from kvmhub.platform import services
from kvmhub.platform.db import init_schema, seed_roles, transaction
from kvmhub.platform.models import DEFAULT_TENANT_ID, Tenant

ROOT = pathlib.Path(__file__).resolve().parents[1] / "kvmhub"


def _calls(name: str):
    for path in sorted(ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            called = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if called == name:
                yield path.relative_to(ROOT.parent), node


def test_every_require_call_passes_a_tenant_id():
    calls = list(_calls("require"))
    assert calls, "scan found no require() calls; the test is stale"
    missing = [f"{path}:{node.lineno}" for path, node in calls
               if not any(k.arg == "tenant_id" for k in node.keywords)]
    assert not missing, f"require() without tenant_id: {missing}"


def test_require_platform_is_only_used_with_platform_codes():
    calls = list(_calls("require_platform"))
    assert calls
    bad = []
    for path, node in calls:
        code = node.args[2] if len(node.args) > 2 else None
        if isinstance(code, ast.Constant) and not str(code.value).startswith("platform."):
            bad.append(f"{path}:{node.lineno}")
    assert not bad, bad


@pytest.fixture
def db():
    from kvmhub.platform.config import Settings
    from kvmhub.platform.api import create_app
    from kvmhub.platform.redis_state import MemoryState
    cfg = Settings(env="test", db_url="sqlite:///:memory:", redis_url="",
                   credential_key=b"0123456789abcdef0123456789abcdef", session_ttl=3600,
                   lease_seconds=30, bootstrap_admin=None, bootstrap_password=None,
                   strict_prod=False)
    platform = create_app(cfg, state=MemoryState()).state.platform
    with transaction(platform.factory) as session:
        init_schema(platform.engine)
        seed_roles(session)
        yield session


def test_require_refuses_a_missing_tenant(db):
    admin = services.create_user(db, "a", "synthetic-password", "admin", actor="test")
    with pytest.raises(TypeError):
        services.require(db, admin.id, "asset.write")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        services.require(db, admin.id, "asset.write", tenant_id=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        services.require(db, admin.id, "platform.tenant.read", tenant_id=DEFAULT_TENANT_ID)


def test_consumer_mode_caps_an_admin_role(db):
    admin = services.create_user(db, "a", "synthetic-password", "admin", actor="test")
    db.get(Tenant, DEFAULT_TENANT_ID).mode = "consumer"
    db.flush()
    services.require(db, admin.id, "console.close", tenant_id=DEFAULT_TENANT_ID)
    with pytest.raises(services.PlatformError, match="permission_denied"):
        services.require(db, admin.id, "asset.write", tenant_id=DEFAULT_TENANT_ID)


def test_require_platform_refuses_tenant_codes(db):
    admin = services.create_user(db, "a", "synthetic-password", "admin", actor="test")
    with pytest.raises(ValueError):
        services.require_platform(db, admin.id, "asset.write")
