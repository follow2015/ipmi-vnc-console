"""Out-of-band password recovery for a forgotten superuser credential."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from kvmhub.platform import services
from kvmhub.platform.api import create_app
from kvmhub.platform.config import Settings
from kvmhub.platform.db import bootstrap_platform_admin, init_schema, make_engine, seed_roles, session_factory, transaction
from kvmhub.platform.models import User
from kvmhub.platform.redis_state import MemoryState
from kvmhub.platform.security import verify_password
from tools import platform_admin as cli

KEY = b"0123456789abcdef0123456789abcdef"
OLD = "old-synthetic-password"
NEW = "new-synthetic-password"
ORIGIN = "http://testserver"


def cfg_for(db_url: str) -> Settings:
    return Settings(env="test", db_url=db_url, redis_url="", credential_key=KEY,
                    session_ttl=3600, lease_seconds=30, bootstrap_admin=None,
                    bootstrap_password=None, strict_prod=False)


@pytest.fixture
def rig(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path}/control.db"
    cfg = cfg_for(db_url)
    engine = make_engine(db_url)
    factory = session_factory(engine)
    state = MemoryState()
    with transaction(factory) as db:
        init_schema(engine)
        seed_roles(db)
        bootstrap_platform_admin(db, "platform", OLD)
        globex = services.create_tenant(db, code="globex", name="Globex", actor="test")
        services.create_user(db, "g-admin", OLD, "admin", actor="test", tenant_id=globex.id)

    class SharedStateView:
        def __getattr__(self, name):
            return getattr(state, name)

        async def close(self):
            pass

    monkeypatch.setattr(cli, "_context", lambda args: (cfg, engine, factory, None))
    monkeypatch.setattr(cli, "create_state", lambda url: SharedStateView())
    monkeypatch.setenv("KVMHUB_NEW_PASSWORD", NEW)

    app = create_app(cfg, state=state, plane=None)
    yield SimpleNamespace(engine=engine, factory=factory, state=state,
                          client=TestClient(app, base_url=ORIGIN))
    engine.dispose()


def args(username: str, tenant: str = "", generate: bool = False) -> SimpleNamespace:
    return SimpleNamespace(username=username, tenant=tenant, actor="recovery",
                           generate=generate)


def run_cli(capsys, username: str, tenant: str = "", generate: bool = False) -> dict:
    cli.cmd_reset_password(args(username, tenant, generate))
    out = capsys.readouterr().out.strip()
    return json.loads(out)


def platform_login(client: TestClient, password: str):
    return client.post("/api/v2/platform/login",
                       json={"username": "platform", "password": password})


def test_platform_admin_password_is_reset_and_new_one_logs_in(rig, capsys):
    result = run_cli(capsys, "platform")
    assert result["ok"] is True
    assert result["user"] == "platform"
    assert result["tenant_id"] is None
    assert result["sessions_revoked"] is True
    assert NEW not in capsys.readouterr().out
    assert platform_login(rig.client, OLD).status_code == 401
    assert platform_login(rig.client, NEW).status_code == 200


def test_password_change_is_audited_as_platform(rig, capsys):
    run_cli(capsys, "platform")
    with transaction(rig.factory) as db:
        rows = db.execute(text(
            "select action, actor_type from kvm_audit_log where action='user_password_reset'"
        )).fetchall()
    assert ("user_password_reset", "platform") in [(r[0], r[1]) for r in rows]


def test_all_live_sessions_of_the_account_are_revoked(rig, capsys):
    import asyncio
    with transaction(rig.factory) as db:
        target = db.scalar(select(User.id).where(User.username == "platform"))
    asyncio.run(rig.state.put_session("digest-a", {"user_id": target}, 3600))
    asyncio.run(rig.state.put_session("digest-b", {"user_id": target}, 3600))
    asyncio.run(rig.state.put_session("other", {"user_id": "someone-else"}, 3600))

    run_cli(capsys, "platform")

    assert asyncio.run(rig.state.get_session("digest-a")) is None
    assert asyncio.run(rig.state.get_session("digest-b")) is None
    assert asyncio.run(rig.state.get_session("other")) is not None


def test_tenant_account_requires_tenant_scope(rig, capsys):
    with pytest.raises(SystemExit):
        run_cli(capsys, "g-admin")
    result = run_cli(capsys, "g-admin", "globex")
    assert result["user"] == "g-admin"
    assert result["tenant_id"] is not None
    with transaction(rig.factory) as db:
        user = db.scalar(select(User).where(User.username == "g-admin"))
    assert verify_password(NEW, user.password_hash)


def test_unknown_user_fails_without_writing(rig, capsys):
    with pytest.raises(SystemExit):
        run_cli(capsys, "ghost")
    assert platform_login(rig.client, OLD).status_code == 200


def test_generate_mints_strong_password_without_env(rig, capsys, monkeypatch):
    monkeypatch.delenv("KVMHUB_NEW_PASSWORD", raising=False)
    cli.cmd_reset_password(args("platform", generate=True))
    out = capsys.readouterr().out.strip()
    result = json.loads(out)
    generated = result["new_password"]
    assert len(generated) >= 8
    assert any(c.islower() for c in generated)
    assert any(c.isupper() for c in generated)
    assert any(c.isdigit() for c in generated)
    assert platform_login(rig.client, OLD).status_code == 401
    assert platform_login(rig.client, generated).status_code == 200
    assert out.count(generated) == 1
