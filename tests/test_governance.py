"""The brand workbench: read-only by construction, and the command it hands out."""
from __future__ import annotations

import json
import shlex
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from kvmhub.platform import governance, services, vendor_registry
from kvmhub.platform.api import create_app
from kvmhub.platform.bus import AssemblyBus
from kvmhub.platform.config import Settings
from kvmhub.platform.db import (bootstrap_platform_admin, init_schema, make_engine,
                                seed_roles, session_factory, transaction)
from kvmhub.platform.models import (CAPABILITY_DRAFT, CAPABILITY_VERIFIED,
                                    PROFILE_APPROVED, Capability, VendorProfile)
from kvmhub.platform.redis_state import MemoryState
from tools import platform_admin

KEY = b"0123456789abcdef0123456789abcdef"
PASSWORD = "synthetic-password"
ORIGIN = "http://testserver"
NOW = 1_800_000_000.0
REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def rig(tmp_path):
    cfg = Settings(env="test", db_url=f"sqlite:///{tmp_path}/control.db", redis_url="",
                   credential_key=KEY, session_ttl=3600, lease_seconds=30,
                   bootstrap_admin=None, bootstrap_password=None, strict_prod=False)
    state = MemoryState()
    app = create_app(cfg, state=state, plane=None)
    platform = app.state.platform
    stamp = time.time()
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        services.create_user(db, "admin", PASSWORD, "admin", actor="test")
        bootstrap_platform_admin(db, "platform", PASSWORD)
        vendor_registry.seed_builtin_profiles(db)
        db.add(VendorProfile(
            id="profile-overdue", code="synthetic-overdue", vendor="Synthetic",
            vendor_aliases="[]", model_pattern="^X9", status=PROFILE_APPROVED,
            evidence="/srv/evidence/2026-05.json", approver="ops",
            approved_at=stamp - 400 * 86400, review_due=stamp - 3 * 86400,
            revision=2, created=stamp - 400 * 86400))
        db.add(VendorProfile(
            id="profile-current", code="synthetic-current", vendor="Synthetic",
            vendor_aliases="[]", model_pattern="^X8", status=PROFILE_APPROVED,
            evidence="/srv/evidence/2026-09.json", approver="ops",
            approved_at=stamp - 10 * 86400, review_due=stamp + 170 * 86400,
            revision=1, created=stamp - 10 * 86400))
        other = services.create_tenant(db, code="globex", name="Globex", actor="test")
        db.add(VendorProfile(
            id="profile-globex", tenant_id=other.id, code="globex-private",
            vendor="Synthetic", vendor_aliases="[]", model_pattern="^G", status="draft",
            evidence="", approver="", priority=10, created=stamp))
        for capability in (
            Capability(id="cap-verified", vendor="Supermicro (Inspur OEM)",
                       model="X10DRT-PS", firmware="8.78",
                       adapter="supermicro-x10-passthrough", status=CAPABILITY_VERIFIED,
                       expires=stamp + 200 * 86400, review_due=stamp + 200 * 86400,
                       evidence="/srv/evidence/2026-05.json", created=stamp),
            Capability(id="cap-expired", vendor="Synthetic", model="X9", firmware="1.0",
                       adapter="supermicro-x10-passthrough", status=CAPABILITY_VERIFIED,
                       expires=stamp - 86400, review_due=stamp + 86400, created=stamp),
            Capability(id="cap-review", vendor="Synthetic", model="X9", firmware="1.1",
                       adapter="supermicro-x10-passthrough", status=CAPABILITY_VERIFIED,
                       expires=stamp + 100 * 86400, review_due=stamp - 86400, created=stamp),
            Capability(id="cap-draft", vendor="Synthetic", model="X9", firmware="1.2",
                       adapter="supermicro-x10-passthrough", status=CAPABILITY_DRAFT,
                       expires=0, review_due=0, created=stamp),
        ):
            db.add(capability)
        db.flush()
        draft_id = next(row.id for row in db.scalars(select(VendorProfile)).all()
                        if row.status == "draft")
    with TestClient(app, base_url=ORIGIN) as client:
        yield SimpleNamespace(client=client, platform=platform,
                              ids={"draft": draft_id, "overdue": "profile-overdue",
                                   "globex": "profile-globex"})
        platform.engine.dispose()


def login(client: TestClient, username: str, tenant_code: str | None = None) -> str:
    body = {"username": username, "password": PASSWORD}
    path = "/api/v2/login"
    if username == "platform":
        path = "/api/v2/platform/login"
    elif tenant_code:
        body["tenant_code"] = tenant_code
    response = client.post(path, json=body)
    assert response.status_code == 200, response.text
    return response.json()["csrf"]


def headers(csrf: str) -> dict:
    return {"Origin": ORIGIN, "X-CSRF-Token": csrf}



def flags(command: str) -> dict[str, object]:
    argv, out, index = shlex.split(command), {}, 0
    while index < len(argv):
        token = argv[index]
        if token.startswith("--"):
            value = argv[index + 1] if index + 1 < len(argv) else None
            out[token[2:]] = True if value is None or value.startswith("--") else value
            index += 1 if value is None or value.startswith("--") else 2
        else:
            index += 1
    return out


def test_command_quotes_values_a_shell_would_eat():
    command = governance.approve_profile_command(
        "p'; rm -rf /", approver="ops", evidence="/srv/measured evidence.json")
    assert shlex.split(command) == [
        "tools/platform_admin.py", "approve-profile", "--id", "p'; rm -rf /",
        "--approver", "ops", "--evidence", "/srv/measured evidence.json",
        "--review-days", "180"]


def test_command_round_trips_through_the_cli_parser():
    command = governance.approve_profile_command("profile-x", approver="ops", renew=True)
    argv = shlex.split(command)
    assert argv[0] == "tools/platform_admin.py"
    args = platform_admin.parser().parse_args(argv[1:])
    assert args.fn is platform_admin.cmd_approve_profile
    assert args.id == "profile-x" and args.approver == "ops"
    assert args.renew is True and args.review_days == 180
    args = platform_admin.parser().parse_args(
        shlex.split(governance.approve_profile_command("profile-y"))[1:])
    assert args.renew is False


def test_capability_command_round_trips_through_the_cli_parser():
    args = platform_admin.parser().parse_args(
        shlex.split(governance.approve_capability_command("cap-1"))[1:])
    assert args.fn is platform_admin.cmd_approve_capability
    assert (args.id, args.valid_days) == ("cap-1", 365)


@pytest.mark.parametrize("status,review_due,expected", [
    ("draft", 0, "draft"),
    ("approved", 0, "approved"),
    ("approved", NOW - 1, "overdue"),
    ("approved", NOW + 60, "due_soon"),
    ("approved", NOW + governance.DUE_SOON_SECONDS + 1, "approved"),
    ("suspended", NOW + 86400, "suspended"),
])
def test_profile_state(status, review_due, expected):
    assert governance.profile_state(status, review_due, NOW) == expected


@pytest.mark.parametrize("status,expires,review_due,expected", [
    ("draft", 0, 0, "draft"),
    ("verified", 0, 0, "expired"),
    ("verified", NOW - 1, NOW + 86400, "expired"),
    ("verified", NOW + 100, NOW - 86400, "review_overdue"),
    ("verified", NOW + 60, NOW + 86400, "expiring"),
    ("verified", NOW + governance.DUE_SOON_SECONDS + 1, 0, "verified"),
])
def test_capability_state(status, expires, review_due, expected):
    assert governance.capability_state(status, expires, review_due, NOW) == expected



def test_workbench_lists_every_profile_and_never_approves(rig):
    csrf = login(rig.client, "platform")
    response = rig.client.get("/api/v2/platform/vendor-profiles",
                              headers={"Origin": ORIGIN})
    assert response.status_code == 200, response.text
    rows = {row["id"]: row for row in response.json()}
    assert {"profile-overdue", "profile-globex"} <= set(rows)

    draft = rows[rig.ids["draft"]]
    assert draft["state"] == "draft"
    assert draft["approve_command"].startswith("tools/platform_admin.py approve-profile")
    assert flags(draft["approve_command"])["approver"] == "platform"
    assert "renew" not in flags(draft["approve_command"])

    overdue = rows["profile-overdue"]
    assert overdue["state"] == "overdue"
    assert flags(overdue["approve_command"])["renew"] is True
    assert overdue["evidence"] == "/srv/evidence/2026-05.json"

    assert rows["profile-globex"]["scope"] == "tenant"
    assert rows[rig.ids["draft"]]["scope"] == "global"


def test_a_current_profile_offers_no_command(rig):
    login(rig.client, "platform")
    rows = {row["id"]: row for row in
            rig.client.get("/api/v2/platform/vendor-profiles",
                           headers={"Origin": ORIGIN}).json()}
    assert rows["profile-current"]["state"] == "approved"
    assert rows["profile-current"]["approve_command"] is None


def test_capability_view_separates_expiry_from_review(rig):
    login(rig.client, "platform")
    rows = {row["id"]: row for row in
            rig.client.get("/api/v2/platform/capabilities", headers={"Origin": ORIGIN}).json()}
    assert rows["cap-verified"]["state"] == "verified"
    assert rows["cap-verified"]["approve_command"] is None
    assert rows["cap-expired"]["state"] == "expired"
    assert flags(rows["cap-expired"]["approve_command"])["valid-days"] == "365"
    assert rows["cap-review"]["state"] == "review_overdue"
    assert rows["cap-draft"]["state"] == "draft"


def test_a_tenant_cannot_reach_the_workbench(rig):
    csrf = login(rig.client, "admin")
    assert rig.client.get("/api/v2/platform/vendor-profiles",
                          headers=headers(csrf)).status_code == 403
    assert rig.client.get("/api/v2/platform/capabilities",
                          headers=headers(csrf)).status_code == 403



def test_cli_refuses_to_silently_reapprove(rig, tmp_path, monkeypatch, capsys):
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(platform_admin, "_context",
                        lambda args: (None, None, rig.platform.factory, None))
    args = SimpleNamespace(id="profile-overdue", approver="ops", evidence=str(evidence),
                           review_days=180, renew=False, env_file=None)
    with pytest.raises(SystemExit) as refused:
        platform_admin.cmd_approve_profile(args)
    assert "already approved" in str(refused.value)

    args.renew = True
    platform_admin.cmd_approve_profile(args)
    result = json.loads(capsys.readouterr().out)
    assert result["renewed"] is True and result["review_due"] > time.time()

    with transaction(rig.platform.factory) as db:
        profile = db.get(VendorProfile, "profile-overdue")
        assert profile.revision == 3
        assert profile.review_due > time.time() + 179 * 86400
        actions = [row["action"] for row in services.recent_audit(db, 5)]
        assert "vendor_profile_reapproved" in actions


def test_cli_refuses_evidence_that_is_not_there(rig, tmp_path, monkeypatch):
    monkeypatch.setattr(platform_admin, "_context",
                        lambda args: (None, None, rig.platform.factory, None))
    args = SimpleNamespace(id="profile-overdue", approver="ops",
                           evidence=str(tmp_path / "missing.json"),
                           review_days=180, renew=True, env_file=None)
    with pytest.raises(SystemExit) as refused:
        platform_admin.cmd_approve_profile(args)
    assert "evidence" in str(refused.value)


def test_admin_generated_command_cli_accepts(tmp_path):
    db_path = tmp_path / "cli.db"
    engine = make_engine(f"sqlite:///{db_path}")
    init_schema(engine)
    factory = session_factory(engine)
    hostile_id = "prof; touch PWNED; echo '"
    with transaction(factory) as db:
        seed_roles(db)
        db.add(VendorProfile(id=hostile_id, code="synthetic-cli", vendor="Synthetic",
                             vendor_aliases="[]", model_pattern="^X7", status="draft",
                             evidence="", approver="", created=time.time()))
    evidence = tmp_path / "evidence & report.json"
    evidence.write_text("{}", encoding="utf-8")
    env_file = tmp_path / "cli.env"
    env_file.write_text(f"KVMHUB_ENV=test\nKVMHUB_DB_URL=sqlite:///{db_path}\n",
                        encoding="utf-8")

    command = governance.approve_profile_command(hostile_id, approver="ops",
                                                 evidence=str(evidence))
    argv = shlex.split(command)
    result = subprocess.run([sys.executable, argv[0], "--env-file", str(env_file), *argv[1:]],
                            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["code"] == "synthetic-cli"
    assert not (REPO_ROOT / "PWNED").exists()
    assert not (tmp_path / "PWNED").exists()

    with transaction(factory) as db:
        assert db.get(VendorProfile, hostile_id).status == "approved"
    engine.dispose()
