"""DCIM integration API, model one: bearer token + source-IP allowlist."""
from __future__ import annotations

import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from kvmhub.platform import services
from kvmhub.platform.api import create_app
from kvmhub.platform.db import transaction
from kvmhub.platform.models import ServiceToken
from test_quota_sessions import ORIGIN, rig  # noqa: F401 - rig is a pytest fixture


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Origin": ORIGIN,
            "Accept": "application/json"}


def issue(rig, *, tenant: str = "default", label: str = "dcim",
          allow: list[str] | None = None, expires_days: int | None = None) -> str:
    with transaction(rig.platform.factory) as db:
        result = services.create_service_token(
            db, tenant_code=tenant, label=label,
            allowlist=allow if allow is not None else ["127.0.0.0/8"],
            actor="platform", expires_days=expires_days)
    return result["token"]


def test_a_token_is_required_and_browser_cookies_do_not_count(rig):
    response = rig.client.get("/api/v2/integration/ping", headers={"Origin": ORIGIN})
    assert response.status_code == 401
    assert response.json()["error"] == "authentication_required"


def test_ping_identifies_the_bound_tenant_without_naming_it(rig):
    token = issue(rig, label="dcim-prod")
    response = rig.client.get("/api/v2/integration/ping", headers=bearer(token))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["tenant_code"] == "default"
    assert body["token_label"] == "dcim-prod"
    assert body["service_account"].startswith("svc-dcim-")
    assert token not in str(body)


def test_source_outside_the_allowlist_is_refused(rig):
    token = issue(rig, label="office-only", allow=["203.0.113.0/24"])
    response = rig.client.get("/api/v2/integration/ping", headers=bearer(token))
    assert response.status_code == 403
    assert response.json()["error"] == "source_not_allowed"


def test_revocation_takes_effect_on_the_next_call(rig):
    token = issue(rig, label="to-revoke")
    with transaction(rig.platform.factory) as db:
        row = db.query(ServiceToken).filter_by(label="to-revoke").first()
        services.revoke_service_token(db, row.id, actor="platform")
    response = rig.client.get("/api/v2/integration/ping", headers=bearer(token))
    assert response.status_code == 401
    assert response.json()["error"] == "service_token_revoked"


def test_an_expired_token_is_refused(rig):
    token = issue(rig, label="expired", expires_days=1)
    with transaction(rig.platform.factory) as db:
        row = db.query(ServiceToken).filter_by(label="expired").first()
        row.expires = time.time() - 1
        db.commit()
    response = rig.client.get("/api/v2/integration/ping", headers=bearer(token))
    assert response.status_code == 401
    assert response.json()["error"] == "service_token_expired"


def test_integration_asset_list_is_tenant_scoped(rig):
    token = issue(rig, tenant="globex", label="globex-dcim")
    response = rig.client.get("/api/v2/integration/assets", headers=bearer(token))
    assert response.status_code == 200, response.text
    assert response.json() == {"assets": []}
    default_token = issue(rig, label="default-dcim")
    response = rig.client.get("/api/v2/integration/assets", headers=bearer(default_token))
    assert {row["address"] for row in response.json()["assets"]} == {
        "192.0.2.11", "192.0.2.12"}


def test_console_open_runs_as_the_service_principal_and_audits_the_operator(rig):
    token = issue(rig, label="console-dcim")
    response = rig.client.post("/api/v2/integration/console/open",
                               headers=bearer(token),
                               json={"asset_id": rig.ids["assets"][0],
                                     "operator": "dcim-user-42"})
    assert response.status_code == 200, response.text
    sid = response.json()["sid"]
    with transaction(rig.platform.factory) as db:
        rows = services.recent_audit(db, 50)
    issued = [row for row in rows if row["action"] == "console_ticket_issued"
              and row.get("detail", {}).get("sid") == sid]
    assert len(issued) == 1
    assert issued[0]["actor_type"] == "dcim_system"
    assert issued[0]["detail"]["operator"] == "dcim-user-42"
    assert issued[0]["detail"]["token_id"]

    closed = rig.client.post(f"/api/v2/integration/consoles/{sid}/close",
                             headers=bearer(token), json={})
    assert closed.status_code == 200, closed.text


def test_a_token_cannot_be_used_as_a_browser_password(rig):
    token = issue(rig, label="not-a-password")
    response = rig.client.post("/api/v2/login", json={"username": "admin",
                                                      "password": token})
    assert response.status_code == 401


def test_trusted_proxy_is_required_before_forwarded_for_counts(rig):
    token = issue(rig, label="behind-proxy", allow=["198.51.100.7/32"])
    forged = {**bearer(token), "X-Forwarded-For": "198.51.100.7"}
    assert rig.client.get("/api/v2/integration/ping", headers=forged).status_code == 403

    trusted = replace(rig.platform.cfg,
                      integration_trusted_proxies="127.0.0.0/8")
    app = create_app(trusted, state=rig.state, plane=rig.plane)
    with TestClient(app, base_url=ORIGIN,
                    client=("127.0.0.1", 54322)) as client:
        assert client.get("/api/v2/integration/ping", headers=forged).status_code == 200


def test_a_forged_leftmost_forwarded_hop_does_not_win(rig):
    token = issue(rig, label="chain", allow=["198.51.100.7/32"])
    trusted = replace(rig.platform.cfg,
                      integration_trusted_proxies="127.0.0.0/8")
    app = create_app(trusted, state=rig.state, plane=rig.plane)
    with TestClient(app, base_url=ORIGIN,
                    client=("127.0.0.1", 54323)) as client:
        forged = {**bearer(token),
                  "X-Forwarded-For": "198.51.100.7, 203.0.113.9"}
        assert client.get("/api/v2/integration/ping", headers=forged).status_code == 403
