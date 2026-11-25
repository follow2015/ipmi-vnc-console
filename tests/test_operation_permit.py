"""G1 operation permits: strict audience, bindings, clock and no secret."""
import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kvmhub.common import AUDIENCE, ISSUER, Problem
from kvmhub.operation_permit import (OPERATION_AUDIENCE, issue_operation_permit,
                                     verify_operation_permit)

KEY = Ed25519PrivateKey.generate()
NOW = 1_760_000_300.0
DIGEST = "d" * 64


def permit(**overrides):
    values = dict(operation="exchange", sid="sid-1", asset_id="asset-1",
                  tenant_id="tenant-1", user_id="user-1", domain_id="admission-canary",
                  worker_id="w1", instance_id="i1", connection_revision=3,
                  admission_revision=2, digest=DIGEST, generation="gen-1",
                  lease_not_after=NOW + 30, now=NOW)
    values.update(overrides)
    return issue_operation_permit(KEY, **values)


def test_valid_permit_verifies_with_expected_binding():
    token = permit()
    claims = verify_operation_permit(KEY.public_key(), token, now=NOW,
                                     expected={"sid": "sid-1", "op": "exchange",
                                               "dgs": DIGEST, "cr": 3})
    assert claims["jti"]
    assert claims["aud"] == OPERATION_AUDIENCE
    assert claims["lna"] == NOW + 30


def test_wrong_operation_domain_or_generation_is_refused():
    token = permit()
    for expected in ({"op": "renew"}, {"dom": "other"}, {"gen": "old"}):
        with pytest.raises(Problem) as exc:
            verify_operation_permit(KEY.public_key(), token, now=NOW, expected=expected)
        assert exc.value.code == "operation_permit_invalid"


def test_browser_audience_and_extra_claim_are_refused():
    browser = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "iat": int(NOW),
                          "exp": int(NOW) + 5, "jti": "x", "op": "exchange"},
                         KEY, algorithm="EdDSA", headers={"kid": "local-v1"})
    with pytest.raises(Problem):
        verify_operation_permit(KEY.public_key(), browser, now=NOW)
    extra = jwt.decode(permit(), KEY.public_key(), algorithms=["EdDSA"],
                       audience=OPERATION_AUDIENCE, issuer=ISSUER,
                       options={"verify_exp": False, "verify_iat": False})
    extra["unexpected"] = "value"
    tampered = jwt.encode(extra, KEY, algorithm="EdDSA", headers={"kid": "local-v1"})
    with pytest.raises(Problem):
        verify_operation_permit(KEY.public_key(), tampered, now=NOW)


def test_stale_permit_reports_a_clock_fault_not_a_bad_token():
    stale = permit(now=NOW - 60)
    with pytest.raises(Problem) as exc:
        verify_operation_permit(KEY.public_key(), stale, now=NOW)
    assert exc.value.code == "clock_skew"
    assert exc.value.status == 401
    assert exc.value.detail["drift_seconds"] >= 40
    assert exc.value.detail["tolerance_seconds"] > 0


def test_permit_from_the_future_is_also_a_clock_fault():
    ahead = permit(now=NOW + 30)
    with pytest.raises(Problem) as exc:
        verify_operation_permit(KEY.public_key(), ahead, now=NOW)
    assert exc.value.code == "clock_skew"


def test_skew_tolerance_covers_a_few_seconds_not_a_few_minutes():
    for offset in (-4.0, 0.0, 4.0):
        claims = verify_operation_permit(KEY.public_key(), permit(now=NOW + offset),
                                        now=NOW)
        assert claims["op"] == "exchange"
    with pytest.raises(Problem) as exc:
        verify_operation_permit(KEY.public_key(), permit(now=NOW + 12), now=NOW)
    assert exc.value.code == "clock_skew"


def test_permit_claiming_a_wider_window_is_tampering_not_skew():
    long_window = jwt.decode(permit(), KEY.public_key(), algorithms=["EdDSA"],
                             audience=OPERATION_AUDIENCE, issuer=ISSUER,
                             options={"verify_exp": False, "verify_iat": False})
    long_window["exp"] = long_window["iat"] + 120
    tampered = jwt.encode(long_window, KEY, algorithm="EdDSA",
                          headers={"kid": "local-v1"})
    with pytest.raises(Problem) as exc:
        verify_operation_permit(KEY.public_key(), tampered, now=NOW)
    assert exc.value.code == "operation_permit_invalid"


def test_permit_carries_no_secret_material():
    payload = permit().split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    text = json.dumps(claims)
    for secret in ("password", "calvin", "secret", "credential"):
        assert secret not in text
