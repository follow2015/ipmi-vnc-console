"""Short-lived EdDSA permits for G1 managed device operations."""
from __future__ import annotations

import time
import uuid

import jwt

from .common import ISSUER, OPERATION_AUDIENCE, Problem

OPERATIONS = frozenset({"allocate", "exchange", "activate", "renew",
                        "reconnect", "recover"})
PERMIT_SCHEMA = "g1-v2"
PERMIT_CLAIMS = frozenset({
    "iss", "aud", "iat", "exp", "jti", "op", "sid", "aid", "tid", "usr",
    "dom", "wid", "iid", "cr", "ar", "dgs", "gen", "lna", "schema",
})
TRUSTED_KEY_IDS = ("local-v1",)
CLOCK_SKEW = 2.0
MAX_WINDOW = 5.0


def _number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def issue_operation_permit(private_key, *, operation: str, sid: str, asset_id: str,
                           tenant_id: str | None, user_id: str, domain_id: str,
                           worker_id: str, instance_id: str, connection_revision: int,
                           admission_revision: int, digest: str, generation: str,
                           lease_not_after: float = 0.0, now: float | None = None,
                           key_id: str = TRUSTED_KEY_IDS[0]) -> str:
    if operation not in OPERATIONS:
        raise ValueError("unknown operation")
    stamp = time.time() if now is None else float(now)
    claims = {
        "iss": ISSUER,
        "aud": OPERATION_AUDIENCE,
        "iat": int(stamp),
        "exp": int(stamp + MAX_WINDOW),
        "jti": uuid.uuid4().hex,
        "op": operation,
        "sid": sid,
        "aid": asset_id,
        "tid": tenant_id or "",
        "usr": user_id,
        "dom": domain_id,
        "wid": worker_id,
        "iid": instance_id,
        "cr": int(connection_revision),
        "ar": int(admission_revision),
        "dgs": digest,
        "gen": generation,
        "lna": float(lease_not_after),
        "schema": PERMIT_SCHEMA,
    }
    return jwt.encode(claims, private_key, algorithm="EdDSA", headers={"kid": key_id})


def verify_operation_permit(public_key, token: str, *, now: float | None = None,
                            expected: dict | None = None,
                            trusted_key_ids=TRUSTED_KEY_IDS) -> dict:
    stamp = time.time() if now is None else float(now)
    try:
        header = jwt.get_unverified_header(token)
        if header.get("kid") not in trusted_key_ids:
            raise ValueError()
        claims = jwt.decode(token, public_key, algorithms=["EdDSA"],
                            audience=OPERATION_AUDIENCE, issuer=ISSUER,
                            options={"require": sorted(PERMIT_CLAIMS),
                                     "verify_exp": False, "verify_iat": False})
        if set(claims) != PERMIT_CLAIMS:
            raise ValueError()
        if claims["schema"] != PERMIT_SCHEMA or claims["op"] not in OPERATIONS:
            raise ValueError()
        for key in ("jti", "sid", "aid", "usr", "dom", "wid", "iid", "dgs", "gen"):
            if not isinstance(claims[key], str) or not claims[key]:
                raise ValueError()
        if not isinstance(claims["tid"], str):
            raise ValueError()
        for key in ("iat", "exp", "cr", "ar"):
            if type(claims[key]) is not int:
                raise ValueError()
        if not _number(claims["lna"]) or claims["lna"] < 0:
            raise ValueError()
        if not (claims["exp"] >= claims["iat"] > 0
                and claims["exp"] - claims["iat"] <= int(MAX_WINDOW + CLOCK_SKEW)
                and claims["iat"] <= stamp + CLOCK_SKEW
                and claims["exp"] >= stamp - CLOCK_SKEW):
            raise ValueError()
        for key, value in (expected or {}).items():
            if key not in claims or claims[key] != value:
                raise ValueError()
        return claims
    except jwt.ExpiredSignatureError:
        raise Problem("operation_permit_invalid", 401) from None
    except (jwt.PyJWTError, ValueError, TypeError, KeyError):
        raise Problem("operation_permit_invalid", 401) from None
