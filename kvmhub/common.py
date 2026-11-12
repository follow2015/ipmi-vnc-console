import hashlib
import hmac
import json
import os
import re
import ssl
import uuid
from pathlib import Path

import jwt

ISSUER = "kvmhub-local-manager"
AUDIENCE = "kvm-worker"
CLAIMS = ["iss", "aud", "iat", "exp", "jti", "sub", "aid", "sid", "wid", "iid", "trc"]
HOST_LABEL = re.compile(r"^w1-([0-9a-f]{32})\.kvm\.localhost$")
TRACE_ID = re.compile(r"^[0-9a-f]{32}$")

PASSTHROUGH_ADAPTER_ID = "supermicro-x10-passthrough"


def _env_port(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc
    if not 1 <= value <= 65535:
        raise RuntimeError(f"{name} must be in 1..65535, got {value}")
    return value


UI_PORT = _env_port("KVMHUB_UI_PORT", 8443)
INTERNAL_PORT = _env_port("KVMHUB_INTERNAL_PORT", 8444)
WORKER_PORT = _env_port("KVMHUB_WORKER_PORT", 9443)
BMC_PORT = _env_port("KVMHUB_BMC_PORT", 10443)

UI_ORIGIN = f"https://localhost:{UI_PORT}"
INTERNAL_ORIGIN = f"https://localhost:{INTERNAL_PORT}"
BMC_BASE_URL = f"https://127.0.0.1:{BMC_PORT}"
WORKER_HOST_SUFFIX = f":{WORKER_PORT}"

ERROR_STATUS = {
    "invalid_host": 421, "authentication_required": 401, "authentication_failed": 401,
    "invalid_ticket": 401, "ticket_expired": 401, "invalid_request": 400,
    "csrf_rejected": 403, "route_denied": 403, "worker_request_rejected": 403, "permission_denied": 403,
    "adapter_not_verified": 403, "asset_busy": 409, "ticket_consumed_or_expired": 409,
    "cleanup_not_pending": 409, "console_already_connected": 409,
    "session_revoked": 410, "request_too_large": 413, "invalid_report": 400,
    "capability_withdrawn": 410, "capability_not_found": 404, "capability_state": 409,
    "capability_exists": 409, "capability_incomplete": 400,
    "invalid_target_policy": 502, "bmc_auth_failed": 502,
    "upstream_invalid_response": 502, "upstream_handshake_failed": 502,
    "upstream_redirect_denied": 502, "upstream_frame_too_large": 502,
    "upstream_budget_exceeded": 502, "connection_limit": 429,
    "manager_unavailable": 502, "upstream_unavailable": 502,
    "credential_unavailable": 503, "subprotocol_required": 400,
    "internal_error": 500, "unknown_operation": 404, "session_not_found": 404,
    "worker_authentication_failed": 403, "instance_mismatch": 403,
}


class Problem(Exception):
    def __init__(self, code: str, status: int | None = None):
        self.code = code
        self.status = status if status is not None else ERROR_STATUS.get(code, 409)
        super().__init__(code)


SESSION_END_CODES = frozenset({"session_revoked", "capability_withdrawn"})


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def secret_matches(value: str, expected_hash: str) -> bool:
    return hmac.compare_digest(digest(value), expected_hash)


def issue(private_key, row: dict, now: float, ttl: float = 60, trace: str | None = None) -> str:
    return jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "iat": int(now),
                       "exp": int(min(now + ttl, row["hard_until"])),
                       "jti": row["jti"], "sub": row["user_id"],
                       "aid": row["asset_id"], "sid": row["id"],
                       "wid": row["worker_id"], "iid": row["instance_id"],
                       "trc": trace if TRACE_ID.fullmatch(trace or "") else uuid.uuid4().hex},
                      private_key, algorithm="EdDSA", headers={"kid": "local-v1"})


def verify(public_key, token: str, worker: str, instance: str) -> dict:
    try:
        claims = jwt.decode(token, public_key, algorithms=["EdDSA"],
                            audience=AUDIENCE, issuer=ISSUER,
                            options={"require": CLAIMS})
        if jwt.get_unverified_header(token).get("kid") != "local-v1":
            raise ValueError()
        if any(not isinstance(claims[k], str) or not claims[k] for k in CLAIMS[:2] + CLAIMS[4:]):
            raise ValueError()
        if any(type(claims[k]) is not int for k in ("iat", "exp")):
            raise ValueError()
        if not TRACE_ID.fullmatch(claims["trc"]):
            raise ValueError()
        if claims["exp"] - claims["iat"] > 60 or claims["wid"] != worker or claims["iid"] != instance:
            raise ValueError()
        return claims
    except jwt.ExpiredSignatureError:
        raise Problem("ticket_expired", 401) from None
    except (jwt.PyJWTError, ValueError, TypeError):
        raise Problem("invalid_ticket", 401) from None


def config(path: str) -> dict:
    return json.loads(Path(path).read_text())


def server_tls(cert: str, key: str, ca: str | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    if ca:
        ctx.load_verify_locations(ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def client_tls(ca: str, cert: str | None = None, key: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca)
    if cert:
        ctx.load_cert_chain(cert, key)
    return ctx
