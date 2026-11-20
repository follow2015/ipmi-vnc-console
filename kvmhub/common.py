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
TRACE_ID = re.compile(r"^[0-9a-f]{32}$")

WORKER_DOMAIN = os.environ.get("KVMHUB_WORKER_DOMAIN", "")
if WORKER_DOMAIN:
    HOST_LABEL = re.compile(r"^w[0-9a-z-]{1,32}-([0-9a-f]{32})\." + re.escape(WORKER_DOMAIN) + r"$")
else:
    HOST_LABEL = re.compile(r"^w1-([0-9a-f]{32})\.kvm\.localhost$")

SESSION_MODE = os.environ.get("KVMHUB_WORKER_SESSION_MODE", "host")
if SESSION_MODE not in ("host", "path"):
    raise RuntimeError(f"KVMHUB_WORKER_SESSION_MODE must be host|path, got {SESSION_MODE!r}")
BASE_PATH = os.environ.get("KVMHUB_BASE_PATH", "").rstrip("/")
if BASE_PATH and not BASE_PATH.startswith("/"):
    BASE_PATH = "/" + BASE_PATH

PATH_SESSION = re.compile(r"^/s/([0-9a-f]{32})(/.*)?$")
_PATH_TRAVERSAL = re.compile(r"(?:\.\.|\\|\x00)")


def cookie_name_for(sid: str) -> str:
    if SESSION_MODE == "path":
        return f"__Secure-kvm_{sid}"
    return "__Host-kvm_sid"


def cookie_path_for(sid: str) -> str:
    if SESSION_MODE == "path":
        return f"{BASE_PATH}/s/{sid}/"
    return "/"


def route_prefix_for(sid: str) -> str:
    return f"{BASE_PATH}/s/{sid}"


def accept_redirect_location(sid: str) -> str:
    return "../"


def path_segment_is_safe(path: str) -> bool:
    if _PATH_TRAVERSAL.search(path):
        return False
    stripped = path[:-1] if len(path) > 1 and path.endswith("/") else path
    return "//" not in stripped

PASSTHROUGH_ADAPTER_ID = "supermicro-x10-passthrough"
IDRAC8_ADAPTER_ID = "dell-idrac8-html5"
IDRAC_VNC_ADAPTER_ID = "dell-idrac-vnc-tcp"

BMC_ALLOWED_NETWORKS_ENV = "KVMHUB_BMC_ALLOWED_NETWORKS"


def bmc_allowed_networks_from_env() -> tuple[str, ...]:
    raw = os.environ.get(BMC_ALLOWED_NETWORKS_ENV, "")
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def parse_controlled_networks(raw) -> tuple:
    import ipaddress
    if isinstance(raw, str):
        items = [item.strip() for item in raw.split(",") if item.strip()]
    else:
        items = [str(item).strip() for item in (raw or ()) if str(item).strip()]
    return tuple(ipaddress.ip_network(item, strict=False) for item in items)


def require_controlled_host(host: str, networks, *, adapter_id: str = IDRAC_VNC_ADAPTER_ID) -> None:
    import ipaddress
    parsed = parse_controlled_networks(networks)
    if not parsed:
        raise Problem("bmc_network_not_allowed", 403)
    try:
        address = ipaddress.ip_address(host)
    except (ValueError, TypeError):
        raise Problem("bmc_network_not_allowed", 403) from None
    if not any(address in network for network in parsed):
        raise Problem("bmc_network_not_allowed", 403)


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
WORKER_HOST_SUFFIX = "" if WORKER_DOMAIN else f":{WORKER_PORT}"
WORKER_FORM_ACTION = ("https://*." + WORKER_DOMAIN + WORKER_HOST_SUFFIX) if WORKER_DOMAIN \
    else f"https://*.kvm.localhost:{WORKER_PORT}"


def worker_accept_url(worker_id: str, sid: str) -> str:
    domain = WORKER_DOMAIN or "kvm.localhost"
    return f"https://{worker_id}-{sid}.{domain}{WORKER_HOST_SUFFIX}/_platform/accept"

ERROR_STATUS = {
    "invalid_host": 421, "invalid_session_path": 421,
    "authentication_required": 401, "authentication_failed": 401,
    "invalid_ticket": 401, "ticket_expired": 401, "invalid_request": 400,
    "csrf_rejected": 403, "route_denied": 403, "worker_request_rejected": 403, "permission_denied": 403,
    "adapter_not_verified": 403, "asset_busy": 409, "ticket_consumed_or_expired": 409,
    "bmc_network_not_allowed": 403,
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
    "worker_certificate_missing": 403, "worker_certificate_mismatch": 403,
    "assembly_missing": 502,
    "asset_not_found": 404, "fingerprint_invalid": 400,
    "fingerprint_unchanged": 409, "rotation_incomplete": 400,
}


USER_MESSAGES = {
    "asset_busy": "该资产当前有一场会话，或上一场正在等待上游注销确认；请稍后重试，不要重复点击。",
    "connection_limit": "该会话的控制台连接数已达上限，请关闭多余的标签页后刷新。",
    "cleanup_not_pending": "该会话的清理状态不允许人工放行。",
    "session_revoked": "该会话已被撤销，请返回 Manager 重新申请。",
    "session_not_found": "找不到该会话，可能已被清理。",
    "permission_denied": "没有该资产的访问权限。",
    "adapter_not_verified": "该资产的适配器未通过核验、已过期或未获批准。",
    "bmc_network_not_allowed": "该 BMC 不在允许的管理网段内，明文 VNC 控制台已被拒绝。",
    "authentication_required": "会话已失效，请重新登录。",
}


def user_message(code: str) -> str | None:
    return USER_MESSAGES.get(code)


def peer_certificate(transport) -> dict | None:
    if transport is None:
        return None
    try:
        ssl_object = transport.get_extra_info("ssl_object")
        cert = ssl_object.getpeercert() if ssl_object is not None else None
    except (AttributeError, ValueError, OSError):
        return None
    return cert if isinstance(cert, dict) and cert else None


def certificate_common_name(cert) -> str | None:
    for rdn in (cert or {}).get("subject", ()):
        for key, value in rdn:
            if key == "commonName" and value:
                return value
    return None


def expected_worker_cert_cn(cfg) -> str:
    declared = cfg.get("worker_cert_cn")
    if isinstance(declared, str) and declared.strip():
        return declared.strip()
    return f"{cfg['worker_id']}-{cfg['instance_id']}"


END_REASON_MESSAGES = {
    "client_closed": "操作员结束了会话。",
    "revoked": "会话已被撤销。",
    "capability_withdrawn": "该资产的能力在会话期间被收回，会话随之结束。",
    "role_downgraded": "账号权限被下调或该资产授权被撤销，会话已结束；请联系管理员重新授权。",
    "upstream_error": "与 BMC 的连接异常中断。",
    "upstream_unresponsive": "BMC 长时间没有响应，连接已判定失效。",
    "upstream_reconnect_failed": "BMC 连接断开，自动重建控制台没有成功，会话已结束。",
    "lease_expired": "租约到期，会话已结束。",
    "login_failed": "登录 BMC 失败，会话未能建立。",
    "worker_shutdown": "网关进程重启或停止，会话已结束。",
    "exchange_failed": "与 Manager 的票据交换失败，会话未能建立。",
    "client_message_denied": "浏览器发来了白名单之外的消息，为安全起见结束了会话。",
    "client_message_malformed": "浏览器发来的消息格式非法，会话已结束。",
    "input_overflow": "按键输入过快，整形队列已满；为避免卡键，会话已明确结束。",
    "manual_release": "管理员核对上游已清理后人工放行。",
    "deadline": "到达硬性截止时间，平台结束了会话。",
    "credential_unavailable": "BMC 凭据不可用，会话已结束。",
}


def end_reason_message(reason: str) -> str | None:
    return END_REASON_MESSAGES.get(reason)


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


def issue(private_key, row: dict, now: float, ttl: float = 60, trace: str | None = None,
          tenant_id: str = "") -> str:
    claims = {"iss": ISSUER, "aud": AUDIENCE, "iat": int(now),
              "exp": int(min(now + ttl, row["hard_until"])),
              "jti": row["jti"], "sub": row["user_id"],
              "aid": row["asset_id"], "sid": row["id"],
              "wid": row["worker_id"], "iid": row["instance_id"],
              "trc": trace if TRACE_ID.fullmatch(trace or "") else uuid.uuid4().hex}
    if tenant_id:
        claims["tid"] = tenant_id
    return jwt.encode(claims, private_key, algorithm="EdDSA",
                      headers={"kid": "local-v1"})


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
        if "tid" in claims and (not isinstance(claims["tid"], str) or not claims["tid"]):
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
