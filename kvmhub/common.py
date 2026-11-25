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
OPERATION_AUDIENCE = "kvmhub-device-operation-v2"
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
IDRAC_VNC_ADAPTER_ID = "dell-idrac-vnc-tcp"
HUAWEI_IBMC_VNC_ADAPTER_ID = "huawei-ibmc-vnc-tls"
HUAWEI_IBMC_KVM_GATEWAY_ID = "huawei-ibmc-kvm-gateway"
ATEN_JAVA_ADAPTER_ID = "aten-java-rfb-tcp"

BMC_ALLOWED_NETWORKS_ENV = "KVMHUB_BMC_ALLOWED_NETWORKS"
ATEN_HTTP_CODEBASE_HOSTS_ENV = "KVMHUB_ATEN_HTTP_CODEBASE_HOSTS"


def bmc_allowed_networks_from_env() -> tuple[str, ...]:
    raw = os.environ.get(BMC_ALLOWED_NETWORKS_ENV, "")
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def aten_http_codebase_hosts_from_env(raw=None) -> frozenset[str]:
    import ipaddress
    if raw is None:
        raw = os.environ.get(ATEN_HTTP_CODEBASE_HOSTS_ENV, "")
    if isinstance(raw, str):
        items = [item.strip() for item in raw.split(",") if item.strip()]
    else:
        items = [str(item).strip() for item in (raw or ()) if str(item).strip()]
    out = set()
    for item in items:
        try:
            out.add(str(ipaddress.ip_address(item)))
        except ValueError:
            continue
    return frozenset(out)


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
    "worker_capacity_exhausted": 503, "transcode_capacity_exhausted": 429,
    "transcode_family_unsupported": 503,
    "pipeline_version_unavailable": 503,
    "manager_unavailable": 502, "upstream_unavailable": 502,
    "credential_unavailable": 503, "subprotocol_required": 400,
    "internal_error": 500, "unknown_operation": 404, "session_not_found": 404,
    "worker_authentication_failed": 403, "instance_mismatch": 403,
    "worker_certificate_missing": 403, "worker_certificate_mismatch": 403,
    "projector_certificate_missing": 403, "projector_certificate_mismatch": 403,
    "projection_invalid": 400, "connection_snapshot_conflict": 409,
    "device_not_admitted": 403, "device_admission_expired": 403,
    "device_admission_review_overdue": 403, "connection_config_pending": 409,
    "connection_revision_mismatch": 409, "execution_domain_unavailable": 503,
    "target_network_denied": 403, "projection_schema_unsupported": 409,
    "admission_service_unavailable": 503, "operation_permit_invalid": 401,
    "operation_permit_replayed": 409,
    "admission_certificate_missing": 403, "admission_certificate_mismatch": 403,
    "assembly_missing": 502,
    "asset_not_found": 404, "fingerprint_invalid": 400,
    "fingerprint_unchanged": 409, "rotation_incomplete": 400,
    "bmc_cert_pin_invalid": 400,
}


USER_MESSAGES = {
    "asset_busy": "该资产当前有一场会话，或上一场正在等待上游注销确认；请稍后重试，不要重复点击。",
    "connection_limit": "该会话的控制台连接数已达上限，请关闭多余的标签页后刷新。",
    "worker_capacity_exhausted": "Worker 会话容量已满，请稍后重试。",
    "transcode_capacity_exhausted": "转码容量或预算已满，请稍后重试。",
    "transcode_family_unsupported": "该设备的视频协议族没有可用的转码插件，连接被拒绝。",
    "pipeline_version_unavailable": "没有匹配视频管线版本的 Worker，请联系管理员。",
    "cleanup_not_pending": "该会话的清理状态不允许人工放行。",
    "session_revoked": "该会话已被撤销，请返回 Manager 重新申请。",
    "session_not_found": "找不到该会话，可能已被清理。",
    "permission_denied": "没有该资产的访问权限。",
    "adapter_not_verified": "该资产的适配器未通过核验、已过期或未获批准。",
    "bmc_network_not_allowed": "该 BMC 不在允许的管理网段内，明文 VNC 控制台已被拒绝。",
    "authentication_required": "会话已失效，请重新登录。",
    "projector_certificate_missing": "投影服务证书缺失，连接被拒绝。",
    "projector_certificate_mismatch": "投影服务证书身份不匹配，连接被拒绝。",
    "projection_invalid": "连接投影内容不合法，已被拒绝。",
    "connection_snapshot_conflict": "连接配置版本冲突，拒绝覆盖已确认的配置。",
    "device_not_admitted": "设备尚未准入或已被撤销，请联系管理员。",
    "device_admission_expired": "设备准入已到期，请联系管理员续期。",
    "device_admission_review_overdue": "设备准入复核已逾期，请联系管理员。",
    "connection_config_pending": "设备连接配置尚未确认，请稍后重试。",
    "connection_revision_mismatch": "连接配置版本不一致，请重新申请。",
    "execution_domain_unavailable": "执行域不可用，请稍后重试。",
    "target_network_denied": "目标地址不在允许的管理网段内。",
    "projection_schema_unsupported": "连接投影版本不兼容，请联系管理员。",
    "admission_service_unavailable": "准入服务暂不可用，请稍后重试。",
    "operation_permit_invalid": "操作凭证无效，请重新申请。",
    "operation_permit_replayed": "操作凭证已被使用，请重新申请。",
    "admission_certificate_missing": "准入服务客户端证书缺失。",
    "admission_certificate_mismatch": "准入服务客户端证书身份不匹配。",
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


def expected_projector_cert_cn(cfg) -> str:
    declared = cfg.get("projector_cert_cn")
    if isinstance(declared, str) and declared.strip():
        return declared.strip()
    return "kvmhub-projector"


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
          tenant_id: str = "", binding: str = "") -> str:
    claims = {"iss": ISSUER, "aud": AUDIENCE, "iat": int(now),
              "exp": int(min(now + ttl, row["hard_until"])),
              "jti": row["jti"], "sub": row["user_id"],
              "aid": row["asset_id"], "sid": row["id"],
              "wid": row["worker_id"], "iid": row["instance_id"],
              "trc": trace if TRACE_ID.fullmatch(trace or "") else uuid.uuid4().hex}
    if tenant_id:
        claims["tid"] = tenant_id
    if binding:
        if not re.fullmatch(r"[0-9a-f]{64}", binding):
            raise ValueError("invalid ticket binding")
        claims["bdg"] = binding
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
        if "bdg" in claims and not re.fullmatch(r"[0-9a-f]{64}", claims["bdg"]):
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
