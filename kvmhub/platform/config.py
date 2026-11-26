"""Production control-plane configuration."""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote_plus

from dotenv import load_dotenv

_ENV_FILE_LOADED = False


def load_env(path: str | os.PathLike[str] | None = None) -> None:
    global _ENV_FILE_LOADED
    if _ENV_FILE_LOADED:
        return
    target = Path(path) if path else Path.cwd() / ".env"
    if target.is_file():
        load_dotenv(target, override=False)
    _ENV_FILE_LOADED = True


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if not 0 < value < 65536:
        raise ValueError(f"{name} is out of range: {value}")
    return value


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    if raw.strip().lower() not in ("0", "1", "true", "false", "yes", "no"):
        raise ValueError(f"{name} must be a boolean, got {raw!r}")
    return raw.strip().lower() in ("1", "true", "yes")


def mysql_url() -> str:
    user = os.getenv("MYSQL_USER", "kvmhub")
    password = os.getenv("MYSQL_PASSWORD", "")
    host = os.getenv("MYSQL_HOST", "127.0.0.1")
    port = _int("MYSQL_PORT", 3306)
    database = os.getenv("MYSQL_DATABASE", "kvmhub")
    charset = os.getenv("MYSQL_CHARSET", "utf8mb4")
    return (f"mysql+pymysql://{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/"
            f"{quote_plus(database)}?charset={quote_plus(charset)}")


@dataclass(frozen=True)
class Settings:
    env: str
    db_url: str
    redis_url: str
    credential_key: bytes | None
    session_ttl: int
    lease_seconds: int
    bootstrap_admin: str | None
    bootstrap_password: str | None
    strict_prod: bool
    data_plane_store: str = ""
    data_plane_key: bytes | None = None
    signing_key_path: str = ""
    worker_url_template: str = ""
    passthrough_targets: str = ""
    bmc_allowed_networks: str = ""
    iframe_mode: str = "off"
    strict_grants: bool = False
    integration_trusted_proxies: str = ""
    authority_url: str = ""
    authority_ca: str = ""
    authority_cert: str = ""
    authority_key: str = ""
    authority_cert_cn: str = ""
    platform_cert_cn: str = ""
    managed_domains: str = ""
    previous_credential_key: bytes | None = None

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    @property
    def data_plane_dialect(self) -> str:
        if not self.data_plane_store:
            return ""
        from ..sql_backend import parse_store_dsn
        return parse_store_dsn(self.data_plane_store).dialect

    def validate(self) -> None:
        if self.env not in ("dev", "test", "prod"):
            raise ValueError(f"KVMHUB_ENV must be dev/test/prod, got {self.env!r}")
        if not self.db_url:
            raise ValueError("KVMHUB_DB_URL / MYSQL_* is not configured")
        if self.credential_key is not None and len(self.credential_key) != 32:
            raise ValueError("KVMHUB_CREDENTIAL_KEY must decode to exactly 32 bytes (AES-256-GCM)")
        if self.strict_prod and self.is_prod:
            missing = []
            if self.db_url.startswith("sqlite"):
                missing.append("MySQL (sqlite is dev/test only)")
            if not self.redis_url:
                missing.append("KVMHUB_REDIS_URL")
            if self.credential_key is None:
                missing.append("KVMHUB_CREDENTIAL_KEY")
            if missing:
                raise ValueError("production configuration incomplete: " + ", ".join(missing))
        if self.session_ttl < 60 or self.session_ttl > 86400:
            raise ValueError("KVMHUB_SESSION_TTL must be between 60 and 86400 seconds")
        if self.iframe_mode not in ("off", "on"):
            raise ValueError("KVMHUB_IFRAME_MODE must be off|on")
        if self.data_plane_store:
            if not self.signing_key_path:
                raise ValueError("KVMHUB_SIGNING_KEY is required when KVMHUB_DATA_PLANE_STORE is set")
            if self.data_plane_key is None or len(self.data_plane_key) != 32:
                raise ValueError("KVMHUB_DATA_PLANE_KEY must decode to exactly 32 bytes")
        if self.integration_trusted_proxies:
            import ipaddress
            for item in self.integration_trusted_proxies.split(","):
                if item.strip():
                    ipaddress.ip_network(item.strip(), strict=False)
        managed_domains = tuple(item.strip() for item in self.managed_domains.split(",")
                                if item.strip())
        if managed_domains and not self.authority_url:
            raise ValueError("KVMHUB_MANAGED_DOMAINS requires KVMHUB_AUTHORITY_URL; "
                             "managed domains must never fall back to the legacy chain")
        if self.authority_url:
            from urllib.parse import urlparse
            parsed = urlparse(self.authority_url)
            if parsed.scheme != "https" or not parsed.netloc:
                raise ValueError("KVMHUB_AUTHORITY_URL must be an https URL with a host")
            missing = [name for name, value in (
                ("KVMHUB_AUTHORITY_CA", self.authority_ca),
                ("KVMHUB_AUTHORITY_CERT", self.authority_cert),
                ("KVMHUB_AUTHORITY_KEY", self.authority_key),
            ) if not value]
            if missing:
                raise ValueError("managed admission needs " + ", ".join(missing))
            for name, path in (("KVMHUB_AUTHORITY_CA", self.authority_ca),
                               ("KVMHUB_AUTHORITY_CERT", self.authority_cert),
                               ("KVMHUB_AUTHORITY_KEY", self.authority_key)):
                if not Path(path).is_file():
                    raise ValueError(f"{name} does not point to a file")
        if self.is_prod and not self.bmc_allowed_networks:
            raise ValueError("KVMHUB_BMC_ALLOWED_NETWORKS must be configured in production")
        if self.bmc_allowed_networks:
            import ipaddress
            for item in self.bmc_allowed_networks.split(","):
                if not item.strip():
                    raise ValueError("KVMHUB_BMC_ALLOWED_NETWORKS has an empty CIDR entry")
                ipaddress.ip_network(item.strip(), strict=False)


def _decode_key(raw: str, name: str) -> bytes | None:
    if not raw:
        return None
    try:
        return base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise ValueError(f"{name} must be base64 encoded") from exc


def settings(env_path: str | os.PathLike[str] | None = None) -> Settings:
    load_env(env_path)
    key = _decode_key(os.getenv("KVMHUB_CREDENTIAL_KEY", ""), "KVMHUB_CREDENTIAL_KEY")
    previous_key = _decode_key(
        os.getenv("KVMHUB_CREDENTIAL_KEY_PREVIOUS", ""), "KVMHUB_CREDENTIAL_KEY_PREVIOUS")
    if previous_key and key and previous_key == key:
        raise ValueError("KVMHUB_CREDENTIAL_KEY_PREVIOUS must differ from the current key")
    data_plane_key = _decode_key(os.getenv("KVMHUB_DATA_PLANE_KEY", ""),
                                 "KVMHUB_DATA_PLANE_KEY")
    db_url = os.getenv("KVMHUB_DB_URL", "")
    if not db_url:
        db_url = (mysql_url() if os.getenv("KVMHUB_ENV") == "prod"
                  else os.getenv("KVMHUB_SQLITE_PATH", "sqlite:///./.local-platform/platform.db"))
    cfg = Settings(
        env=os.getenv("KVMHUB_ENV", "dev"),
        db_url=db_url,
        redis_url=os.getenv("KVMHUB_REDIS_URL", ""),
        credential_key=key,
        previous_credential_key=previous_key,
        session_ttl=_int("KVMHUB_SESSION_TTL", 3600),
        lease_seconds=_int("KVMHUB_LEASE_SECONDS", 30),
        bootstrap_admin=os.getenv("KVMHUB_BOOTSTRAP_ADMIN"),
        bootstrap_password=os.getenv("KVMHUB_BOOTSTRAP_PASSWORD"),
        strict_prod=_bool("KVMHUB_STRICT_PROD", True),
        data_plane_store=os.getenv("KVMHUB_DATA_PLANE_STORE", ""),
        data_plane_key=data_plane_key,
        signing_key_path=os.getenv("KVMHUB_SIGNING_KEY", ""),
        worker_url_template=os.getenv("KVMHUB_WORKER_URL_TEMPLATE", ""),
        passthrough_targets=os.getenv("KVMHUB_PASSTHROUGH_TARGETS", ""),
        bmc_allowed_networks=os.getenv("KVMHUB_BMC_ALLOWED_NETWORKS", "").strip(),
        iframe_mode=os.getenv("KVMHUB_IFRAME_MODE", "off").strip().lower(),
        strict_grants=_bool("KVMHUB_STRICT_GRANTS", False),
        integration_trusted_proxies=os.getenv("KVMHUB_TRUSTED_PROXIES", "").strip(),
        authority_url=os.getenv("KVMHUB_AUTHORITY_URL", "").strip(),
        authority_ca=os.getenv("KVMHUB_AUTHORITY_CA", "").strip(),
        authority_cert=os.getenv("KVMHUB_AUTHORITY_CERT", "").strip(),
        authority_key=os.getenv("KVMHUB_AUTHORITY_KEY", "").strip(),
        authority_cert_cn=os.getenv("KVMHUB_AUTHORITY_CERT_CN", "").strip(),
        platform_cert_cn=os.getenv("KVMHUB_PLATFORM_CERT_CN", "").strip(),
        managed_domains=os.getenv("KVMHUB_MANAGED_DOMAINS", "").strip(),
    )
    cfg.validate()
    return cfg
