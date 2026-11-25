"""Fail-closed configuration for the three production G1 runtime services."""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from urllib.parse import urlparse

from aiohttp import web

from kvmhub.common import client_tls, server_tls
from kvmhub.platform.admission_api import create_admission_app
from kvmhub.internal_api import create_app as internal_create_app
from kvmhub.store import Store

logger = logging.getLogger(__name__)


class G1ConfigError(RuntimeError):
    pass


required_g1_keys = (
    "db_url",
    "data_plane_store",
    "authority_url",
    "authority_host",
    "projection_host",
    "signing_key",
    "ca",
    "server_cert",
    "server_key",
    "authority_cert",
    "authority_key",
    "projector_cert",
    "projector_key",
    "authority_cert_cn",
    "platform_cert_cn",
    "projector_cert_cn",
)


def load_g1_config(environ: dict[str, str]) -> dict:
    raw = (environ.get("KVMHUB_G1_CONFIG") or "").strip()
    if not raw:
        raise G1ConfigError("KVMHUB_G1_CONFIG is required for G1 runtime services")
    path = Path(raw)
    if not path.is_file():
        raise G1ConfigError(f"G1 config not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise G1ConfigError(f"invalid json in G1 config: {path}") from exc
    if not isinstance(data, dict):
        raise G1ConfigError(f"G1 config must be a JSON object: {path}")
    return data


def _validate(cfg: dict, keys: tuple[str, ...]) -> None:
    for key in keys:
        if key not in cfg or not str(cfg[key] or "").strip():
            raise G1ConfigError(f"G1 config missing required key: {key}")


def build_authority_config(cfg: dict, config_dir: Path) -> dict:
    _validate(cfg, required_g1_keys)
    parsed = urlparse(str(cfg["authority_url"]))
    if parsed.scheme != "https" or not parsed.netloc:
        raise G1ConfigError("KVMHUB_G1 authority_url must be an https URL with a host")
    if parsed.netloc != str(cfg["authority_host"]).strip():
        raise G1ConfigError(
            f"authority_url netloc {parsed.netloc!r} != authority_host {cfg['authority_host']!r}")
    return {
        "db_url": cfg["db_url"],
        "signing_key": str(config_dir / cfg["signing_key"]),
        "worker_proof_hash": "",
        "authority_cert_cn": cfg["authority_cert_cn"],
        "platform_cert_cn": cfg["platform_cert_cn"],
        "projector_cert_cn": cfg["projector_cert_cn"],
        "ca": str(config_dir / cfg["ca"]),
        "server_cert": str(config_dir / cfg["server_cert"]),
        "server_key": str(config_dir / cfg["server_key"]),
        "authority_cert": str(config_dir / cfg["authority_cert"]),
        "authority_key": str(config_dir / cfg["authority_key"]),
        "tls_ca": str(config_dir / cfg["ca"]),
        "authority_url": cfg["authority_url"],
        "expected_host": cfg["authority_host"],
    }


def build_projector_config(cfg: dict, config_dir: Path) -> dict:
    _validate(cfg, required_g1_keys)
    _split_host(str(cfg["projection_host"]))
    return {
        "endpoint_base": f"https://{cfg['projection_host']}",
        "expected_host": cfg["projection_host"],
        "client_cert_cn": cfg["projector_cert_cn"],
        "ca": str(config_dir / cfg["ca"]),
        "client_cert": str(config_dir / cfg["projector_cert"]),
        "client_key": str(config_dir / cfg["projector_key"]),
        "data_plane_store": cfg["data_plane_store"],
        "db_url": cfg["db_url"],
    }


async def projector_loop(run_once, sleep, *, interval: float = 1.0) -> None:
    while True:
        try:
            await run_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - one bad pass must not stop the daemon
            logger.warning("g1 projector pass failed", exc_info=True)
        await sleep(interval)



def _preflight_files(cfg: dict, keys: tuple[str, ...]) -> None:
    for key in keys:
        path = Path(cfg[key])
        if not path.is_file():
            raise G1ConfigError(f"G1 config key {key} points to a file not found: {path}")


def make_session_factory(db_url: str):
    from kvmhub.platform.db import make_engine, session_factory
    return session_factory(make_engine(db_url))


_AUTHORITY_FILES = ("signing_key", "ca", "server_cert", "server_key",
                    "authority_cert", "authority_key")
_PROJECTOR_FILES = ("ca", "client_cert", "client_key")


def build_authority_app(cfg: dict, session_factory_fn) -> object:
    _preflight_files(cfg, _AUTHORITY_FILES)
    factory = session_factory_fn(cfg["db_url"])
    return create_admission_app(cfg, factory, expected_host=cfg["expected_host"])


def build_projector_runtime(cfg: dict) -> dict:
    _preflight_files(cfg, _PROJECTOR_FILES)
    tls = client_tls(cfg["ca"], cfg["client_cert"], cfg["client_key"])
    endpoint = cfg["endpoint_base"]
    headers = {"Host": cfg["expected_host"], "X-Projector-Proof": "ignored-by-design"}
    return {"endpoint": endpoint, "tls": tls, "headers": headers}



async def run_forever():
    await asyncio.Event().wait()


def _split_host(host: str) -> tuple[str, int]:
    value = str(host).strip()
    if ":" not in value:
        raise G1ConfigError(f"authority_host/projection_host must be host:port, got {value!r}")
    name, port = value.rsplit(":", 1)
    if not name or not port.isdigit():
        raise G1ConfigError(f"invalid host:port {value!r}")
    return name, int(port)


def run_authority(cfg: dict) -> None:
    app = build_authority_app(cfg, make_session_factory)
    host, port = _split_host(cfg["expected_host"])

    async def serve():
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, host, port,
                           ssl_context=server_tls(cfg["server_cert"], cfg["server_key"],
                                                  cfg["ca"]))
        await site.start()
        logger.info("g1 authority listening on %s:%s", host, port)
        try:
            await run_forever()
        finally:
            await runner.cleanup()

    asyncio.run(serve())


def build_projector_once(cfg: dict, *, factory=None, http_put=None) -> object:
    from kvmhub.projector import run_projector_once

    runtime = build_projector_runtime(cfg)
    session_factory = factory or make_session_factory(cfg["db_url"])

    async def once():
        return await run_projector_once(
            session_factory,
            endpoint=runtime["endpoint"], tls=runtime["tls"],
            headers=runtime["headers"], http_put=http_put)

    return once


def run_projector(cfg: dict, *, interval: float = 1.0) -> None:
    once = build_projector_once(cfg)

    async def serve():
        await projector_loop(once, asyncio.sleep, interval=interval)

    asyncio.run(serve())


def _load_and_run(role: str) -> None:
    import os

    cfg = load_g1_config(os.environ)
    config_dir = Path(os.environ["KVMHUB_G1_CONFIG"]).resolve().parent
    if role == "authority":
        run_authority(build_authority_config(cfg, config_dir))
    elif role == "projector":
        proj_cfg = build_projector_config(cfg, config_dir)
        run_projector(proj_cfg,
                      interval=float(os.environ.get("KVMHUB_G1_PROJECT_INTERVAL", "1.0")))
    elif role == "projection":
        from base64 import b64decode

        listener_cfg = build_projection_listener_config(cfg, config_dir)
        raw_key = (os.environ.get("KVMHUB_DATA_PLANE_KEY") or "").strip()
        if not raw_key:
            raise G1ConfigError("KVMHUB_DATA_PLANE_KEY is required for the projection listener")
        try:
            key = b64decode(raw_key, validate=True)
        except Exception as exc:
            raise G1ConfigError("KVMHUB_DATA_PLANE_KEY is not valid base64") from exc
        run_projection_listener(listener_cfg, key)
    else:
        raise G1ConfigError(f"unknown G1 role: {role}")



class NoWorkerAuthority:
    async def authorize(self, **_kwargs):
        raise RuntimeError("worker operations are not served by the G1 projection listener")


def build_projection_listener_config(cfg: dict, config_dir: Path) -> dict:
    _validate(cfg, required_g1_keys)
    return {
        "ca": str(config_dir / cfg["ca"]),
        "server_cert": str(config_dir / cfg["server_cert"]),
        "server_key": str(config_dir / cfg["server_key"]),
        "signing_key": str(config_dir / cfg["signing_key"]),
        "data_plane_store": cfg["data_plane_store"],
        "expected_host": cfg["projection_host"],
        "projector_cert_cn": cfg["projector_cert_cn"],
        "worker_cert_cn": cfg["projector_cert_cn"] + "-unused",
        "worker_proof_hash": "",
        "db_url": cfg["db_url"],
    }


_PROJECTION_LISTENER_FILES = ("ca", "server_cert", "server_key", "signing_key")


def build_projection_app(listener_cfg: dict, data_plane_key: bytes | None = None):
    _preflight_files(listener_cfg, _PROJECTION_LISTENER_FILES)
    store = Store(listener_cfg["data_plane_store"], data_plane_key)
    return internal_create_app(
        listener_cfg, store,
        expected_host=listener_cfg["expected_host"],
        authority=NoWorkerAuthority(), permit_public_key=None)


def run_projection_listener(listener_cfg: dict, data_plane_key: bytes | None = None) -> None:
    app = build_projection_app(listener_cfg, data_plane_key)
    host, port = _split_host(listener_cfg["expected_host"])

    async def serve():
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(
            runner, host, port,
            ssl_context=server_tls(listener_cfg["server_cert"],
                                   listener_cfg["server_key"], listener_cfg["ca"]))
        await site.start()
        logger.info("g1 projection listener on %s:%s", host, port)
        try:
            await run_forever()
        finally:
            await runner.cleanup()

    asyncio.run(serve())


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2 or sys.argv[1] not in ("authority", "projector", "projection"):
        raise SystemExit("usage: python -m kvmhub.g1_runtime authority|projector|projection")
    _load_and_run(sys.argv[1])
