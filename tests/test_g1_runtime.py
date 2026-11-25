"""Production G1 runtime config must be fail-closed and complete."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from kvmhub.g1_runtime import (G1ConfigError, build_authority_config,
                               build_projector_config, load_g1_config,
                               projector_loop, required_g1_keys)


def _valid_cfg() -> dict:
    return {
        "db_url": "mysql+pymysql://synthetic-user:synthetic-password@127.0.0.1:3306/kvmhub",
        "data_plane_store": "mysql+pymysql://synthetic-user:synthetic-password@127.0.0.1:3306/kvmhub_store",
        "authority_url": "https://127.0.0.1:18443",
        "authority_host": "127.0.0.1:18443",
        "projection_host": "127.0.0.1:18444",
        "signing_key": "signing.key",
        "ca": "ca.pem",
        "server_cert": "authority-server.pem",
        "server_key": "authority-server.key",
        "authority_cert": "kvmhub-authority-client.pem",
        "authority_key": "kvmhub-authority-client.key",
        "projector_cert": "kvmhub-projector.pem",
        "projector_key": "kvmhub-projector.key",
        "authority_cert_cn": "kvmhub-authority-client",
        "platform_cert_cn": "kvmhub-platform-client",
        "projector_cert_cn": "kvmhub-projector",
    }



def test_load_g1_config_missing_env_refuses():
    with pytest.raises(G1ConfigError, match="KVMHUB_G1_CONFIG"):
        load_g1_config({})


def test_load_g1_config_missing_file_refuses(monkeypatch, tmp_path):
    with pytest.raises(G1ConfigError, match="not found"):
        load_g1_config({"KVMHUB_G1_CONFIG": str(tmp_path / "absent.json")})


def test_load_g1_config_invalid_json_refuses(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(G1ConfigError, match="invalid json"):
        load_g1_config({"KVMHUB_G1_CONFIG": str(path)})


def test_load_g1_config_returns_parsed_dict(tmp_path):
    path = tmp_path / "g1.json"
    path.write_text(json.dumps(_valid_cfg()), encoding="utf-8")
    assert load_g1_config({"KVMHUB_G1_CONFIG": str(path)}) == _valid_cfg()


@pytest.mark.parametrize("key", required_g1_keys)
def test_each_required_key_is_enforced(key):
    cfg = _valid_cfg()
    cfg.pop(key)
    with pytest.raises(G1ConfigError, match=key):
        build_authority_config(cfg, Path("/etc/kvmhub/g1"))



def test_authority_config_uses_pinned_tls_and_expected_host(tmp_path):
    cfg = build_authority_config(_valid_cfg(), tmp_path)
    assert cfg["db_url"] == _valid_cfg()["db_url"]
    assert cfg["authority_cert_cn"] == "kvmhub-authority-client"
    assert cfg["platform_cert_cn"] == "kvmhub-platform-client"
    assert cfg["expected_host"] == "127.0.0.1:18443"
    assert cfg["tls_ca"] == str(tmp_path / "ca.pem")


def test_authority_config_requires_https_url():
    cfg = _valid_cfg()
    cfg["authority_url"] = "http://127.0.0.1:18443"
    with pytest.raises(G1ConfigError, match="https"):
        build_authority_config(cfg, Path("/etc/kvmhub/g1"))



def test_projector_config_targets_the_internal_projection_listener(tmp_path):
    cfg = build_projector_config(_valid_cfg(), tmp_path)
    assert cfg["endpoint_base"] == "https://127.0.0.1:18444"
    assert cfg["expected_host"] == "127.0.0.1:18444"
    assert cfg["client_cert_cn"] == "kvmhub-projector"


def test_projector_config_requires_a_store():
    cfg = _valid_cfg()
    cfg.pop("data_plane_store")
    with pytest.raises(G1ConfigError, match="data_plane_store"):
        build_projector_config(cfg, Path("/etc/kvmhub/g1"))



def test_projector_loop_survives_a_single_failure():
    calls = {"n": 0}

    async def flaky_once():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")
        raise asyncio.CancelledError()

    async def no_sleep(_seconds):
        return None

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(projector_loop(flaky_once, no_sleep, interval=0.01))
    assert calls["n"] == 2


def test_projector_loop_keeps_the_configured_interval():
    sleeps = []

    async def once():
        return None

    async def cancel_on_sleep(seconds):
        sleeps.append(seconds)
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(projector_loop(once, cancel_on_sleep, interval=2.5))
    assert sleeps == [2.5]



def test_authority_service_rejects_missing_cert_files(tmp_path):
    from kvmhub.g1_runtime import build_authority_app, make_session_factory

    cfg = build_authority_config(_valid_cfg(), tmp_path)
    with pytest.raises(G1ConfigError, match="not found"):
        build_authority_app(cfg, make_session_factory)


def test_authority_service_builds_app_with_expected_host(monkeypatch, tmp_path):
    from kvmhub import g1_runtime

    cfg = build_authority_config(_valid_cfg(), tmp_path)
    for key in ("signing_key", "ca", "server_cert", "server_key",
                "authority_cert", "authority_key"):
        Path(cfg[key]).write_text("dummy", encoding="utf-8")

    captured = {}

    def fake_create_app(app_cfg, factory, *, expected_host):
        captured["cfg"] = app_cfg
        captured["expected_host"] = expected_host
        return object()

    monkeypatch.setattr(g1_runtime, "create_admission_app", fake_create_app)
    app = g1_runtime.build_authority_app(cfg, lambda url: "factory")

    assert app is not None
    assert captured["expected_host"] == "127.0.0.1:18443"
    assert captured["cfg"]["signing_key"] == cfg["signing_key"]


def test_projector_service_preflight_requires_cert_files(tmp_path):
    from kvmhub.g1_runtime import build_projector_runtime

    cfg = build_projector_config(_valid_cfg(), tmp_path)
    with pytest.raises(G1ConfigError, match="not found"):
        build_projector_runtime(cfg)


def test_projector_service_builds_endpoint_from_host(monkeypatch, tmp_path):
    from kvmhub import g1_runtime

    cfg = build_projector_config(_valid_cfg(), tmp_path)
    for key in ("ca", "client_cert", "client_key"):
        Path(cfg[key]).write_text("dummy", encoding="utf-8")

    captured = {}

    def fake_run_once(*_args, **_kwargs):
        captured["called"] = True
        return None

    monkeypatch.setattr(g1_runtime, "client_tls", lambda *a, **k: "tls-ctx")
    runtime = g1_runtime.build_projector_runtime(cfg)
    assert runtime["endpoint"] == "https://127.0.0.1:18444"
    assert runtime["tls"] == "tls-ctx"
    assert runtime["headers"]["X-Projector-Proof"] == "ignored-by-design"



def test_run_authority_serves_built_app_on_pinned_tls(monkeypatch, tmp_path):
    from kvmhub import g1_runtime

    cfg = build_authority_config(_valid_cfg(), tmp_path)
    for key in _AUTHORITY_FILES_IN_TEST():
        Path(cfg[key]).write_text("dummy", encoding="utf-8")

    sent = {}

    class FakeRunner:
        def __init__(self, app, **_kwargs):
            sent["app"] = app

        async def setup(self):
            sent["setup"] = True

        async def cleanup(self):
            pass

    class FakeSite:
        def __init__(self, runner, host, port, ssl_context):
            sent["host"], sent["port"], sent["ssl"] = host, port, ssl_context

        async def start(self):
            sent["started"] = True

    async def fake_wait():
        raise asyncio.CancelledError()

    monkeypatch.setattr(g1_runtime, "make_session_factory", lambda url: lambda: "session")
    monkeypatch.setattr(g1_runtime, "server_tls", lambda *a, **k: "server-tls")
    monkeypatch.setattr(g1_runtime.web, "AppRunner", FakeRunner)
    monkeypatch.setattr(g1_runtime.web, "TCPSite", FakeSite)
    monkeypatch.setattr(g1_runtime, "run_forever", fake_wait)

    with pytest.raises(asyncio.CancelledError):
        g1_runtime.run_authority(cfg)

    assert sent["host"] == "127.0.0.1"
    assert sent["port"] == 18443
    assert sent["ssl"] == "server-tls"
    assert sent["started"] is True


def test_run_projector_passes_tls_and_headers_to_loop(monkeypatch, tmp_path):
    from kvmhub import g1_runtime

    cfg = build_projector_config(_valid_cfg(), tmp_path)
    for key in ("ca", "client_cert", "client_key"):
        Path(cfg[key]).write_text("dummy", encoding="utf-8")

    sentinel = object()
    monkeypatch.setattr(g1_runtime, "client_tls", lambda *a, **k: "proj-tls")
    monkeypatch.setattr(g1_runtime, "build_projector_once", lambda *a, **kw: sentinel)
    seen = {}

    async def fake_loop(once, sleep, *, interval):
        seen["once"], seen["interval"] = once, interval

    monkeypatch.setattr(g1_runtime, "projector_loop", fake_loop)

    g1_runtime.run_projector(cfg, interval=3.0)

    assert seen["once"] is sentinel
    assert seen["interval"] == 3.0


def _AUTHORITY_FILES_IN_TEST():
    return ("signing_key", "ca", "server_cert", "server_key",
            "authority_cert", "authority_key")


def test_cli_refuses_without_g1_config(monkeypatch):
    from kvmhub import g1_runtime

    monkeypatch.delenv("KVMHUB_G1_CONFIG", raising=False)
    with pytest.raises(G1ConfigError, match="KVMHUB_G1_CONFIG"):
        g1_runtime._load_and_run("authority")


def test_cli_refuses_unknown_role(monkeypatch, tmp_path):
    from kvmhub import g1_runtime

    path = tmp_path / "g1.json"
    path.write_text(json.dumps(_valid_cfg()), encoding="utf-8")
    monkeypatch.setenv("KVMHUB_G1_CONFIG", str(path))
    with pytest.raises(G1ConfigError, match="unknown G1 role"):
        g1_runtime._load_and_run("bogus")


def test_authority_config_accepts_absolute_signing_key_from_data_plane(tmp_path):
    cfg = _valid_cfg()
    cfg["signing_key"] = "/var/lib/kvmhub/gateway/signing.key"
    built = build_authority_config(cfg, tmp_path)
    assert built["signing_key"] == "/var/lib/kvmhub/gateway/signing.key"



def _projector_factory(tmp_path):
    import uuid
    from kvmhub.platform.db import init_schema, make_engine, session_factory, transaction
    from kvmhub.platform.models import (Asset, AssetConnection, Capability, Credential,
                                        ExecutionDomain, PlaneOutbox, PlaneProjection)
    engine = make_engine(f"sqlite:///{tmp_path / 'g1-control.db'}")
    init_schema(engine)
    factory = session_factory(engine)
    stamp = 1_760_000_100.0
    cid, capid, asset = str(uuid.uuid4()), str(uuid.uuid4()), "asset-g1-real"
    with transaction(factory) as db:
        db.add_all([
            Credential(id=cid, tenant_id=None, label="bmc", username_cipher=b"u",
                       password_cipher=b"p", key_version=1, revision=1, created=stamp),
            Capability(id=capid, vendor="Supermicro", model="X10", firmware="1.0",
                       adapter="rfb-vnc", status="verified", evidence="measured",
                       approver="operator", expires=stamp + 86400, revision=1, created=stamp),
            Asset(id=asset, tenant_id=None, name="n1", address="192.0.2.99",
                  credential_id=cid, capability_id=capid, created=stamp, updated=stamp),
            ExecutionDomain(domain_id="admission-canary", store_id="s1",
                            endpoint="https://internal.invalid",
                            supported_schema='["v2"]', health="healthy",
                            generation="gen-1", policy_fingerprint="pol-1"),
            AssetConnection(id=str(uuid.uuid4()), asset_id=asset, revision=1,
                            endpoint_json="[]", adapter="rfb-vnc", identity_policy="{}",
                            source_versions_json="{}", secret_ref=cid,
                            secret_source="vnc_hidden", secret_revision=1, schema="v2",
                            digest="a" * 64, created=stamp),
            PlaneProjection(id=str(uuid.uuid4()), asset_id=asset, domain_id="admission-canary",
                            desired_revision=1, desired_digest="a" * 64, generation="gen-1",
                            policy_fingerprint="pol-1", status="pending", error="", ack_at=0.0),
            PlaneOutbox(event_id=str(uuid.uuid4()), asset_id=asset, revision=1,
                        event_type="test_change", created=stamp, next_attempt=stamp,
                        lease_until=0.0, attempts=0),
        ])
        db.flush()
    return factory, asset


def test_build_projector_once_delivers_without_typeerror(tmp_path, monkeypatch):
    from kvmhub import g1_runtime

    cfg = build_projector_config(_valid_cfg(), tmp_path)
    for key in ("ca", "client_cert", "client_key"):
        Path(cfg[key]).write_text("dummy", encoding="utf-8")
    monkeypatch.setattr(g1_runtime, "client_tls", lambda *a, **k: object())

    factory, asset = _projector_factory(tmp_path)
    monkeypatch.setattr(g1_runtime, "make_session_factory", lambda url: factory)

    seen = {}

    async def capture_put(url, body, headers, tls):
        seen["url"] = url
        return {"ok": True}

    once = g1_runtime.build_projector_once(cfg, http_put=capture_put)
    assert callable(once), "must return a callable, not a spent coroutine"
    result = asyncio.run(once())

    assert result["claimed"] == 1
    assert result["delivered"] == 1
    assert result["acknowledged"] == 1
    assert seen["url"].endswith(f"/internal/v2/projections/{asset}/1")


def test_projector_loop_actually_drains_outbox(tmp_path, monkeypatch):
    from kvmhub import g1_runtime

    cfg = build_projector_config(_valid_cfg(), tmp_path)
    for key in ("ca", "client_cert", "client_key"):
        Path(cfg[key]).write_text("dummy", encoding="utf-8")
    monkeypatch.setattr(g1_runtime, "client_tls", lambda *a, **k: object())
    factory, asset = _projector_factory(tmp_path)
    monkeypatch.setattr(g1_runtime, "make_session_factory", lambda url: factory)

    seen = {}

    async def capture_put(url, body, headers, tls):
        seen["url"] = url
        return {"ok": True}

    once = g1_runtime.build_projector_once(cfg, http_put=capture_put)

    async def one_pass_only():
        passes = 0
        real_sleep = asyncio.sleep

        async def sleep_and_stop(_interval):
            nonlocal passes
            passes += 1
            raise asyncio.CancelledError

        try:
            await g1_runtime.projector_loop(once, sleep_and_stop, interval=0)
        except asyncio.CancelledError:
            pass
        return passes

    asyncio.run(one_pass_only())
    assert seen.get("url", "").endswith(f"/internal/v2/projections/{asset}/1"), (
        "projector_loop must actually deliver the outbox, not swallow a TypeError")



def _real_signing_key(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    path = tmp_path / "signing.key"
    path.write_bytes(ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return path


def test_projection_listener_config_reuses_authority_ca_and_server_cert(tmp_path):
    from kvmhub.g1_runtime import build_projection_listener_config

    cfg = _valid_cfg()
    listener = build_projection_listener_config(cfg, tmp_path)
    assert listener["ca"] == str(tmp_path / "ca.pem")
    assert listener["server_cert"] == str(tmp_path / "authority-server.pem")
    assert listener["server_key"] == str(tmp_path / "authority-server.key")
    assert listener["signing_key"] == str(tmp_path / "signing.key")
    assert listener["data_plane_store"] == cfg["data_plane_store"]
    assert listener["expected_host"] == "127.0.0.1:18444"
    assert listener["projector_cert_cn"] == "kvmhub-projector"


def test_projection_listener_app_uses_no_worker_authority(tmp_path, monkeypatch):
    from kvmhub import g1_runtime

    listener = g1_runtime.build_projection_listener_config(_valid_cfg(), tmp_path)
    key = _real_signing_key(tmp_path)
    listener["signing_key"] = str(key)
    for k in ("ca", "server_cert", "server_key"):
        Path(listener[k]).write_text("dummy", encoding="utf-8")

    captured = {}

    class FakeStore:
        def __init__(self, dsn, cipher):
            captured["store"] = (dsn, cipher)

    def fake_create_app(app_cfg, store, **kwargs):
        captured["kwargs"] = kwargs
        captured["app_cfg"] = app_cfg
        return object()

    monkeypatch.setattr(g1_runtime, "Store", FakeStore)
    monkeypatch.setattr(g1_runtime, "internal_create_app", fake_create_app)

    app = g1_runtime.build_projection_app(listener, data_plane_key=b"k" * 32)

    assert app is not None
    assert captured["store"] == (listener["data_plane_store"], b"k" * 32)
    assert captured["kwargs"]["expected_host"] == "127.0.0.1:18444"
    assert captured["kwargs"]["permit_public_key"] is None
    assert type(captured["kwargs"]["authority"]).__name__ == "NoWorkerAuthority"
    assert captured["app_cfg"]["projector_cert_cn"] == "kvmhub-projector"


def test_projection_listener_refuses_missing_cert_files(tmp_path):
    from kvmhub.g1_runtime import (build_projection_listener_config,
                                   build_projection_app)
    listener = build_projection_listener_config(_valid_cfg(), tmp_path)
    with pytest.raises(G1ConfigError, match="not found"):
        build_projection_app(listener)


def test_cli_projection_decodes_data_plane_key_and_serves(monkeypatch, tmp_path):
    import base64
    import os
    from kvmhub import g1_runtime

    path = tmp_path / "g1.json"
    path.write_text(json.dumps(_valid_cfg()), encoding="utf-8")
    monkeypatch.setenv("KVMHUB_G1_CONFIG", str(path))
    monkeypatch.setenv("KVMHUB_DATA_PLANE_KEY", base64.b64encode(b"k" * 32).decode())

    seen = {}

    def fake_run(listener_cfg, key):
        seen["key"] = key
        seen["expected_host"] = listener_cfg["expected_host"]

    monkeypatch.setattr(g1_runtime, "run_projection_listener", fake_run)
    g1_runtime._load_and_run("projection")
    assert seen["key"] == b"k" * 32
    assert seen["expected_host"] == "127.0.0.1:18444"


def test_cli_projection_refuses_without_data_plane_key(monkeypatch, tmp_path):
    from kvmhub import g1_runtime

    path = tmp_path / "g1.json"
    path.write_text(json.dumps(_valid_cfg()), encoding="utf-8")
    monkeypatch.setenv("KVMHUB_G1_CONFIG", str(path))
    monkeypatch.delenv("KVMHUB_DATA_PLANE_KEY", raising=False)
    with pytest.raises(G1ConfigError, match="KVMHUB_DATA_PLANE_KEY"):
        g1_runtime._load_and_run("projection")


def test_run_projection_listener_binds_pinned_tls(monkeypatch, tmp_path):
    from kvmhub import g1_runtime

    listener = g1_runtime.build_projection_listener_config(_valid_cfg(), tmp_path)
    key = _real_signing_key(tmp_path)
    listener["signing_key"] = str(key)
    for k in ("ca", "server_cert", "server_key"):
        Path(listener[k]).write_text("dummy", encoding="utf-8")

    sent = {}

    class FakeRunner:
        def __init__(self, app, **_kwargs):
            sent["app"] = app

        async def setup(self):
            pass

        async def cleanup(self):
            pass

    class FakeSite:
        def __init__(self, runner, host, port, ssl_context):
            sent["host"], sent["port"], sent["ssl"] = host, port, ssl_context

        async def start(self):
            sent["started"] = True

    async def fake_wait():
        raise asyncio.CancelledError()

    monkeypatch.setattr(g1_runtime, "build_projection_app", lambda *a, **k: "proj-app")
    monkeypatch.setattr(g1_runtime, "server_tls", lambda *a, **k: "proj-server-tls")
    monkeypatch.setattr(g1_runtime.web, "AppRunner", FakeRunner)
    monkeypatch.setattr(g1_runtime.web, "TCPSite", FakeSite)
    monkeypatch.setattr(g1_runtime, "run_forever", fake_wait)

    with pytest.raises(asyncio.CancelledError):
        g1_runtime.run_projection_listener(listener)

    assert sent["host"] == "127.0.0.1"
    assert sent["port"] == 18444
    assert sent["ssl"] == "proj-server-tls"
    assert sent["started"] is True



def test_authority_url_host_must_match_expected_host(tmp_path):
    cfg = _valid_cfg()
    cfg["authority_url"] = "https://192.0.2.99:18443"
    with pytest.raises(G1ConfigError, match="netloc"):
        build_authority_config(cfg, tmp_path)


def test_projection_host_requires_explicit_port(tmp_path):
    cfg = _valid_cfg()
    cfg["projection_host"] = "127.0.0.1"
    with pytest.raises(G1ConfigError, match="port"):
        build_projector_config(cfg, tmp_path)



def test_cli_main_guard_is_after_all_role_helpers():
    import ast
    import kvmhub.g1_runtime as g1_mod
    src = Path(g1_mod.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    main_pos = None
    for node in tree.body:
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
            if any(getattr(c, "id", None) == "__name__" for c in
                   [node.test.left] + list(node.test.comparators)):
                main_pos = node.lineno
    assert main_pos is not None, "missing __main__ guard"
    func_lines = [n.lineno for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    assert main_pos > max(func_lines), (
        f"__main__ guard at line {main_pos} precedes a function at {max(func_lines)}")


def test_each_role_cli_invocation_resolves_without_nameerror(tmp_path, monkeypatch):
    import runpy
    for role in ("authority", "projector", "projection"):
        monkeypatch.delenv("KVMHUB_G1_CONFIG", raising=False)
        monkeypatch.setattr("sys.argv", ["kvmhub.g1_runtime", role])
        with pytest.raises(Exception) as exc:
            runpy.run_module("kvmhub.g1_runtime", run_name="__main__")
        assert not isinstance(exc.value, NameError), f"{role} role hit NameError"
