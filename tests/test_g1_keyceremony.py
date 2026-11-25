"""The operator key-ceremony CLI ties identity generation to a pinned config."""
from __future__ import annotations

import json

import pytest

from tools.g1_keyceremony import build_parser, run_ceremony


def test_parser_requires_directories():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_ceremony_writes_config_and_manifest(tmp_path):
    out = tmp_path / "g1"
    key = tmp_path / "signing.key"
    key.write_text("dummy-key", encoding="utf-8")
    result = run_ceremony([
        "--cert-dir", str(out),
        "--config-out", str(tmp_path / "g1.json"),
        "--authority-host", "127.0.0.1:18443",
        "--projection-host", "127.0.0.1:18444",
        "--db-url", "mysql+pymysql://synthetic-user:synthetic-password@h/db",
        "--data-plane-store", "mysql+pymysql://synthetic-user:synthetic-password@h/store",
        "--signing-key", str(key),
    ])
    assert result["ok"] is True
    doc = json.loads((tmp_path / "g1.json").read_text(encoding="utf-8"))
    assert doc["authority_host"] == "127.0.0.1:18443"
    assert doc["ca"] == "g1/ca.pem"
    assert doc["server_cert"] == "g1/authority-server.pem"
    assert (out / "ca.pem").is_file()
    assert (tmp_path / doc["ca"]).is_file(), "runtime must resolve ca relative to config"
    assert doc["signing_key"] == str(key.resolve())
    assert "BEGIN PRIVATE KEY" not in json.dumps(doc)
    assert "BEGIN CERTIFICATE" not in json.dumps(doc)


def test_ceremony_refuses_to_overwrite_existing_cert_dir(tmp_path):
    out = tmp_path / "g1"
    out.mkdir()
    (out / "sentinel").write_text("keep", encoding="utf-8")
    key = tmp_path / "signing.key"
    key.write_text("dummy-key", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Refusing to overwrite"):
        run_ceremony([
            "--cert-dir", str(out),
            "--config-out", str(tmp_path / "g1.json"),
            "--authority-host", "127.0.0.1:18443",
            "--projection-host", "127.0.0.1:18444",
            "--db-url", "mysql://synthetic-user:synthetic-password@h/db",
            "--data-plane-store", "mysql://synthetic-user:synthetic-password@h/store",
            "--signing-key", str(key),
        ])
