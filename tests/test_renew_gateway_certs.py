"""Renewal must re-sign certs in place without rotating any secret or identity."""
import datetime
import json

from cryptography import x509

from tools.bootstrap import generate
from tools.renew_gateway_certs import main as renew_main


def _not_after(path):
    return x509.load_pem_x509_certificate(path.read_bytes()).not_valid_after_utc


def _ca_public_numbers(cert_bytes):
    return x509.load_pem_x509_certificate(cert_bytes).public_key().public_numbers()


def test_renew_extends_validity_keeps_keys_and_identity(tmp_path, capsys):
    root = generate(tmp_path / "gw")
    worker = json.loads((root / "worker.json").read_text())
    manager = json.loads((root / "manager.json").read_text())
    cn = f"w1-{worker['instance_id']}"
    client_cert = root / f"{cn}.pem"
    before_expiry = _not_after(client_cert)
    assert (before_expiry - datetime.datetime.now(datetime.timezone.utc)).days <= 8

    key_snapshot = {p.name: p.read_bytes() for p in root.glob("*.key")}
    secret_snapshot = {
        p.name: p.read_bytes() for p in root.glob("*")
        if p.name in {"encryption.key", "signing.key", "worker-proof", "login-token",
                      "manager.json", "worker.json"}
    }

    assert renew_main(["--gateway", str(root), "--days", "3650"]) == 0
    out = capsys.readouterr().out

    new_ca = x509.load_pem_x509_certificate((root / "ca.pem").read_bytes())
    for pem in ("server.pem", f"{cn}.pem", "mock.pem"):
        cert = x509.load_pem_x509_certificate((root / pem).read_bytes())
        assert cert.issuer == new_ca.subject
        assert cert.not_valid_after_utc.year >= datetime.datetime.now(datetime.timezone.utc).year + 8
    client = x509.load_pem_x509_certificate(client_cert.read_bytes())
    assert client.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME)[0].value == manager["worker_cert_cn"]

    for name, data in key_snapshot.items():
        assert (root / name).read_bytes() == data, name
    for name, data in secret_snapshot.items():
        assert (root / name).read_bytes() == data, name
    assert (root / "ca.key").exists()
    assert "re-signed server" in out


def test_renew_reuses_stored_ca_key(tmp_path, capsys):
    root = generate(tmp_path / "gw")
    renew_main(["--gateway", str(root), "--days", "3650"])
    ca_key_bytes = (root / "ca.key").read_bytes()
    ca_before = (root / "ca.pem").read_bytes()
    ca_pub_before = _ca_public_numbers(ca_before)
    renew_main(["--gateway", str(root), "--days", "3650"])
    assert (root / "ca.key").read_bytes() == ca_key_bytes
    assert _ca_public_numbers((root / "ca.pem").read_bytes()) == ca_pub_before
    assert "reusing stored CA key" in capsys.readouterr().out
