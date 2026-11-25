"""G1 identity generation must be isolated, role-bound and fail-closed."""
from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from kvmhub.g1_certs import (G1_CERT_FILES, generate_g1_identities,
                             g1_config_template)

AUTH_CN = "kvmhub-authority-client"
PLATFORM_CN = "kvmhub-platform-client"
PROJ_CN = "kvmhub-projector"


def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _cn(cert: x509.Certificate) -> str:
    return cert.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME)[0].value


def test_generate_refuses_existing_directory(tmp_path):
    (tmp_path / "sentinel").write_text("keep", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Refusing to overwrite"):
        generate_g1_identities(tmp_path, authority_host="127.0.0.1")


def test_generate_does_not_create_a_new_signing_key(tmp_path):
    out = tmp_path / "g1"
    generate_g1_identities(out, authority_host="127.0.0.1")
    assert not (out / "signing.key").exists()


def test_generate_creates_all_required_files(tmp_path):
    out = tmp_path / "g1"
    generate_g1_identities(out, authority_host="127.0.0.1")
    for name in G1_CERT_FILES:
        assert (out / name).is_file(), name


def test_ca_private_key_is_never_persisted(tmp_path):
    out = tmp_path / "g1"
    generate_g1_identities(out, authority_host="127.0.0.1")
    assert not (out / "ca.key").exists()
    assert not any("ca" in p.name.lower() and "key" in p.name.lower()
                   for p in out.iterdir())


def test_role_common_names_match_config_contract(tmp_path):
    out = tmp_path / "g1"
    generate_g1_identities(out, authority_host="127.0.0.1")
    assert _cn(_load_cert(out / "kvmhub-authority-client.pem")) == AUTH_CN
    assert _cn(_load_cert(out / "kvmhub-platform-client.pem")) == PLATFORM_CN
    assert _cn(_load_cert(out / "kvmhub-projector.pem")) == PROJ_CN


def test_authority_server_cert_covers_the_listening_host(tmp_path):
    out = tmp_path / "g1"
    generate_g1_identities(out, authority_host="127.0.0.1")
    cert = _load_cert(out / "authority-server.pem")
    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    assert "127.0.0.1" in [str(v) for v in san.get_values_for_type(x509.IPAddress)] or \
        "127.0.0.1" in san.get_values_for_type(x509.DNSName)


def test_authority_host_with_port_yields_ip_san_not_dns_name(tmp_path):
    out = tmp_path / "g1"
    generate_g1_identities(out, authority_host="127.0.0.1:18443")
    cert = _load_cert(out / "authority-server.pem")
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ips = [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    assert "127.0.0.1" in ips, f"expected IP SAN 127.0.0.1, got {ips}"
    dns = san.get_values_for_type(x509.DNSName)
    assert not any(":" in d for d in dns), f"host:port must not become a DNS SAN: {dns}"


def test_ca_cert_has_keycertsign_for_strict_verifiers(tmp_path):
    out = tmp_path / "g1"
    generate_g1_identities(out, authority_host="127.0.0.1")
    ca = _load_cert(out / "ca.pem")
    ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is True
    import ssl
    ctx = ssl.create_default_context(cafile=str(out / "ca.pem"))
    ctx.load_cert_chain(str(out / "authority-server.pem"),
                        str(out / "authority-server.key"))


def test_client_certs_are_client_auth_only(tmp_path):
    out = tmp_path / "g1"
    generate_g1_identities(out, authority_host="127.0.0.1")
    for name in ("kvmhub-authority-client", "kvmhub-platform-client", "kvmhub-projector"):
        cert = _load_cert(out / f"{name}.pem")
        eku = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage).value
        assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku
        assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH not in eku


def test_private_keys_are_pkcs8_and_readable_only_by_owner(tmp_path):
    out = tmp_path / "g1"
    generate_g1_identities(out, authority_host="127.0.0.1")
    for name in ("authority-server", AUTH_CN, PLATFORM_CN, PROJ_CN):
        key_path = out / f"{name}.key"
        serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        mode = key_path.stat().st_mode & 0o777
        assert mode == 0o600, (name, oct(mode))


def test_config_template_uses_relative_paths_and_matching_cns(tmp_path):
    out = tmp_path / "g1"
    generate_g1_identities(out, authority_host="127.0.0.1")
    doc = g1_config_template(out, authority_host="127.0.0.1",
                             projection_host="127.0.0.1:18444",
                             data_plane_store="mysql+pymysql://synthetic-user:synthetic-password@h/db",
                             db_url="mysql+pymysql://synthetic-user:synthetic-password@h/db",
                             signing_key_path="/var/lib/kvmhub/gateway/signing.key")
    assert doc["authority_cert_cn"] == AUTH_CN
    assert doc["projector_cert_cn"] == PROJ_CN
    assert doc["ca"] == "ca.pem"
    assert doc["authority_url"] == "https://127.0.0.1"
    assert doc["signing_key"] == "/var/lib/kvmhub/gateway/signing.key"


def test_config_template_with_port_keeps_url_and_host_consistent(tmp_path):
    out = tmp_path / "g1"
    generate_g1_identities(out, authority_host="127.0.0.1")
    doc = g1_config_template(out, authority_host="127.0.0.1:18443",
                             projection_host="127.0.0.1:18444",
                             db_url="mysql://synthetic-user:synthetic-password@h/db",
                             data_plane_store="mysql://synthetic-user:synthetic-password@h/store",
                             signing_key_path="/var/lib/kvmhub/gateway/signing.key")
    assert doc["authority_url"] == "https://127.0.0.1:18443"
    assert doc["authority_host"] == "127.0.0.1:18443"
    from kvmhub.g1_runtime import _split_host
    assert _split_host(doc["authority_host"]) == ("127.0.0.1", 18443)
