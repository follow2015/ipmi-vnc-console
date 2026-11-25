"""Generate the isolated mTLS identities for G1 managed admission."""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

AUTHORITY_SERVER = "authority-server"
AUTHORITY_CLIENT = "kvmhub-authority-client"
PLATFORM_CLIENT = "kvmhub-platform-client"
PROJECTOR = "kvmhub-projector"
CLIENT_ROLES = (AUTHORITY_CLIENT, PLATFORM_CLIENT, PROJECTOR)

G1_CERT_FILES = (
    "ca.pem",
    "authority-server.pem", "authority-server.key",
    f"{AUTHORITY_CLIENT}.pem", f"{AUTHORITY_CLIENT}.key",
    f"{PLATFORM_CLIENT}.pem", f"{PLATFORM_CLIENT}.key",
    f"{PROJECTOR}.pem", f"{PROJECTOR}.key",
)

VALID_DAYS = 825


def _save(root: Path, name: str, data: bytes) -> str:
    path = root / name
    with path.open("xb") as handle:
        os.chmod(path, 0o600)
        handle.write(data)
    return str(path)


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def generate_g1_identities(root: Path, *, authority_host: str,
                           valid_days: int = VALID_DAYS) -> Path:
    root = Path(root).resolve()
    if root.exists():
        raise RuntimeError(f"Refusing to overwrite {root}: choose a fresh directory")
    root.mkdir(parents=True, mode=0o700)
    os.chmod(root, 0o700)

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "KVM Hub G1 CA")])
    ca = (x509.CertificateBuilder()
          .subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=1))
          .not_valid_after(now + datetime.timedelta(days=valid_days))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.KeyUsage(
              digital_signature=False, content_commitment=False,
              key_encipherment=False, data_encipherment=False,
              key_agreement=False, key_cert_sign=True, crl_sign=True,
              encipher_only=None, decipher_only=None), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
              ca_key.public_key()), False)
          .sign(ca_key, hashes.SHA256()))
    _save(root, "ca.pem", ca.public_bytes(serialization.Encoding.PEM))

    def identity(label: str, *, client: bool, host: str | None = None) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
                   .issuer_name(ca.subject)
                   .public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(minutes=1))
                   .not_valid_after(now + datetime.timedelta(days=valid_days))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                       ca_key.public_key()), False)
                   .add_extension(x509.KeyUsage(
                       digital_signature=True, content_commitment=False,
                       key_encipherment=True, data_encipherment=False,
                       key_agreement=False, key_cert_sign=False, crl_sign=False,
                       encipher_only=None, decipher_only=None), True)
                   .add_extension(x509.ExtendedKeyUsage([
                       ExtendedKeyUsageOID.CLIENT_AUTH if client
                       else ExtendedKeyUsageOID.SERVER_AUTH]), False))
        if not client:
            san_entries = []
            clean = str(host or "localhost").strip()
            if ":" in clean:
                clean = clean.rsplit(":", 1)[0]
            try:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(clean)))
            except ValueError:
                san_entries.append(x509.DNSName(clean))
            san_entries.append(x509.DNSName("localhost"))
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_entries), False)
        cert = builder.sign(ca_key, hashes.SHA256())
        _save(root, f"{label}.pem", cert.public_bytes(serialization.Encoding.PEM))
        _save(root, f"{label}.key", _key_pem(key))

    identity(AUTHORITY_SERVER, client=False, host=authority_host)
    for role in CLIENT_ROLES:
        identity(role, client=True)

    return root


def g1_config_template(cert_dir: Path, *, authority_host: str,
                       projection_host: str, db_url: str,
                       data_plane_store: str, signing_key_path: str,
                       config_out: Path | None = None) -> dict:
    import os
    host = str(authority_host).strip()
    authority_url = host if host.startswith("https://") else f"https://{host}"
    base_dir = Path(config_out).resolve().parent if config_out else Path(cert_dir).resolve()
    prefix = os.path.relpath(Path(cert_dir).resolve(), base_dir)
    def cert(name: str) -> str:
        return f"{prefix}/{name}" if prefix != "." else name
    return {
        "db_url": db_url,
        "data_plane_store": data_plane_store,
        "authority_url": authority_url,
        "authority_host": host.replace("https://", "", 1),
        "projection_host": projection_host,
        "signing_key": signing_key_path,
        "ca": cert("ca.pem"),
        "server_cert": cert(f"{AUTHORITY_SERVER}.pem"),
        "server_key": cert(f"{AUTHORITY_SERVER}.key"),
        "authority_cert": cert(f"{AUTHORITY_CLIENT}.pem"),
        "authority_key": cert(f"{AUTHORITY_CLIENT}.key"),
        "projector_cert": cert(f"{PROJECTOR}.pem"),
        "projector_key": cert(f"{PROJECTOR}.key"),
        "authority_cert_cn": AUTHORITY_CLIENT,
        "platform_cert_cn": PLATFORM_CLIENT,
        "projector_cert_cn": PROJECTOR,
    }
