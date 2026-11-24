#!/usr/bin/env -S python3
"""Renew the local mTLS gateway certificates WITHOUT rotating any secret."""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def load_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def save(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(path)


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gateway", required=True)
    ap.add_argument("--days", type=int, default=3650)
    args = ap.parse_args(argv)
    root = Path(args.gateway).resolve()
    if not root.is_dir():
        raise SystemExit(f"gateway directory not found: {root}")

    worker_cfg = json.loads((root / "worker.json").read_text(encoding="utf-8"))
    manager_cfg = json.loads((root / "manager.json").read_text(encoding="utf-8"))
    instance = worker_cfg["instance_id"]
    client_cn = f"w1-{instance}"
    if manager_cfg.get("worker_cert_cn") != client_cn:
        raise SystemExit(f"worker_cert_cn mismatch: {manager_cfg.get('worker_cert_cn')} != {client_cn}")

    ca_key_path = root / "ca.key"
    if ca_key_path.exists():
        ca_key = load_key(ca_key_path)
        print("reusing stored CA key", ca_key_path)
    else:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        save(ca_key_path, ca_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        print("generated and persisted new CA key", ca_key_path)

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(minutes=5)
    not_after = now + datetime.timedelta(days=args.days)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "KVM Hub local CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(not_before).not_valid_after(not_after)
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True, crl_sign=True,
                                      encipher_only=None, decipher_only=None), True)
          .sign(ca_key, hashes.SHA256()))
    save(root / "ca.pem", pem(ca))

    def sign_leaf(label: str, key_path: Path, *, client: bool) -> None:
        key = load_key(key_path)
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
                   .issuer_name(ca.subject).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(not_before).not_valid_after(not_after)
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                               key_encipherment=True, data_encipherment=False,
                                               key_agreement=False, key_cert_sign=False, crl_sign=False,
                                               encipher_only=None, decipher_only=None), True)
                   .add_extension(x509.ExtendedKeyUsage(
                       [ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), False))
        if not client:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.DNSName("*.kvm.localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        cert = builder.sign(ca_key, hashes.SHA256())
        save(root / f"{label}.pem", pem(cert))
        print("re-signed", label, "valid until", not_after.date())

    sign_leaf("server", root / "server.key", client=False)
    sign_leaf(client_cn, root / f"{client_cn}.key", client=True)
    mock_key = root / "mock.key"
    if mock_key.exists():
        sign_leaf("mock", mock_key, client=False)

    print("OK: gateway certificates renewed; restart kvmhub-data to pick them up")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
