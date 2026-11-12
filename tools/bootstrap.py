"""Generate isolated local TLS identities and synthetic assets. Never contacts a BMC."""
import argparse
import base64
import datetime
import hashlib
import ipaddress
import json
import os
import secrets
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from kvmhub.common import BMC_BASE_URL, INTERNAL_ORIGIN, UI_ORIGIN, digest
from kvmhub.store import Store


def generate(root):
    root = Path(root).resolve()
    if root.exists():
        raise SystemExit(f"Refusing to overwrite {root}; choose a fresh --directory")
    root.mkdir(parents=True, mode=0o700)
    os.chmod(root, 0o700)

    def save(name, data):
        path = root / name
        with path.open("xb") as f:
            os.chmod(path, 0o600)
            f.write(data.encode() if isinstance(data, str) else data)
        return str(path)

    def key_bytes(key):
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "KVM Hub local demo CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
          .not_valid_after(now+datetime.timedelta(days=7)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                      crl_sign=True, encipher_only=None, decipher_only=None), True)
          .sign(ca_key, hashes.SHA256()))
    ca_path = save("ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    instance = uuid.uuid4().hex

    def identity(label, client=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
                .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=7))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                            data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                            crl_sign=False, encipher_only=None, decipher_only=None), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), False))
        if not client:
            cert = cert.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("*.kvm.localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        cert = cert.sign(ca_key, hashes.SHA256())
        return save(label+".pem", cert.public_bytes(serialization.Encoding.PEM)), save(label+".key", key_bytes(key)), cert

    server_cert, server_key, _ = identity("server")
    client_cert, client_key, _ = identity("w1-"+instance, True)
    mock_cert, mock_key, mock = identity("mock")
    signing = ed25519.Ed25519PrivateKey.generate()
    signing_path = save("signing.key", key_bytes(signing))
    public = save("signing.pub", signing.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    encryption = secrets.token_bytes(32)
    encryption_path = save("encryption.key", base64.b64encode(encryption))
    login = secrets.token_urlsafe(32)
    save("login-token", login+"\n")
    proof = secrets.token_urlsafe(32)
    proof_path = save("worker-proof", proof+"\n")
    mock_user, mock_password = "synthetic-user", secrets.token_urlsafe(32)
    fingerprint = mock.fingerprint(hashes.SHA256()).hex()
    database = str(root/"manager.sqlite3")
    store = Store(database, encryption)
    store.seed_mock(BMC_BASE_URL, fingerprint, mock_user, mock_password)
    store.close()
    os.chmod(database, 0o600)
    manager = {"database": database, "encryption_key": encryption_path, "signing_key": signing_path,
               "worker_id": "w1", "instance_id": instance, "login_hash": digest(login),
               "worker_proof_hash": digest(proof), "manager_origin": UI_ORIGIN,
               "ca": ca_path, "server_cert": server_cert, "server_key": server_key}
    worker = {"worker_id": "w1", "instance_id": instance, "public_key": public,
              "manager_origin": UI_ORIGIN, "manager_internal": INTERNAL_ORIGIN,
              "ca": ca_path, "client_cert": client_cert, "client_key": client_key,
              "worker_proof": proof_path, "server_cert": server_cert, "server_key": server_key}
    mock_cfg = {"username": mock_user, "password": mock_password, "cert": mock_cert, "key": mock_key}
    for name, value in (("manager.json", manager), ("worker.json", worker), ("mock.json", mock_cfg)):
        save(name, json.dumps(value, indent=2)+"\n")
    save(".gitignore", "*\n!.gitignore\n")
    return root


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", default=".local")
    args = parser.parse_args()
    generated = generate(args.directory)
    print(f"Local synthetic fixtures created: {generated}\nStart: .venv/bin/python -m kvmhub.run --directory {generated}\nLogin token file: {generated / 'login-token'}")
