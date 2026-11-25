#!/usr/bin/env python3
"""Offline key ceremony for G1 managed admission."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kvmhub.g1_certs import generate_g1_identities, g1_config_template  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cert-dir", required=True, help="fresh directory for CA/certs/keys")
    p.add_argument("--config-out", required=True, help="path for the pinned G1 JSON config")
    p.add_argument("--authority-host", required=True, help="authority listener host:port")
    p.add_argument("--projection-host", required=True, help="projection listener host:port")
    p.add_argument("--db-url", required=True, help="control-plane MySQL DSN")
    p.add_argument("--data-plane-store", required=True, help="data-plane Store DSN")
    p.add_argument("--signing-key", required=True,
                   help="absolute path to the data plane's existing EdDSA signing.key")
    p.add_argument("--valid-days", type=int, default=825)
    return p


def run_ceremony(argv: list[str] | None = None) -> dict:
    args = build_parser().parse_args(argv)
    cert_dir = Path(args.cert_dir)
    config_out = Path(args.config_out)
    if config_out.exists():
        raise RuntimeError(f"Refusing to overwrite existing config: {config_out}")

    generate_g1_identities(cert_dir, authority_host=args.authority_host,
                           valid_days=args.valid_days)
    signing_key = Path(args.signing_key).resolve()
    if not signing_key.is_file():
        raise RuntimeError(f"signing key not found: {signing_key}")
    doc = g1_config_template(
        cert_dir, authority_host=args.authority_host,
        projection_host=args.projection_host, db_url=args.db_url,
        data_plane_store=args.data_plane_store,
        signing_key_path=str(signing_key), config_out=config_out)
    payload = json.dumps(doc, indent=2) + "\n"
    with config_out.open("x", encoding="utf-8") as handle:
        os.chmod(config_out, 0o600)
        handle.write(payload)
    return {"ok": True, "cert_dir": str(cert_dir), "config": str(config_out),
            "files": sorted(p.name for p in cert_dir.iterdir())}


def main() -> int:
    result = run_ceremony()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
