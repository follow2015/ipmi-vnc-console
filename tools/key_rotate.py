"""Out-of-band rotation of the BMC credential master key."""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402

from kvmhub.platform.config import settings  # noqa: E402
from kvmhub.platform.db import make_engine, session_factory, transaction  # noqa: E402
from kvmhub.platform.models import Asset, Credential  # noqa: E402
from kvmhub.platform.security import CredentialCipher  # noqa: E402
from kvmhub.platform import services  # noqa: E402


def _key(name: str) -> bytes:
    raw = os.environ.get(name, "")
    if not raw:
        raise SystemExit(f"{name} must be set (keys are never CLI arguments)")
    try:
        value = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise SystemExit(f"{name} must be base64 encoded") from exc
    if len(value) != 32:
        raise SystemExit(f"{name} must decode to exactly 32 bytes")
    return value


def _encrypted_rows(db):
    for row in db.scalars(select(Credential).order_by(Credential.created)):
        yield row, "username_cipher", "password_cipher", "key_version", ":username", ":password", row.id
    for row in db.scalars(select(Asset).where(
            Asset.vnc_username_cipher.is_not(None) | Asset.vnc_password_cipher.is_not(None)
    ).order_by(Asset.created)):
        yield (row, "vnc_username_cipher", "vnc_password_cipher", "vnc_key_version",
               ":vnc_username", ":vnc_password", "vnc:" + row.id)


def rotate(db, old: CredentialCipher, new: CredentialCipher, *, write: bool,
           actor: str, stamp: float) -> dict:
    rows = list(_encrypted_rows(db))
    versions = sorted({int(getattr(row, version) or 1)
                       for row, _, _, version, _, _, _ in rows})
    prepared = []
    for row, ufield, pfield, version, uaad, paad, _ in rows:
        username = old.decrypt(getattr(row, ufield), aad=row.id + uaad)
        password = old.decrypt(getattr(row, pfield), aad=row.id + paad)
        prepared.append((row, ufield, pfield, version, uaad, paad, username, password))
    counts = {"credential_rows": sum(isinstance(item[0], Credential) for item in rows),
              "vnc_rows": sum(isinstance(item[0], Asset) for item in rows)}
    if write:
        for row, ufield, pfield, version, uaad, paad, username, password in prepared:
            setattr(row, ufield, new.encrypt(username, aad=row.id + uaad))
            setattr(row, pfield, new.encrypt(password, aad=row.id + paad))
            setattr(row, version, int(getattr(row, version) or 1) + 1)
            if isinstance(row, Credential):
                row.rotated_at = stamp
            else:
                row.updated = stamp
        services.audit(db, actor, "credential_key_rotated",
                       detail={"rows": len(prepared), **counts, "from_versions": versions,
                               "to_version": (versions[-1] if versions else 1) + 1}, now=stamp)
    return {"rows": len(prepared), **counts, "key_versions_before": versions,
            "key_version_after": (versions[-1] if versions else 1) + 1 if write else None,
            "written": bool(write)}


def verify_all(db, cipher: CredentialCipher) -> dict:
    rows = list(_encrypted_rows(db))
    good, bad = 0, []
    for row, ufield, pfield, _, uaad, paad, identifier in rows:
        try:
            cipher.decrypt(getattr(row, ufield), aad=row.id + uaad)
            cipher.decrypt(getattr(row, pfield), aad=row.id + paad)
            good += 1
        except Exception:
            bad.append(identifier)
    return {"rows": len(rows),
            "credential_rows": sum(isinstance(item[0], Credential) for item in rows),
            "vnc_rows": sum(isinstance(item[0], Asset) for item in rows),
            "decryptable": good, "undecryptable": bad,
            "ok": not bad}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--env-file", help="path to .env; defaults to CWD/.env")
    p.add_argument("--actor", default="cli")
    p.add_argument("--dry-run", action="store_true", help="decrypt-check only, write nothing")
    p.add_argument("--verify", action="store_true", help="verify every row with the NEW key")
    args = p.parse_args()

    cfg = settings(args.env_file)
    old = CredentialCipher(_key("KVMHUB_OLD_CREDENTIAL_KEY"))
    new = CredentialCipher(_key("KVMHUB_NEW_CREDENTIAL_KEY"))
    engine = make_engine(cfg.db_url)
    factory = session_factory(engine)
    try:
        if args.verify:
            with transaction(factory) as db:
                result = verify_all(db, new)
            print(json.dumps({"mode": "verify", **result}, ensure_ascii=False))
            return 0 if result["ok"] else 1
        with transaction(factory) as db:
            result = rotate(db, old, new, write=not args.dry_run,
                            actor=args.actor, stamp=time.time())
        print(json.dumps({"mode": "dry-run" if args.dry_run else "rotate", **result},
                         ensure_ascii=False))
        return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
