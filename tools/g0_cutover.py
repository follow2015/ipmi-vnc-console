#!/usr/bin/env python3
"""Auditable one-shot import of legacy-approved assets into G0."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sqlalchemy import select  # noqa: E402

from kvmhub.platform.config import settings  # noqa: E402
from kvmhub.platform.db import make_engine, session_factory, transaction  # noqa: E402
from kvmhub.platform.models import (Asset, Capability, Credential,  # noqa: E402
                                    ExecutionDomain, DeviceAdmission, AssetConnection)
from kvmhub.platform import connection_config  # noqa: E402

DEFAULT_DOMAIN = "prod-bmc"
POLICY_FINGERPRINT = "g1-prod-policy-20261125"
GENERATION = "g1-prod-gen-1"


@dataclass(frozen=True)
class Candidate:
    asset_id: str
    address: str
    tenant_id: str
    capability_id: str
    credential_id: str
    adapter: str
    evidence: str
    approver: str
    review_due: float
    expires: float
    skip_reason: str = ""


def collect(db, *, domain_id: str, now: float) -> dict:
    assets = db.scalars(select(Asset).order_by(Asset.id)).all()
    caps = {c.id: c for c in db.scalars(select(Capability)).all()}
    creds = set(db.scalars(select(Credential.id)).all())
    already = set(db.scalars(select(DeviceAdmission.asset_id).where(
        DeviceAdmission.domain_id == domain_id,
        DeviceAdmission.state == "approved")).all())

    candidates: list[Candidate] = []
    skipped: list[dict] = []
    for a in assets:
        cap = caps.get(a.capability_id) if a.capability_id else None
        reasons = []
        if cap is None:
            reasons.append("no_capability")
        elif cap.status != "verified":
            reasons.append(f"capability_{cap.status}")
        elif cap.expires and cap.expires <= now:
            reasons.append("capability_expired")
        if not a.credential_id or a.credential_id not in creds:
            reasons.append("no_credential")
        if not a.fingerprint:
            reasons.append("no_fingerprint")
        row = Candidate(
            asset_id=a.id, address=a.address, tenant_id=a.tenant_id,
            capability_id=str(a.capability_id or ""),
            credential_id=str(a.credential_id or ""),
            adapter=(cap.adapter if cap else "") or "",
            evidence=(cap.evidence if cap else "") or "",
            approver=(cap.approver if cap else "") or "",
            review_due=float(cap.review_due) if cap else 0.0,
            expires=float(cap.expires) if cap else 0.0,
        )
        if a.id in already:
            reasons.append("already_admitted")
        if reasons:
            skipped.append({"asset_id": a.id, "reasons": reasons})
        else:
            candidates.append(row)
    return {"candidates": candidates, "skipped": skipped,
            "already_admitted": sorted(already), "domain_id": domain_id}


def ensure_domain(db, *, domain_id: str, store_id: str, endpoint: str) -> None:
    row = db.get(ExecutionDomain, domain_id)
    if row is None:
        db.add(ExecutionDomain(domain_id=domain_id, store_id=store_id,
                               endpoint=endpoint, supported_schema='["v2"]',
                               policy_fingerprint=POLICY_FINGERPRINT,
                               generation=GENERATION, health="healthy"))
        db.flush()
        return
    problems = []
    if row.policy_fingerprint != POLICY_FINGERPRINT:
        problems.append("policy_fingerprint")
    if row.generation != GENERATION:
        problems.append("generation")
    if row.health != "healthy":
        problems.append("health")
    if problems:
        raise RuntimeError(f"domain {domain_id} conflicts on: {problems}")


def import_asset(db, *, row: Candidate, domain_id: str, now: float,
                 actor: str) -> dict:
    connection_config.record_change(db, asset_ids=[row.asset_id],
                                    reason="g0_cutover", actor=actor,
                                    now=now, domain_id=domain_id)
    connection_config.admit_asset(
        db, asset_id=row.asset_id, tenant_id=row.tenant_id or None,
        approver=row.approver or "platform-admin", evidence=row.evidence,
        review_due=row.review_due, expires=row.expires,
        domain_id=domain_id, actor=actor, now=now)
    return {"asset_id": row.asset_id, "imported": True}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--env-file", default="/opt/kvmhub/.env")
    p.add_argument("--domain", default=DEFAULT_DOMAIN)
    p.add_argument("--store-id", default="prod-main-store")
    p.add_argument("--endpoint", default="https://127.0.0.1:8444")
    p.add_argument("--actor", default="g0-cutover")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    cfg = settings(args.env_file)
    engine = make_engine(cfg.db_url)
    factory = session_factory(engine)
    now = time.time()
    try:
        with transaction(factory) as db:
            report = collect(db, domain_id=args.domain, now=now)
            if args.apply:
                if not report["candidates"]:
                    raise RuntimeError("no eligible assets; refusing empty apply")
                ensure_domain(db, domain_id=args.domain, store_id=args.store_id,
                              endpoint=args.endpoint)
                imported = [import_asset(db, row=c, domain_id=args.domain,
                                         now=now, actor=args.actor)
                            for c in report["candidates"]]
            else:
                imported = []
        out = {
            "ok": True, "mode": "dry-run" if args.dry_run else "apply",
            "domain_id": args.domain,
            "policy_fingerprint": POLICY_FINGERPRINT, "generation": GENERATION,
            "candidate_count": len(report["candidates"]),
            "skipped_count": len(report["skipped"]),
            "already_admitted_count": len(report["already_admitted"]),
            "candidates": [asdict(c) for c in report["candidates"]],
            "skipped": report["skipped"],
            "imported": imported,
        }
        print(json.dumps(out, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 2
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
