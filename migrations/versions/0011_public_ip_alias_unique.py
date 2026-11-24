"""Normalised public-IP aliases with a database uniqueness guard."""
from __future__ import annotations

import re
import uuid

from alembic import op
import sqlalchemy as sa

revision = "0011_public_ip_alias_unique"
down_revision = "0010_public_ip_float_precision"
branch_labels = None
depends_on = None

_SPLIT = re.compile(r"[,，;；\s]+")

_PUBLIC_IP = sa.table(
    "kvm_public_ip",
    sa.column("id", sa.String(36)),
    sa.column("tenant_id", sa.String(36)),
    sa.column("asset_id", sa.String(36)),
    sa.column("primary_ip", sa.String(256)),
    sa.column("additional_ips", sa.Text),
    sa.column("created", sa.Float),
    sa.column("updated", sa.Float),
)

_ALIAS = sa.table(
    "kvm_public_ip_alias",
    sa.column("id", sa.String(36)),
    sa.column("tenant_id", sa.String(36)),
    sa.column("ip", sa.String(256)),
    sa.column("asset_id", sa.String(36)),
    sa.column("mapping_id", sa.String(36)),
    sa.column("created", sa.Float),
    sa.column("updated", sa.Float),
)


def backfill_aliases(conn) -> None:
    claimed: set[tuple[str, str]] = set()
    rows = conn.execute(sa.select(
        _PUBLIC_IP.c.id, _PUBLIC_IP.c.tenant_id, _PUBLIC_IP.c.asset_id,
        _PUBLIC_IP.c.primary_ip, _PUBLIC_IP.c.additional_ips,
        _PUBLIC_IP.c.created, _PUBLIC_IP.c.updated).order_by(
            _PUBLIC_IP.c.created, _PUBLIC_IP.c.id)).mappings()
    for row in rows:
        values = [row.primary_ip or ""]
        values.extend(part.strip() for part in _SPLIT.split(row.additional_ips or ""))
        for value in values:
            ip = value.strip().lower()
            if not ip:
                continue
            key = (row.tenant_id, ip)
            if key in claimed:
                print(f"WARNING: duplicate public IP claim ip={ip!r} "
                      f"tenant={row.tenant_id!r} mapping={row.id!r} skipped; "
                      "alias uniqueness guard does not cover this mapping")
                continue
            claimed.add(key)
            conn.execute(_ALIAS.insert().values(
                id=str(uuid.uuid4()), tenant_id=row.tenant_id, ip=ip,
                asset_id=row.asset_id, mapping_id=row.id,
                created=row.created or 0.0, updated=row.updated or 0.0))


def upgrade() -> None:
    op.create_table(
        "kvm_public_ip_alias",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("ip", sa.String(256), nullable=False),
        sa.Column("asset_id", sa.String(36),
                  sa.ForeignKey("kvm_asset.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("mapping_id", sa.String(36),
                  sa.ForeignKey("kvm_public_ip.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("created", sa.Float(precision=53), nullable=False),
        sa.Column("updated", sa.Float(precision=53), nullable=False),
        sa.UniqueConstraint("tenant_id", "ip",
                            name="uq_kvm_public_ip_alias_tenant_ip"),
    )
    op.create_index("ix_kvm_public_ip_alias_asset", "kvm_public_ip_alias",
                    ["asset_id"])

    backfill_aliases(op.get_bind())


def downgrade() -> None:
    op.drop_index("ix_kvm_public_ip_alias_asset", table_name="kvm_public_ip_alias")
    op.drop_table("kvm_public_ip_alias")
