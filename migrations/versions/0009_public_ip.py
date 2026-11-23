"""Tenant-facing public IP aliases, keyed by asset row id."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0009_public_ip"
down_revision = "0008_vendor_protocol"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kvm_public_ip",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("asset_id", sa.String(36),
                  sa.ForeignKey("kvm_asset.id", ondelete="CASCADE"),
                  nullable=False, unique=True),
        sa.Column("primary_ip", sa.String(256), nullable=False),
        sa.Column("additional_ips", sa.Text, nullable=False),
        sa.Column("created", sa.Float, nullable=False),
        sa.Column("updated", sa.Float, nullable=False),
    )
    op.create_index("ix_kvm_public_ip_tenant_primary", "kvm_public_ip",
                    ["tenant_id", "primary_ip"])


def downgrade() -> None:
    op.drop_index("ix_kvm_public_ip_tenant_primary", table_name="kvm_public_ip")
    op.drop_table("kvm_public_ip")
