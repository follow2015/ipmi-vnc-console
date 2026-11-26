"""Staging table for measured identity changes."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0018_probe_candidate"
down_revision = "0017_clock_watermark"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kvm_probe_candidate",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("state", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("vendor", sa.String(128), nullable=False, server_default=""),
        sa.Column("model", sa.String(128), nullable=False, server_default=""),
        sa.Column("firmware", sa.String(64), nullable=False, server_default=""),
        sa.Column("profile_id", sa.String(36), nullable=True),
        sa.Column("capability_id", sa.String(36), nullable=True),
        sa.Column("fingerprint", sa.String(128), nullable=False, server_default=""),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created", sa.Float(), nullable=False),
        sa.Column("resolved", sa.Float(), nullable=False, server_default="0"),
        sa.Column("resolved_by", sa.String(128), nullable=False, server_default=""))
    op.create_index("ix_kvm_probe_candidate_asset_id", "kvm_probe_candidate", ["asset_id"])
    op.create_index("ix_kvm_probe_candidate_tenant_id", "kvm_probe_candidate", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_kvm_probe_candidate_tenant_id", table_name="kvm_probe_candidate")
    op.drop_index("ix_kvm_probe_candidate_asset_id", table_name="kvm_probe_candidate")
    op.drop_table("kvm_probe_candidate")
