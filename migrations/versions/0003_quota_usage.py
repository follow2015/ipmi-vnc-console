"""Derived monthly usage roll-up (design §8.2)."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_quota_usage"
down_revision = "0002_tenant"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("kvm_quota_usage"):
        return
    op.create_table(
        "kvm_quota_usage",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("kvm_tenant.id"), nullable=False),
        sa.Column("period", sa.String(7), nullable=False),
        sa.Column("assets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sessions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("minutes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated", sa.Float(precision=53), nullable=False),
        sa.UniqueConstraint("tenant_id", "period", name="uq_kvm_quota_usage"),
    )
    op.create_index("ix_kvm_quota_usage_tenant_id", "kvm_quota_usage", ["tenant_id"])


def downgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("kvm_quota_usage"):
        op.drop_table("kvm_quota_usage")
