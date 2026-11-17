"""Service tokens and source-IP allowlists for the DCIM integration API."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0004_integration"
down_revision = "0003_quota_usage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("kvm_service_token"):
        return
    op.create_table(
        "kvm_service_token",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("kvm_tenant.id"), nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("kvm_user.id"), nullable=False),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("prefix", sa.String(16), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("allowlist_json", sa.Text, nullable=False),
        sa.Column("expires", sa.Float(), nullable=True),
        sa.Column("created", sa.Float(), nullable=False),
        sa.Column("revoked", sa.Float(), nullable=True),
        sa.Column("last_used", sa.Float(), nullable=True),
        sa.Column("created_by", sa.String(128), nullable=False, server_default=""),
        sa.UniqueConstraint("tenant_id", "label", name="uq_kvm_service_token_label"),
        sa.Index("ix_kvm_service_token_tenant_id", "tenant_id"),
    )


def downgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("kvm_service_token"):
        op.drop_table("kvm_service_token")
