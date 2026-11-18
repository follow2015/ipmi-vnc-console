"""Tenant capability tier: use-only (consumer) vs full management (manager)."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0005_tenant_mode"
down_revision = "0004_integration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "kvm_tenant",
        sa.Column("mode", sa.String(32), nullable=False, server_default="manager"),
    )


def downgrade() -> None:
    op.drop_column("kvm_tenant", "mode")
