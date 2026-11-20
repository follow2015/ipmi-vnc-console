"""Brand protocol strategy column on vendor profiles."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0008_vendor_protocol"
down_revision = "0007_user_unique_per_tenant"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "kvm_vendor_profile",
        sa.Column("protocol", sa.String(96), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("kvm_vendor_profile", "protocol")
