"""Access-template parameters on a brand profile."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020_profile_access_params"
down_revision = "0019_probe_task"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("kvm_vendor_profile",
                  sa.Column("access_params", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("kvm_vendor_profile", "access_params")
