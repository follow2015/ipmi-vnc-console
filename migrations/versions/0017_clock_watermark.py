"""Control-plane clock high-water mark."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017_clock_watermark"
down_revision = "0016_profile_overlay"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kvm_clock_watermark",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("high_water", sa.Float(precision=53), nullable=False),
        sa.Column("observed", sa.Float(precision=53), nullable=False),
        sa.Column("regressions", sa.Integer(), nullable=False))


def downgrade() -> None:
    op.drop_table("kvm_clock_watermark")
