"""Explicit key identities and a monotonic anchor for the clock floor."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022_key_clock_anchor"
down_revision = "0021_epoch_timestamps_double"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("kvm_asset") as batch_op:
        batch_op.add_column(sa.Column("vnc_key_id", sa.String(16),
                                      nullable=False, server_default=""))
    with op.batch_alter_table("kvm_clock_watermark") as batch_op:
        batch_op.add_column(sa.Column("monotonic_anchor", sa.Float(precision=53),
                                      nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("suspicious_forward", sa.Integer(),
                                      nullable=False, server_default="0"))


def downgrade() -> None:
    with op.batch_alter_table("kvm_clock_watermark") as batch_op:
        batch_op.drop_column("suspicious_forward")
        batch_op.drop_column("monotonic_anchor")
    with op.batch_alter_table("kvm_asset") as batch_op:
        batch_op.drop_column("vnc_key_id")
