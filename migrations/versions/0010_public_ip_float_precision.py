"""Public-IP alias timestamps must be DOUBLE, not MySQL 4-byte FLOAT."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010_public_ip_float_precision"
down_revision = "0009_public_ip"
branch_labels = None
depends_on = None


def _retype(batch_op, precision):
    batch_op.alter_column(
        "created", existing_type=sa.Float(), type_=sa.Float(precision=precision),
        existing_nullable=False)
    batch_op.alter_column(
        "updated", existing_type=sa.Float(), type_=sa.Float(precision=precision),
        existing_nullable=False)


def upgrade() -> None:
    with op.batch_alter_table("kvm_public_ip") as batch_op:
        _retype(batch_op, 53)


def downgrade() -> None:
    with op.batch_alter_table("kvm_public_ip") as batch_op:
        _retype(batch_op, None)
