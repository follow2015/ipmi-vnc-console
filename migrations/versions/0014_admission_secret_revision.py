"""Content revisions for credential secrets."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014_admission_secret_revision"
down_revision = "0013_admission_v2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("kvm_credential") as batch_op:
        batch_op.add_column(sa.Column("revision", sa.Integer(),
                                      nullable=False, server_default="1"))
    with op.batch_alter_table("kvm_asset") as batch_op:
        batch_op.add_column(sa.Column("vnc_secret_revision", sa.Integer(),
                                      nullable=False, server_default="1"))


def downgrade() -> None:
    with op.batch_alter_table("kvm_asset") as batch_op:
        batch_op.drop_column("vnc_secret_revision")
    with op.batch_alter_table("kvm_credential") as batch_op:
        batch_op.drop_column("revision")
