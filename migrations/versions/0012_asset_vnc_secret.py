"""Hidden VNC-only credential columns on kvm_asset."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012_asset_vnc_secret"
down_revision = "0011_public_ip_alias_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("kvm_asset") as batch_op:
        batch_op.add_column(sa.Column("vnc_username_cipher", sa.LargeBinary(), nullable=True))
        batch_op.add_column(sa.Column("vnc_password_cipher", sa.LargeBinary(), nullable=True))
        batch_op.add_column(sa.Column("vnc_key_version", sa.Integer(),
                                      nullable=False, server_default="1"))


def downgrade() -> None:
    with op.batch_alter_table("kvm_asset") as batch_op:
        batch_op.drop_column("vnc_key_version")
        batch_op.drop_column("vnc_password_cipher")
        batch_op.drop_column("vnc_username_cipher")
