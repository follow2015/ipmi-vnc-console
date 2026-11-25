"""Recipe and bundle identity for the V1 video lane."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0015_pipeline_recipe_identity"
down_revision = "0014_admission_secret_revision"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("kvm_vendor_profile") as batch_op:
        batch_op.add_column(sa.Column("recipe_id", sa.String(96),
                                      nullable=False, server_default=""))
        batch_op.add_column(sa.Column("recipe_revision", sa.Integer(),
                                      nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("config_schema_version", sa.String(32),
                                      nullable=False, server_default="v1"))
    with op.batch_alter_table("kvm_capability") as batch_op:
        batch_op.add_column(sa.Column("bundle_revision", sa.String(128),
                                      nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("kvm_capability") as batch_op:
        batch_op.drop_column("bundle_revision")
    with op.batch_alter_table("kvm_vendor_profile") as batch_op:
        batch_op.drop_column("config_schema_version")
        batch_op.drop_column("recipe_revision")
        batch_op.drop_column("recipe_id")
