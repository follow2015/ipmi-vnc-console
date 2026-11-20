"""Asset groups and grant provenance for batch authorization."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0006_asset_group"
down_revision = "0005_tenant_mode"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kvm_asset_group",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("created", sa.Float, nullable=False),
        sa.Column("updated", sa.Float, nullable=False),
    )
    op.create_table(
        "kvm_asset_group_member",
        sa.Column("group_id", sa.String(36),
                  sa.ForeignKey("kvm_asset_group.id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("asset_id", sa.String(36),
                  sa.ForeignKey("kvm_asset.id", ondelete="CASCADE"),
                  primary_key=True),
    )
    op.create_table(
        "kvm_grant_source",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), nullable=False, index=True),
        sa.Column("asset_id", sa.String(36), nullable=False, index=True),
        sa.Column("group_id", sa.String(36),
                  sa.ForeignKey("kvm_asset_group.id", ondelete="SET NULL"),
                  nullable=True),
        sa.UniqueConstraint("user_id", "asset_id", "group_id",
                            name="uq_grant_source"),
    )


def downgrade() -> None:
    op.drop_table("kvm_grant_source")
    op.drop_table("kvm_asset_group_member")
    op.drop_table("kvm_asset_group")
