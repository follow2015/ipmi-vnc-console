"""Persisted progress for batch BMC probes."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019_probe_task"
down_revision = "0018_probe_candidate"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kvm_probe_task",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("state", sa.String(16), nullable=False, server_default="running"),
        sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created", sa.Float(), nullable=False),
        sa.Column("updated", sa.Float(), nullable=False, server_default="0"),
        sa.Column("items_json", sa.Text(), nullable=False))
    op.create_index("ix_kvm_probe_task_tenant_id", "kvm_probe_task", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_kvm_probe_task_tenant_id", table_name="kvm_probe_task")
    op.drop_table("kvm_probe_task")
