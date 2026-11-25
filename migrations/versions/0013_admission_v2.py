"""Admission v2 authority records, outbox, projection and domain registry."""
from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op

revision = "0013_admission_v2"
down_revision = "0012_asset_vnc_secret"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kvm_device_admission",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("identity_digest", sa.String(128), nullable=False, server_default=""),
        sa.Column("domain_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("approver", sa.String(128), nullable=False, server_default=""),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("review_due", sa.Float(), nullable=False, server_default="0"),
        sa.Column("expires", sa.Float(), nullable=False, server_default="0"),
        sa.Column("created", sa.Float(), nullable=False),
        sa.UniqueConstraint("asset_id", "revision", name="uq_kvm_device_admission_revision"),
    )
    op.create_index("ix_kvm_device_admission_asset_id", "kvm_device_admission", ["asset_id"])
    op.create_index("ix_kvm_device_admission_tenant_id", "kvm_device_admission", ["tenant_id"])

    op.create_table(
        "kvm_asset_connection",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("endpoint_json", sa.Text(), nullable=False),
        sa.Column("adapter", sa.String(128), nullable=False, server_default=""),
        sa.Column("identity_policy", sa.Text(), nullable=False),
        sa.Column("source_versions_json", sa.Text(), nullable=False),
        sa.Column("secret_ref", sa.String(128), nullable=False, server_default=""),
        sa.Column("secret_source", sa.String(32), nullable=False, server_default=""),
        sa.Column("secret_revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("schema", sa.String(32), nullable=False, server_default="v2"),
        sa.Column("digest", sa.String(128), nullable=False, server_default=""),
        sa.Column("created", sa.Float(), nullable=False),
        sa.UniqueConstraint("asset_id", "revision", name="uq_kvm_asset_connection_revision"),
    )
    op.create_index("ix_kvm_asset_connection_asset_id", "kvm_asset_connection", ["asset_id"])

    op.create_table(
        "kvm_plane_outbox",
        sa.Column("event_id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("created", sa.Float(), nullable=False),
        sa.Column("lease_owner", sa.String(128), nullable=False, server_default=""),
        sa.Column("lease_until", sa.Float(), nullable=False, server_default="0"),
        sa.Column("next_attempt", sa.Float(), nullable=False, server_default="0"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_kvm_plane_outbox_asset_id", "kvm_plane_outbox", ["asset_id"])

    op.create_table(
        "kvm_plane_projection",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("domain_id", sa.String(64), nullable=False),
        sa.Column("desired_revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("desired_digest", sa.String(128), nullable=False, server_default=""),
        sa.Column("applied_revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("applied_digest", sa.String(128), nullable=False, server_default=""),
        sa.Column("generation", sa.String(64), nullable=False, server_default=""),
        sa.Column("policy_fingerprint", sa.String(128), nullable=False, server_default=""),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("ack_at", sa.Float(), nullable=False, server_default="0"),
        sa.UniqueConstraint("asset_id", "domain_id", name="uq_kvm_plane_projection_target"),
    )
    op.create_index("ix_kvm_plane_projection_asset_id", "kvm_plane_projection", ["asset_id"])

    op.create_table(
        "kvm_execution_domain",
        sa.Column("domain_id", sa.String(64), primary_key=True),
        sa.Column("store_id", sa.String(64), nullable=False, unique=True),
        sa.Column("endpoint", sa.String(256), nullable=False, server_default=""),
        sa.Column("supported_schema", sa.Text(), nullable=False),
        sa.Column("policy_fingerprint", sa.String(128), nullable=False, server_default=""),
        sa.Column("generation", sa.String(64), nullable=False, server_default=""),
        sa.Column("health", sa.String(32), nullable=False, server_default="unknown"),
    )

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    rbac_tables = {"kvm_permission", "kvm_role_permission", "kvm_role"}
    if rbac_tables <= tables:
        row = bind.execute(sa.text(
            "SELECT id FROM kvm_permission WHERE code='platform.asset.admit'")).fetchone()
        permission_id = row[0] if row else str(uuid.uuid4())
        if row is None:
            bind.execute(sa.text(
                "INSERT INTO kvm_permission (id, code, name) VALUES (:id, :code, :name)"),
                {"id": permission_id, "code": "platform.asset.admit",
                 "name": "platform.asset.admit"})
        ignore = "INSERT OR IGNORE" if bind.dialect.name == "sqlite" else "INSERT IGNORE"
        bind.execute(sa.text(
            f"{ignore} INTO kvm_role_permission (role_id, permission_id) "
            "SELECT id, :pid FROM kvm_role WHERE code='platform_admin'"),
            {"pid": permission_id})


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if {"kvm_permission", "kvm_role_permission"} <= tables:
        bind.execute(sa.text(
            "DELETE FROM kvm_role_permission WHERE permission_id IN "
            "(SELECT id FROM kvm_permission WHERE code='platform.asset.admit')"))
        bind.execute(sa.text(
            "DELETE FROM kvm_permission WHERE code='platform.asset.admit'"))
    for table in ("kvm_execution_domain", "kvm_plane_projection", "kvm_plane_outbox",
                  "kvm_asset_connection", "kvm_device_admission"):
        if table in set(sa.inspect(bind).get_table_names()):
            op.drop_table(table)
