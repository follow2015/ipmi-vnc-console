"""multi-tenant: kvm_tenant + tenant_id on every business table"""
from __future__ import annotations

import time

import sqlalchemy as sa
from alembic import op

revision = "0002_tenant"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"
TENANT_COLUMNS = {
    "kvm_user": True,
    "kvm_asset": True,
    "kvm_credential": True,
    "kvm_access_grant": True,
    "kvm_audit_log": True,
    "kvm_vendor_profile": False,
    "kvm_capability": False,
}
AUDIT_COLUMNS = ("actor_type", "actor_tenant")
TENANT_INDEXES = {
    "kvm_user": {"ix_kvm_user_tenant_id": ["tenant_id"]},
    "kvm_asset": {"ix_kvm_asset_tenant_id": ["tenant_id"],
                  "ix_kvm_asset_tenant_address": ["tenant_id", "address"]},
    "kvm_credential": {"ix_kvm_credential_tenant_id": ["tenant_id"]},
    "kvm_access_grant": {"ix_kvm_access_grant_tenant_id": ["tenant_id"]},
    "kvm_audit_log": {"ix_kvm_audit_log_tenant_id": ["tenant_id"],
                      "ix_kvm_audit_tenant_ts": ["tenant_id", "ts"]},
    "kvm_vendor_profile": {"ix_kvm_vendor_profile_tenant_id": ["tenant_id"]},
    "kvm_capability": {"ix_kvm_capability_tenant_id": ["tenant_id"]},
}


def _inspector():
    return sa.inspect(op.get_bind())


def _column_names(table: str) -> set[str]:
    inspector = _inspector()
    if table not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table)}


def _index_names(table: str) -> set[str]:
    inspector = _inspector()
    if table not in inspector.get_table_names():
        return set()
    return {index["name"] for index in inspector.get_indexes(table)}


def _unique_names(table: str) -> set[str]:
    inspector = _inspector()
    if table not in inspector.get_table_names():
        return set()
    names = {item.get("name") for item in inspector.get_unique_constraints(table)}
    for index in inspector.get_indexes(table):
        if index.get("unique"):
            names.add(index.get("name"))
    return {name for name in names if name}


def _create_tenant_table() -> None:
    inspector = _inspector()
    if "kvm_tenant" in inspector.get_table_names():
        return
    op.create_table(
        "kvm_tenant",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("code", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(128), nullable=False, server_default=""),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("plan", sa.String(64), nullable=False, server_default="standard"),
        sa.Column("quotas_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created", sa.Float(), nullable=False, server_default="0"),
    )


def _seed_default_tenant() -> None:
    bind = op.get_bind()
    exists = bind.execute(
        sa.text("SELECT 1 FROM kvm_tenant WHERE id = :id"), {"id": DEFAULT_TENANT_ID}).first()
    if exists:
        return
    bind.execute(
        sa.text("INSERT INTO kvm_tenant (id, code, name, status, plan, quotas_json, created) "
                "VALUES (:id, :code, :name, 'active', 'standard', '{}', :created)"),
        {"id": DEFAULT_TENANT_ID, "code": "default", "name": "默认租户",
         "created": time.time()})


def _add_tenant_column(table: str, *, tenant_owned: bool) -> bool:
    if "tenant_id" in _column_names(table):
        return False
    op.add_column(table, sa.Column("tenant_id", sa.String(36), nullable=True,
                                   server_default=DEFAULT_TENANT_ID if tenant_owned else None))
    return True


def _drop_default(table: str, column: str) -> None:
    if column not in _column_names(table):
        return
    with op.batch_alter_table(table) as batch:
        batch.alter_column(column, server_default=None,
                           existing_type=sa.String(36) if column == "tenant_id" else sa.String(16),
                           existing_nullable=True)


def _add_audit_columns() -> None:
    columns = _column_names("kvm_audit_log")
    if "actor_type" not in columns:
        op.add_column("kvm_audit_log", sa.Column("actor_type", sa.String(16),
                                                 nullable=True, server_default="user"))
    if "actor_tenant" not in columns:
        op.add_column("kvm_audit_log", sa.Column("actor_tenant", sa.String(36), nullable=True))


def _create_indexes() -> None:
    for table, wanted in TENANT_INDEXES.items():
        existing = _index_names(table)
        for name, columns in wanted.items():
            if name not in existing:
                op.create_index(name, table, columns)


def _drop_indexes() -> None:
    for table, wanted in TENANT_INDEXES.items():
        existing = _index_names(table)
        for name in wanted:
            if name in existing:
                op.drop_index(name, table_name=table)


def _user_unique_per_tenant() -> None:
    names = _unique_names("kvm_user")
    if "uq_kvm_user_tenant_username" in names:
        return
    with op.batch_alter_table("kvm_user") as batch:
        if "uq_kvm_user_username" in names:
            batch.drop_constraint("uq_kvm_user_username", type_="unique")
        batch.create_unique_constraint("uq_kvm_user_tenant_username",
                                       ["tenant_id", "username"])


def upgrade() -> None:
    bind = op.get_bind()
    _create_tenant_table()
    _seed_default_tenant()
    for table, tenant_owned in TENANT_COLUMNS.items():
        added = _add_tenant_column(table, tenant_owned=tenant_owned)
        if tenant_owned:
            bind.execute(sa.text(
                f"UPDATE {table} SET tenant_id = :tid WHERE tenant_id IS NULL"),
                {"tid": DEFAULT_TENANT_ID})
        if added:
            _drop_default(table, "tenant_id")
    _add_audit_columns()
    _drop_default("kvm_audit_log", "actor_type")
    _create_indexes()
    _user_unique_per_tenant()


def downgrade() -> None:
    bind = op.get_bind()
    _drop_indexes()
    if "uq_kvm_user_tenant_username" in _unique_names("kvm_user"):
        with op.batch_alter_table("kvm_user") as batch:
            batch.drop_constraint("uq_kvm_user_tenant_username", type_="unique")
            batch.create_unique_constraint("uq_kvm_user_username", ["username"])
    for table in TENANT_COLUMNS:
        if table not in _inspector().get_table_names():
            continue
        if "tenant_id" in _column_names(table):
            with op.batch_alter_table(table) as batch:
                batch.drop_column("tenant_id")
    if "kvm_audit_log" in _inspector().get_table_names():
        for column in AUDIT_COLUMNS:
            if column in _column_names("kvm_audit_log"):
                with op.batch_alter_table("kvm_audit_log") as batch:
                    batch.drop_column(column)
    bind.execute(sa.text("DROP TABLE IF EXISTS kvm_tenant"))
