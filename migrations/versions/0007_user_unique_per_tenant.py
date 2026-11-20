"""Drop the legacy global username uniqueness on kvm_user."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0007_user_unique_per_tenant"
down_revision = "0006_asset_group"
branch_labels = None
depends_on = None

LEGACY = ("uq_kvm_user_username", "username")
TENANT_UNIQUE = "uq_kvm_user_tenant_username"


def _names():
    inspector = sa.inspect(op.get_bind())
    indexes = {item.get("name") for item in inspector.get_indexes("kvm_user")
               if item.get("unique")}
    constraints = {item.get("name") for item in inspector.get_unique_constraints("kvm_user")}
    return indexes, constraints


def _duplicated_usernames() -> bool:
    bind = op.get_bind()
    row = bind.execute(sa.text(
        "SELECT username FROM kvm_user GROUP BY username HAVING COUNT(*) > 1 LIMIT 1")).first()
    return row is not None


def upgrade() -> None:
    indexes, constraints = _names()
    with op.batch_alter_table("kvm_user") as batch:
        for name in LEGACY:
            if name in indexes:
                batch.drop_index(name)
            elif name in constraints:
                batch.drop_constraint(name, type_="unique")
        if TENANT_UNIQUE not in indexes and TENANT_UNIQUE not in constraints:
            batch.create_unique_constraint(TENANT_UNIQUE, ["tenant_id", "username"])


def downgrade() -> None:
    if _duplicated_usernames():
        raise RuntimeError("cannot restore global username uniqueness: duplicate usernames exist")
    indexes, constraints = _names()
    with op.batch_alter_table("kvm_user") as batch:
        if TENANT_UNIQUE in constraints:
            batch.drop_constraint(TENANT_UNIQUE, type_="unique")
        elif TENANT_UNIQUE in indexes:
            batch.drop_index(TENANT_UNIQUE)
        batch.create_unique_constraint("uq_kvm_user_username", ["username"])
