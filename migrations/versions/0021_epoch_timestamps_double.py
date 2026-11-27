"""Every control-plane epoch column must be DOUBLE, not MySQL 4-byte FLOAT."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0021_epoch_timestamps_double"
down_revision = "0020_profile_access_params"
branch_labels = None
depends_on = None

COLUMNS = {
    "kvm_asset_connection": (("created", False),),
    "kvm_asset_group": (("created", False), ("updated", False)),
    "kvm_audit_log": (("ts", False),),
    "kvm_clock_watermark": (("high_water", False), ("observed", False)),
    "kvm_credential": (("created", False), ("rotated_at", True)),
    "kvm_device_admission": (("review_due", False), ("expires", False), ("created", False)),
    "kvm_plane_outbox": (("created", False), ("lease_until", False), ("next_attempt", False)),
    "kvm_plane_projection": (("ack_at", False),),
    "kvm_probe_candidate": (("created", False), ("resolved", False)),
    "kvm_probe_task": (("created", False), ("updated", False)),
    "kvm_role": (("created", False),),
    "kvm_tenant": (("created", False),),
    "kvm_user": (("locked_until", False), ("created", False), ("last_login", True)),
    "kvm_vendor_profile": (("approved_at", False), ("review_due", False), ("created", False)),
    "kvm_capability": (("expires", False), ("approved_at", False), ("effective_from", False),
                       ("review_due", False), ("created", False)),
    "kvm_service_token": (("expires", True), ("created", False), ("revoked", True),
                          ("last_used", True)),
    "kvm_asset": (("created", False), ("updated", False)),
    "kvm_access_grant": (("expires", False), ("created", False)),
}


def _retype(batch_op, precision, columns):
    for name, nullable in columns:
        batch_op.alter_column(
            name,
            existing_type=sa.Float(),
            type_=sa.Float(precision=precision),
            existing_nullable=nullable)


def upgrade() -> None:
    for table, columns in COLUMNS.items():
        with op.batch_alter_table(table) as batch_op:
            _retype(batch_op, 53, columns)


def downgrade() -> None:
    for table, columns in COLUMNS.items():
        with op.batch_alter_table(table) as batch_op:
            _retype(batch_op, None, columns)
