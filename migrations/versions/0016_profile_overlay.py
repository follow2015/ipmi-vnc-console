"""Tenant subset overlays, immutable revisions and operator identity evidence."""
import uuid

from alembic import op
import sqlalchemy as sa

revision = '0016_profile_overlay'
down_revision = '0015_pipeline_recipe_identity'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('kvm_profile_overlay',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), nullable=False),
        sa.Column('base_profile_id', sa.String(36), nullable=False),
        sa.Column('current_revision', sa.Integer(), nullable=False),
        sa.Column('state', sa.String(32), nullable=False),
        sa.UniqueConstraint('tenant_id', 'base_profile_id', name='uq_kvm_overlay_tenant_base'))
    op.create_index('ix_kvm_overlay_tenant_state_base', 'kvm_profile_overlay',
                    ['tenant_id', 'state', 'base_profile_id'])
    op.create_table('kvm_profile_overlay_revision',
        sa.Column('overlay_id', sa.String(36), primary_key=True),
        sa.Column('revision', sa.Integer(), primary_key=True),
        sa.Column('base_revision', sa.Integer(), nullable=False),
        sa.Column('state', sa.String(32), nullable=False),
        sa.Column('subset_json', sa.Text(), nullable=False),
        sa.Column('base_versions_json', sa.Text(), nullable=False),
        sa.Column('created_by', sa.String(128), nullable=False),
        sa.Column('created', sa.Float(precision=53), nullable=False))
    op.create_table('kvm_asset_overlay_binding',
        sa.Column('asset_id', sa.String(36), primary_key=True),
        sa.Column('overlay_id', sa.String(36), nullable=False),
        sa.Column('revision', sa.Integer(), nullable=False))
    op.create_index('ix_kvm_asset_overlay_binding_overlay_id', 'kvm_asset_overlay_binding', ['overlay_id'])
    op.create_table('kvm_device_identity_evidence',
        sa.Column('asset_id', sa.String(36), primary_key=True),
        sa.Column('admission_revision', sa.Integer(), primary_key=True),
        sa.Column('identity_digest', sa.String(128), nullable=False),
        sa.Column('model_id', sa.String(36), nullable=False),
        sa.Column('firmware', sa.String(64), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=False),
        sa.Column('attested_by', sa.String(128), nullable=False),
        sa.Column('expires', sa.Float(precision=53), nullable=False))
    bind = op.get_bind()
    if not {'kvm_permission', 'kvm_role', 'kvm_role_permission'} <= set(sa.inspect(bind).get_table_names()):
        return
    meta = sa.MetaData()
    permission = sa.Table('kvm_permission', meta, autoload_with=bind)
    role = sa.Table('kvm_role', meta, autoload_with=bind)
    link = sa.Table('kvm_role_permission', meta, autoload_with=bind)
    code = 'profile.overlay.write'
    pid = bind.scalar(sa.select(permission.c.id).where(permission.c.code == code))
    if not pid:
        pid = str(uuid.uuid4())
        bind.execute(permission.insert().values(id=pid, code=code, name=code))
    rid = bind.scalar(sa.select(role.c.id).where(role.c.code == 'admin'))
    if rid and not bind.scalar(sa.select(link.c.role_id).where(
            link.c.role_id == rid, link.c.permission_id == pid)):
        bind.execute(link.insert().values(role_id=rid, permission_id=pid))


def downgrade():
    bind = op.get_bind()
    meta = sa.MetaData()
    if {'kvm_permission', 'kvm_role_permission'} <= set(sa.inspect(bind).get_table_names()):
        permission = sa.Table('kvm_permission', meta, autoload_with=bind)
        link = sa.Table('kvm_role_permission', meta, autoload_with=bind)
        pid = bind.scalar(sa.select(permission.c.id).where(permission.c.code == 'profile.overlay.write'))
        if pid:
            bind.execute(link.delete().where(link.c.permission_id == pid))
            bind.execute(permission.delete().where(permission.c.id == pid))
    for name in ('kvm_device_identity_evidence', 'kvm_asset_overlay_binding',
                 'kvm_profile_overlay_revision', 'kvm_profile_overlay'):
        op.drop_table(name)
