"""Engine / session construction shared by MySQL (prod) and SQLite (dev, test)."""
from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .models import (Base, DEFAULT_TENANT_CODE, DEFAULT_TENANT_ID, Permission,
                     ROLE_ADMIN, ROLE_OPERATOR, ROLE_PERMISSIONS, ROLE_PLATFORM_ADMIN,
                     ROLE_VIEWER, Role, RolePermission, Tenant, User, UserRole)
from .security import hash_password

ROLE_LABELS = ((ROLE_ADMIN, "系统管理员"), (ROLE_OPERATOR, "运维操作员"),
               (ROLE_VIEWER, "只读观察者"), (ROLE_PLATFORM_ADMIN, "平台管理员"))


def make_engine(db_url: str, *, echo: bool = False) -> Engine:
    if db_url.startswith("sqlite"):
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in db_url:
            kwargs["poolclass"] = StaticPool
        return create_engine(db_url, echo=echo, **kwargs)
    return create_engine(db_url, echo=echo, pool_pre_ping=True, pool_recycle=3600,
                         pool_size=10, max_overflow=20)


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def init_schema(engine: Engine) -> None:
    Base.metadata.create_all(engine)


def seed_default_tenant(session: Session, *, now: float | None = None) -> Tenant:
    stamp = time.time() if now is None else now
    tenant = session.get(Tenant, DEFAULT_TENANT_ID)
    if tenant is None:
        tenant = Tenant(id=DEFAULT_TENANT_ID, code=DEFAULT_TENANT_CODE,
                        name="默认租户", status="active", plan="standard",
                        quotas_json="{}", created=stamp)
        session.add(tenant)
        session.flush()
    return tenant


def seed_roles(session: Session, *, now: float | None = None) -> dict[str, int]:
    stamp = time.time() if now is None else now
    created = {"roles": 0, "permissions": 0, "links": 0}
    seed_default_tenant(session, now=stamp)
    existing_roles = {r.code: r for r in session.scalars(select(Role)).all()}
    for code, name in ROLE_LABELS:
        if code not in existing_roles:
            session.add(Role(id=str(uuid.uuid4()), code=code, name=name,
                             description="", created=stamp))
            created["roles"] += 1
    session.flush()
    roles = {r.code: r.id for r in session.scalars(select(Role)).all()}

    existing_perms = {p.code: p for p in session.scalars(select(Permission)).all()}
    wanted = {code for codes in ROLE_PERMISSIONS.values() for code in codes}
    for code in sorted(wanted):
        if code not in existing_perms:
            session.add(Permission(id=str(uuid.uuid4()), code=code, name=code))
            created["permissions"] += 1
    session.flush()
    perms = {p.code: p.id for p in session.scalars(select(Permission)).all()}

    existing_links = {(r.role_id, r.permission_id)
                      for r in session.scalars(select(RolePermission)).all()}
    for role_code, codes in ROLE_PERMISSIONS.items():
        for code in codes:
            pair = (roles[role_code], perms[code])
            if pair not in existing_links:
                session.add(RolePermission(role_id=pair[0], permission_id=pair[1]))
                created["links"] += 1
    session.commit()
    return created


def bootstrap_admin(session: Session, username: str, password: str,
                    *, now: float | None = None,
                    tenant_id: str = DEFAULT_TENANT_ID) -> User | None:
    if session.scalar(select(User.id).limit(1)) is not None:
        return None
    stamp = time.time() if now is None else now
    tenant = session.get(Tenant, tenant_id)
    if tenant is None:
        seed_default_tenant(session, now=stamp)
    admin = User(id=str(uuid.uuid4()), tenant_id=tenant_id, username=username,
                 display_name="系统管理员", password_hash=hash_password(password),
                 is_active=True, created=stamp)
    session.add(admin)
    session.flush()
    admin_role = session.scalar(select(Role).where(Role.code == ROLE_ADMIN))
    if admin_role is not None:
        session.add(UserRole(user_id=admin.id, role_id=admin_role.id))
    session.commit()
    return admin


def bootstrap_platform_admin(session: Session, username: str, password: str,
                             *, now: float | None = None) -> User | None:
    if session.scalar(select(User.id).where(User.tenant_id.is_(None)).limit(1)) is not None:
        return None
    stamp = time.time() if now is None else now
    user = User(id=str(uuid.uuid4()), tenant_id=None, username=username,
                display_name="平台管理员", password_hash=hash_password(password),
                is_active=True, created=stamp)
    session.add(user)
    session.flush()
    role = session.scalar(select(Role).where(Role.code == ROLE_PLATFORM_ADMIN))
    if role is not None:
        session.add(UserRole(user_id=user.id, role_id=role.id))
    session.commit()
    return user


@contextmanager
def transaction(factory: sessionmaker[Session]) -> Iterator[Session]:
    session = factory()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()
