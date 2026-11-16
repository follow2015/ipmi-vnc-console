"""Engine / session construction shared by MySQL (prod) and SQLite (dev, test)."""
from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .models import (Base, Permission, ROLE_ADMIN, ROLE_OPERATOR, ROLE_PERMISSIONS,
                     ROLE_VIEWER, Role, RolePermission, User)
from .security import hash_password


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


def seed_roles(session: Session, *, now: float | None = None) -> dict[str, int]:
    stamp = time.time() if now is None else now
    created = {"roles": 0, "permissions": 0, "links": 0}
    existing_roles = {r.code: r for r in session.scalars(select(Role)).all()}
    for code, name in ((ROLE_ADMIN, "系统管理员"), (ROLE_OPERATOR, "运维操作员"),
                       (ROLE_VIEWER, "只读观察者")):
        if code not in existing_roles:
            session.add(Role(id=str(uuid.uuid4()), code=code, name=name,
                             description="", created=stamp))
            created["roles"] += 1
    session.flush()
    roles = {r.code: r.id for r in session.scalars(select(Role)).all()}

    existing_perms = {p.code: p for p in session.scalars(select(Permission)).all()}
    for code in ROLE_PERMISSIONS[ROLE_ADMIN]:
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
                    *, now: float | None = None) -> User | None:
    if session.scalar(select(User.id).limit(1)) is not None:
        return None
    stamp = time.time() if now is None else now
    admin = User(id=str(uuid.uuid4()), username=username, display_name="系统管理员",
                 password_hash=hash_password(password), is_active=True, created=stamp)
    session.add(admin)
    session.flush()
    admin_role = session.scalar(select(Role).where(Role.code == ROLE_ADMIN))
    if admin_role is not None:
        from .models import UserRole
        session.add(UserRole(user_id=admin.id, role_id=admin_role.id))
    session.commit()
    return admin


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
