from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.domain.session import (
    DeviceInfo,
    Session,
    SessionId,
    SessionStatus,
    SessionType,
)
from kingsec.infrastructure.persistence.models import SessionORM


class SqlAlchemySessionRepository(SessionRepository):
    def __init__(self, session_factory: Callable[..., Any]) -> None:
        self._session_factory = session_factory

    def _to_domain(self, orm: SessionORM) -> Session:
        return Session(
            id=SessionId(value=orm.id),
            user_id=orm.user_id,
            session_type=SessionType(orm.session_type),
            jti=orm.jti,
            refresh_jti=orm.refresh_jti,
            issued_at=orm.issued_at,
            expires_at=orm.expires_at,
            last_activity=orm.last_activity,
            client_ip=orm.client_ip,
            user_agent=orm.user_agent,
            device_info=DeviceInfo(
                device_name=orm.device_name or "",
                platform=orm.platform or "",
                browser=orm.browser or "",
            ),
            status=SessionStatus(orm.status),
            idle_timeout_seconds=orm.idle_timeout_seconds,
        )

    def save(self, session: Session) -> None:
        with self._session_factory() as db:
            existing = db.query(SessionORM).filter_by(id=str(session.id)).first()
            if existing:
                existing.user_id = session.user_id
                existing.session_type = session.session_type.value
                existing.jti = session.jti
                existing.refresh_jti = session.refresh_jti
                existing.issued_at = session.issued_at
                existing.expires_at = session.expires_at
                existing.last_activity = session.last_activity
                existing.client_ip = session.client_ip
                existing.user_agent = session.user_agent
                existing.device_name = session.device_info.device_name
                existing.platform = session.device_info.platform
                existing.browser = session.device_info.browser
                existing.status = session.status.value
                existing.idle_timeout_seconds = session.idle_timeout_seconds
            else:
                db.add(
                    SessionORM(
                        id=str(session.id),
                        user_id=session.user_id,
                        session_type=session.session_type.value,
                        jti=session.jti,
                        refresh_jti=session.refresh_jti,
                        issued_at=session.issued_at,
                        expires_at=session.expires_at,
                        last_activity=session.last_activity,
                        client_ip=session.client_ip,
                        user_agent=session.user_agent,
                        device_name=session.device_info.device_name,
                        platform=session.device_info.platform,
                        browser=session.device_info.browser,
                        status=session.status.value,
                        idle_timeout_seconds=session.idle_timeout_seconds,
                    )
                )
            db.commit()

    def find_by_id(self, session_id: str) -> Session | None:
        with self._session_factory() as db:
            orm = db.query(SessionORM).filter_by(id=session_id).first()
            return self._to_domain(orm) if orm else None

    def find_by_jti(self, jti: str) -> Session | None:
        with self._session_factory() as db:
            orm = db.query(SessionORM).filter_by(jti=jti).first()
            return self._to_domain(orm) if orm else None

    def find_by_refresh_jti(self, refresh_jti: str) -> Session | None:
        with self._session_factory() as db:
            orm = db.query(SessionORM).filter_by(refresh_jti=refresh_jti).first()
            return self._to_domain(orm) if orm else None

    def find_active_by_user(self, user_id: str) -> list[Session]:
        with self._session_factory() as db:
            orms = db.query(SessionORM).filter_by(user_id=user_id, status="active").all()
            return [self._to_domain(o) for o in orms]

    def count_active_by_user(self, user_id: str) -> int:
        with self._session_factory() as db:
            return cast(int, db.query(SessionORM).filter_by(user_id=user_id, status="active").count())

    def revoke(self, session_id: str) -> None:
        with self._session_factory() as db:
            orm = db.query(SessionORM).filter_by(id=session_id).first()
            if orm:
                orm.status = "revoked"
                db.commit()

    def revoke_all_by_user(self, user_id: str, exclude_session_id: str | None = None) -> None:
        with self._session_factory() as db:
            query = db.query(SessionORM).filter_by(user_id=user_id, status="active")
            if exclude_session_id:
                query = query.filter(SessionORM.id != exclude_session_id)
            query.update({"status": "revoked"}, synchronize_session=False)
            db.commit()

    def update_activity(self, session_id: str, last_activity: str) -> None:
        with self._session_factory() as db:
            orm = db.query(SessionORM).filter_by(id=session_id).first()
            if orm:
                orm.last_activity = last_activity
                db.commit()

    def update_refresh_jti(self, session_id: str, new_refresh_jti: str) -> None:
        with self._session_factory() as db:
            orm = db.query(SessionORM).filter_by(id=session_id).first()
            if orm:
                orm.refresh_jti = new_refresh_jti
                db.commit()

    def delete_expired(self, before: str) -> int:
        with self._session_factory() as db:
            count = db.query(SessionORM).filter(SessionORM.expires_at < before).delete()
            db.commit()
            return cast(int, count)
