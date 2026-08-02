from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from kingsec.application.ports.outbound.license_repository import LicenseRepository
from kingsec.domain.license import License, LicenseEdition, LicenseId, LicenseStatus
from kingsec.infrastructure.persistence.models import LicenseORM


class SQLAlchemyLicenseRepository(LicenseRepository):

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def _to_domain(self, orm: LicenseORM) -> License:
        return License(
            id=LicenseId(orm.id),
            edition=LicenseEdition(orm.edition),
            status=LicenseStatus(orm.status),
            license_key=orm.license_key,
            issued_to=orm.issued_to,
            company=orm.company,
            email=orm.email,
            max_users=orm.max_users,
            max_organizations=orm.max_organizations,
            expires_at=orm.expires_at,
            features=set(json.loads(orm.features) if orm.features else []),
            signature=orm.signature,
            created_at=orm.created_at,
            updated_at=orm.updated_at,
        )

    def _to_orm(self, license: License) -> LicenseORM:
        return LicenseORM(
            id=str(license.id),
            edition=license.edition.value,
            status=license.status.value,
            license_key=license.license_key,
            issued_to=license.issued_to,
            company=license.company,
            email=license.email,
            max_users=license.max_users,
            max_organizations=license.max_organizations,
            expires_at=license.expires_at,
            features=json.dumps(sorted(license.features)),
            signature=license.signature,
            created_at=license.created_at,
            updated_at=license.updated_at,
        )

    def save(self, license: License) -> None:
        with self._session_factory() as session:
            existing = session.get(LicenseORM, str(license.id))
            if existing:
                existing.edition = license.edition.value
                existing.status = license.status.value
                existing.license_key = license.license_key
                existing.issued_to = license.issued_to
                existing.company = license.company
                existing.email = license.email
                existing.max_users = license.max_users
                existing.max_organizations = license.max_organizations
                existing.expires_at = license.expires_at
                existing.features = json.dumps(sorted(license.features))
                existing.signature = license.signature
                existing.updated_at = datetime.now(UTC).isoformat()
            else:
                session.add(self._to_orm(license))
            session.commit()

    def find_active(self) -> License | None:
        stmt = (
            select(LicenseORM)
            .where(LicenseORM.status.in_(["active", "grace_period"]))
            .order_by(LicenseORM.created_at.desc())
            .limit(1)
        )
        with self._session_factory() as session:
            row = session.execute(stmt).scalar_one_or_none()
            return self._to_domain(row) if row else None

    def find_by_key(self, license_key: str) -> License | None:
        stmt = select(LicenseORM).where(LicenseORM.license_key == license_key)
        with self._session_factory() as session:
            row = session.execute(stmt).scalar_one_or_none()
            return self._to_domain(row) if row else None

    def list_all(self) -> list[License]:
        stmt = select(LicenseORM).order_by(LicenseORM.created_at.desc())
        with self._session_factory() as session:
            return [self._to_domain(row) for row in session.execute(stmt).scalars()]

    def delete(self, license_id: str) -> None:
        with self._session_factory() as session:
            orm = session.get(LicenseORM, license_id)
            if orm:
                session.delete(orm)
                session.commit()

    def exists(self) -> bool:
        stmt = select(LicenseORM).limit(1)
        with self._session_factory() as session:
            return session.execute(stmt).first() is not None
