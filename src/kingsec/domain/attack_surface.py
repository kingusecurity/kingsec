from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .errors import InvariantViolation
from .identifiers import AttackSurfaceId


class ExposureType(StrEnum):
    OPEN_PORT = "open_port"
    PUBLIC_SERVICE = "public_service"
    TLS_CERTIFICATE = "tls_certificate"
    DNS_RECORD = "dns_record"
    SUBDOMAIN = "subdomain"
    EXPOSED_ADMIN_PANEL = "exposed_admin_panel"
    DEFAULT_LOGIN_PAGE = "default_login_page"
    PUBLIC_API = "public_api"
    CLOUD_STORAGE_EXPOSURE = "cloud_storage_exposure"
    TECHNOLOGY_FINGERPRINT = "technology_fingerprint"
    EXPIRED_CERTIFICATE = "expired_certificate"
    WEAK_TLS_VERSION = "weak_tls_version"
    HTTP_SECURITY_HEADER = "http_security_header"
    DIRECTORY_LISTING = "directory_listing"
    DEVELOPMENT_SERVER = "development_server"


class ExposureSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExposureStatus(StrEnum):
    ACTIVE = "active"
    MITIGATED = "mitigated"
    CHANGED = "changed"


EXPOSURE_SEVERITY_MAP: dict[ExposureType, ExposureSeverity] = {
    ExposureType.OPEN_PORT: ExposureSeverity.MEDIUM,
    ExposureType.PUBLIC_SERVICE: ExposureSeverity.HIGH,
    ExposureType.TLS_CERTIFICATE: ExposureSeverity.LOW,
    ExposureType.DNS_RECORD: ExposureSeverity.LOW,
    ExposureType.SUBDOMAIN: ExposureSeverity.INFO,
    ExposureType.EXPOSED_ADMIN_PANEL: ExposureSeverity.CRITICAL,
    ExposureType.DEFAULT_LOGIN_PAGE: ExposureSeverity.HIGH,
    ExposureType.PUBLIC_API: ExposureSeverity.MEDIUM,
    ExposureType.CLOUD_STORAGE_EXPOSURE: ExposureSeverity.CRITICAL,
    ExposureType.TECHNOLOGY_FINGERPRINT: ExposureSeverity.LOW,
    ExposureType.EXPIRED_CERTIFICATE: ExposureSeverity.HIGH,
    ExposureType.WEAK_TLS_VERSION: ExposureSeverity.HIGH,
    ExposureType.HTTP_SECURITY_HEADER: ExposureSeverity.MEDIUM,
    ExposureType.DIRECTORY_LISTING: ExposureSeverity.MEDIUM,
    ExposureType.DEVELOPMENT_SERVER: ExposureSeverity.CRITICAL,
}


@dataclass(frozen=True, slots=True)
class ExposureDetail:
    key: str
    value: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.key.strip():
            raise InvariantViolation("ExposureDetail key must not be empty")


@dataclass(frozen=True, slots=True)
class ExposureHistoryEntry:
    exposure_id: str
    event_type: str
    description: str
    timestamp: str
    previous_value: str | None = None
    new_value: str | None = None
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class ExposureTrendPoint:
    timestamp: str
    exposure_score: float
    total_exposures: int
    critical_count: int
    high_count: int
    medium_count: int


@dataclass(frozen=True, slots=True)
class ExposureRisk:
    exposure_score: float = 0.0
    internet_exposure: float = 0.0
    critical_asset_exposure: float = 0.0
    public_service_count: int = 0
    tls_score: float = 100.0
    trend: str = "stable"


class Exposure:
    def __init__(
        self,
        exposure_id: AttackSurfaceId,
        asset_id: str,
        exposure_type: ExposureType,
        *,
        severity: ExposureSeverity | None = None,
        title: str = "",
        description: str = "",
        detail: list[ExposureDetail] | None = None,
        status: ExposureStatus = ExposureStatus.ACTIVE,
        source: str = "scanner",
        port: int | None = None,
        protocol: str | None = None,
        hostname: str | None = None,
        ip_address: str | None = None,
        domain: str | None = None,
        url: str | None = None,
        tls_version: str | None = None,
        certificate_issuer: str | None = None,
        certificate_expiry: str | None = None,
        header_name: str | None = None,
        header_value: str | None = None,
        technology_name: str | None = None,
        technology_version: str | None = None,
        cloud_provider: str | None = None,
        cloud_bucket: str | None = None,
        evidence: str | None = None,
        remediation: str | None = None,
        risk_score: float = 0.0,
        metadata: dict[str, Any] | None = None,
        first_seen: str | None = None,
        last_seen: str | None = None,
        created_at: str | None = None,
        updated_at: str | None = None,
    ) -> None:
        if not isinstance(exposure_id, AttackSurfaceId):
            raise InvariantViolation("exposure_id must be an AttackSurfaceId")
        if not isinstance(exposure_type, ExposureType):
            raise InvariantViolation("exposure_type must be an ExposureType")

        now = datetime.now(UTC).isoformat()
        self._id = exposure_id
        self._asset_id = asset_id
        self._exposure_type = exposure_type
        self._severity = severity or EXPOSURE_SEVERITY_MAP.get(exposure_type, ExposureSeverity.MEDIUM)
        self._title = title
        self._description = description
        self._detail = list(detail) if detail else []
        self._status = status
        self._source = source
        self._port = port
        self._protocol = protocol
        self._hostname = hostname
        self._ip_address = ip_address
        self._domain = domain
        self._url = url
        self._tls_version = tls_version
        self._certificate_issuer = certificate_issuer
        self._certificate_expiry = certificate_expiry
        self._header_name = header_name
        self._header_value = header_value
        self._technology_name = technology_name
        self._technology_version = technology_version
        self._cloud_provider = cloud_provider
        self._cloud_bucket = cloud_bucket
        self._evidence = evidence
        self._remediation = remediation
        self._risk_score = risk_score
        self._metadata = dict(metadata) if metadata else {}
        self._first_seen = first_seen or now
        self._last_seen = last_seen or now
        self._created_at = created_at or now
        self._updated_at = updated_at or now

    @classmethod
    def create(
        cls,
        asset_id: str,
        exposure_type: ExposureType,
        *,
        title: str = "",
        description: str = "",
        **kwargs: Any,
    ) -> Exposure:
        return cls(
            AttackSurfaceId.generate(),
            asset_id,
            exposure_type,
            title=title or exposure_type.value.replace("_", " ").title(),
            description=description,
            **kwargs,
        )

    @property
    def id(self) -> AttackSurfaceId:
        return self._id

    @property
    def asset_id(self) -> str:
        return self._asset_id

    @property
    def exposure_type(self) -> ExposureType:
        return self._exposure_type

    @property
    def severity(self) -> ExposureSeverity:
        return self._severity

    @property
    def title(self) -> str:
        return self._title

    @property
    def description(self) -> str:
        return self._description

    @property
    def detail(self) -> tuple[ExposureDetail, ...]:
        return tuple(self._detail)

    @property
    def status(self) -> ExposureStatus:
        return self._status

    @property
    def source(self) -> str:
        return self._source

    @property
    def port(self) -> int | None:
        return self._port

    @property
    def protocol(self) -> str | None:
        return self._protocol

    @property
    def hostname(self) -> str | None:
        return self._hostname

    @property
    def ip_address(self) -> str | None:
        return self._ip_address

    @property
    def domain(self) -> str | None:
        return self._domain

    @property
    def url(self) -> str | None:
        return self._url

    @property
    def tls_version(self) -> str | None:
        return self._tls_version

    @property
    def certificate_issuer(self) -> str | None:
        return self._certificate_issuer

    @property
    def certificate_expiry(self) -> str | None:
        return self._certificate_expiry

    @property
    def header_name(self) -> str | None:
        return self._header_name

    @property
    def header_value(self) -> str | None:
        return self._header_value

    @property
    def technology_name(self) -> str | None:
        return self._technology_name

    @property
    def technology_version(self) -> str | None:
        return self._technology_version

    @property
    def cloud_provider(self) -> str | None:
        return self._cloud_provider

    @property
    def cloud_bucket(self) -> str | None:
        return self._cloud_bucket

    @property
    def evidence(self) -> str | None:
        return self._evidence

    @property
    def remediation(self) -> str | None:
        return self._remediation

    @property
    def risk_score(self) -> float:
        return self._risk_score

    @property
    def metadata(self) -> dict[str, Any]:
        return dict(self._metadata)

    @property
    def first_seen(self) -> str:
        return self._first_seen

    @property
    def last_seen(self) -> str:
        return self._last_seen

    @property
    def created_at(self) -> str:
        return self._created_at

    @property
    def updated_at(self) -> str:
        return self._updated_at

    def update_status(self, status: ExposureStatus) -> None:
        if not isinstance(status, ExposureStatus):
            raise InvariantViolation("status must be an ExposureStatus")
        self._status = status
        self._updated_at = datetime.now(UTC).isoformat()

    def update_remediation(self, remediation: str) -> None:
        self._remediation = remediation
        self._updated_at = datetime.now(UTC).isoformat()

    def update_last_seen(self, timestamp: str | None = None) -> None:
        self._last_seen = timestamp or datetime.now(UTC).isoformat()
        self._updated_at = datetime.now(UTC).isoformat()

    def calculate_risk_score(self) -> float:
        severity_weights = {
            ExposureSeverity.CRITICAL: 10.0,
            ExposureSeverity.HIGH: 7.0,
            ExposureSeverity.MEDIUM: 4.0,
            ExposureSeverity.LOW: 2.0,
            ExposureSeverity.INFO: 0.5,
        }
        base = severity_weights.get(self._severity, 1.0)
        if self._status == ExposureStatus.MITIGATED:
            base *= 0.1
        self._risk_score = min(base * 10.0, 100.0)
        return self._risk_score

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Exposure) and other._id == self._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return f"Exposure(id={self._id.value!r}, type={self._exposure_type.value}, asset={self._asset_id!r})"
