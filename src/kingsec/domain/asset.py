from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .errors import InvariantViolation
from .identifiers import AssetId


class AssetType(StrEnum):
    HOST = "host"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    WEBSITE = "website"
    API_ENDPOINT = "api_endpoint"
    NETWORK_DEVICE = "network_device"
    SERVER = "server"
    DATABASE = "database"
    CONTAINER = "container"
    CERTIFICATE = "certificate"
    OPERATING_SYSTEM = "operating_system"
    SERVICE = "service"
    APPLICATION = "application"
    TECHNOLOGY_STACK = "technology_stack"
    CLOUD_RESOURCE = "cloud_resource"


class AssetCriticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class AssetTag:
    key: str
    value: str

    def __post_init__(self) -> None:
        if not self.key.strip():
            raise InvariantViolation("AssetTag key must not be empty")


@dataclass(frozen=True, slots=True)
class TechnologyFingerprint:
    technology_type: str
    name: str
    version: str | None = None
    vendor: str | None = None
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not self.technology_type.strip():
            raise InvariantViolation("Technology type must not be empty")
        if not self.name.strip():
            raise InvariantViolation("Technology name must not be empty")


@dataclass(frozen=True, slots=True)
class AssetService:
    name: str
    port: int
    protocol: str = "tcp"
    version: str | None = None
    state: str = "open"


@dataclass(frozen=True, slots=True)
class AssetRelationship:
    source_asset_id: str
    target_asset_id: str
    relationship_type: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AssetHistoryEntry:
    asset_id: str
    event_type: str
    description: str
    timestamp: str
    previous_value: str | None = None
    new_value: str | None = None
    actor: str = "system"
    metadata: dict[str, Any] = field(default_factory=dict)


class Asset:
    def __init__(
        self,
        asset_id: AssetId,
        asset_type: AssetType,
        *,
        hostname: str | None = None,
        ip_address: str | None = None,
        domain: str | None = None,
        fqdn: str | None = None,
        mac_address: str | None = None,
        operating_system: str | None = None,
        os_version: str | None = None,
        criticality: AssetCriticality = AssetCriticality.MEDIUM,
        owner: str | None = None,
        location: str | None = None,
        description: str | None = None,
        tags: list[AssetTag] | None = None,
        services: list[AssetService] | None = None,
        technologies: list[TechnologyFingerprint] | None = None,
        open_ports: list[int] | None = None,
        certificate_issuer: str | None = None,
        certificate_expiry: str | None = None,
        tls_version: str | None = None,
        cloud_provider: str | None = None,
        cloud_region: str | None = None,
        container_runtime: str | None = None,
        container_image: str | None = None,
        database_type: str | None = None,
        database_version: str | None = None,
        web_server: str | None = None,
        programming_language: str | None = None,
        framework: str | None = None,
        cms: str | None = None,
        first_seen: str | None = None,
        last_seen: str | None = None,
        risk_score: float = 0.0,
        metadata: dict[str, Any] | None = None,
        created_at: str | None = None,
        updated_at: str | None = None,
    ) -> None:
        if not isinstance(asset_id, AssetId):
            raise InvariantViolation("asset_id must be an AssetId")
        if not isinstance(asset_type, AssetType):
            raise InvariantViolation("asset_type must be an AssetType")

        now = datetime.now(UTC).isoformat()
        self._id = asset_id
        self._asset_type = asset_type
        self._hostname = hostname
        self._ip_address = ip_address
        self._domain = domain
        self._fqdn = fqdn
        self._mac_address = mac_address
        self._operating_system = operating_system
        self._os_version = os_version
        self._criticality = criticality
        self._owner = owner
        self._location = location
        self._description = description
        self._tags = list(tags) if tags else []
        self._services = list(services) if services else []
        self._technologies = list(technologies) if technologies else []
        self._open_ports = sorted(open_ports) if open_ports else []
        self._certificate_issuer = certificate_issuer
        self._certificate_expiry = certificate_expiry
        self._tls_version = tls_version
        self._cloud_provider = cloud_provider
        self._cloud_region = cloud_region
        self._container_runtime = container_runtime
        self._container_image = container_image
        self._database_type = database_type
        self._database_version = database_version
        self._web_server = web_server
        self._programming_language = programming_language
        self._framework = framework
        self._cms = cms
        self._first_seen = first_seen or now
        self._last_seen = last_seen or now
        self._risk_score = risk_score
        self._metadata = dict(metadata) if metadata else {}
        self._created_at = created_at or now
        self._updated_at = updated_at or now

    @classmethod
    def create(
        cls,
        asset_type: AssetType,
        *,
        hostname: str | None = None,
        ip_address: str | None = None,
        **kwargs: Any,
    ) -> Asset:
        return cls(
            AssetId.generate(),
            asset_type,
            hostname=hostname,
            ip_address=ip_address,
            **kwargs,
        )

    # --- Properties ---
    @property
    def id(self) -> AssetId:
        return self._id

    @property
    def asset_type(self) -> AssetType:
        return self._asset_type

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
    def fqdn(self) -> str | None:
        return self._fqdn

    @property
    def mac_address(self) -> str | None:
        return self._mac_address

    @property
    def operating_system(self) -> str | None:
        return self._operating_system

    @property
    def os_version(self) -> str | None:
        return self._os_version

    @property
    def criticality(self) -> AssetCriticality:
        return self._criticality

    @property
    def owner(self) -> str | None:
        return self._owner

    @property
    def location(self) -> str | None:
        return self._location

    @property
    def description(self) -> str | None:
        return self._description

    @property
    def tags(self) -> tuple[AssetTag, ...]:
        return tuple(self._tags)

    @property
    def services(self) -> tuple[AssetService, ...]:
        return tuple(self._services)

    @property
    def technologies(self) -> tuple[TechnologyFingerprint, ...]:
        return tuple(self._technologies)

    @property
    def open_ports(self) -> tuple[int, ...]:
        return tuple(self._open_ports)

    @property
    def certificate_issuer(self) -> str | None:
        return self._certificate_issuer

    @property
    def certificate_expiry(self) -> str | None:
        return self._certificate_expiry

    @property
    def tls_version(self) -> str | None:
        return self._tls_version

    @property
    def cloud_provider(self) -> str | None:
        return self._cloud_provider

    @property
    def cloud_region(self) -> str | None:
        return self._cloud_region

    @property
    def container_runtime(self) -> str | None:
        return self._container_runtime

    @property
    def container_image(self) -> str | None:
        return self._container_image

    @property
    def database_type(self) -> str | None:
        return self._database_type

    @property
    def database_version(self) -> str | None:
        return self._database_version

    @property
    def web_server(self) -> str | None:
        return self._web_server

    @property
    def programming_language(self) -> str | None:
        return self._programming_language

    @property
    def framework(self) -> str | None:
        return self._framework

    @property
    def cms(self) -> str | None:
        return self._cms

    @property
    def first_seen(self) -> str | None:
        return self._first_seen

    @property
    def last_seen(self) -> str | None:
        return self._last_seen

    @property
    def risk_score(self) -> float:
        return self._risk_score

    @property
    def metadata(self) -> dict[str, Any]:
        return dict(self._metadata)

    @property
    def created_at(self) -> str:
        return self._created_at

    @property
    def updated_at(self) -> str:
        return self._updated_at

    # --- Behaviour ---
    def update_last_seen(self, timestamp: str | None = None) -> None:
        self._last_seen = timestamp or datetime.now(UTC).isoformat()
        self._updated_at = datetime.now(UTC).isoformat()

    def add_tag(self, tag: AssetTag) -> None:
        if not isinstance(tag, AssetTag):
            raise InvariantViolation("tag must be an AssetTag")
        existing = {t.key for t in self._tags}
        if tag.key not in existing:
            self._tags.append(tag)
            self._updated_at = datetime.now(UTC).isoformat()

    def remove_tag(self, key: str) -> None:
        self._tags = [t for t in self._tags if t.key != key]
        self._updated_at = datetime.now(UTC).isoformat()

    def add_service(self, service: AssetService) -> None:
        if not isinstance(service, AssetService):
            raise InvariantViolation("service must be an AssetService")
        self._services.append(service)
        if service.port not in self._open_ports:
            self._open_ports.append(service.port)
            self._open_ports.sort()
        self._updated_at = datetime.now(UTC).isoformat()

    def add_technology(self, tech: TechnologyFingerprint) -> None:
        if not isinstance(tech, TechnologyFingerprint):
            raise InvariantViolation("technology must be a TechnologyFingerprint")
        existing = {(t.name, t.technology_type) for t in self._technologies}
        if (tech.name, tech.technology_type) not in existing:
            self._technologies.append(tech)
            self._updated_at = datetime.now(UTC).isoformat()

    def update_criticality(self, criticality: AssetCriticality) -> None:
        if not isinstance(criticality, AssetCriticality):
            raise InvariantViolation("criticality must be an AssetCriticality")
        self._criticality = criticality
        self._updated_at = datetime.now(UTC).isoformat()

    def calculate_risk_score(self, critical_findings: int = 0, high_findings: int = 0, open_findings: int = 0) -> float:
        score = 0.0
        score += critical_findings * 10.0
        score += high_findings * 5.0
        score += open_findings * 1.0
        if self._criticality == AssetCriticality.CRITICAL:
            score *= 1.5
        elif self._criticality == AssetCriticality.HIGH:
            score *= 1.2
        self._risk_score = min(score, 100.0)
        return self._risk_score

    # --- Identity ---
    def __eq__(self, other: object) -> bool:
        return isinstance(other, Asset) and other._id == self._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        name = self._hostname or self._ip_address or self._fqdn or str(self._id)
        return f"Asset(id={self._id.value!r}, type={self._asset_type.value}, name={name!r})"
