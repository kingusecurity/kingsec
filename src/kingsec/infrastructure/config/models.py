"""Typed configuration value objects, grouped by concern.

Design summary
    Each logical area (app, server, security, ai, logging, storage) is a small
    frozen ``BaseModel``. Grouping does three things:

      1. Keeps the flat env namespace organised. ``KINGSEC_SERVER__PORT`` reads
         better than ``KINGSEC_PORT`` once there are 20+ settings, and it groups
         related values so nobody has to guess which subsystem a key belongs to.
      2. Lets each subsystem own its own validation rules next to its data.
      3. Lets Module 2.2+ depend on a *narrow* slice (e.g. accept a
         ``LoggingSettings``) instead of the whole ``Settings`` object — smaller
         surface, easier tests, cleaner hexagonal boundaries.

    These are plain ``BaseModel`` value objects, NOT ``BaseSettings``. Only the
    root aggregate (``settings.Settings``) knows how to read the environment;
    the groups are dumb, validated data. That separation keeps "where do values
    come from" in exactly one place.

Immutability (Requirement 7)
    Every model sets ``frozen=True`` via the shared ``_FROZEN`` config. Once the
    tree is built at startup it cannot be mutated, so no code path can quietly
    reconfigure the running app. ``extra="forbid"`` additionally rejects unknown
    keys, turning a typo in a ``.env`` nested value into an immediate error
    instead of a silently ignored setting.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from .enums import Environment, LogLevel

# Shared model config: immutable + reject unknown keys. Defined once so every
# group is guaranteed to have identical, non-negotiable safety properties.
_FROZEN = ConfigDict(frozen=True, extra="forbid")

# Binding to any of these means "listen on every network interface", which
# exposes the service beyond the local machine. KingSec's frozen trust posture
# is loopback-by-default, so these require an explicit, deliberate opt-in.
_WILDCARD_HOSTS = frozenset({"0.0.0.0", "::", "*"})  # nosec B104 — set of hosts to validate against, not a binding address

# Shared insecure-default sentinel for cryptographic secret fields (JWT
# signing key, API key pepper). Centralised so every place that needs to
# recognise "this is still the example placeholder, not a real secret" -
# the production-only length/placeholder guard in ``settings.py`` and the
# environment-independent placeholder guard in ``infrastructure.auth.provisioning``
# - checks against exactly one literal instead of several independently
# maintained copies.
DEFAULT_SECRET_PLACEHOLDER = "CHANGE-ME-IN-PRODUCTION-DO-NOT-USE-DEFAULT"  # nosec B105 — sentinel value, not a credential


class AppSettings(BaseModel):
    """Identity and mode of the running application."""

    model_config = _FROZEN

    name: str = "KingSec"
    version: str = "2.0.0"
    environment: Environment = Environment.DEVELOPMENT
    # ``debug`` toggles verbose behaviour. It is intentionally False by default
    # and forbidden in production (see validator) so a leftover debug flag can
    # never ship to a real deployment.
    debug: bool = False

    @model_validator(mode="after")
    def _forbid_debug_in_production(self) -> AppSettings:
        # Cross-field rule: debug + production is almost always an accident and
        # can leak internals. Catch it at startup rather than in the field.
        if self.environment is Environment.PRODUCTION and self.debug:
            raise ValueError("debug mode must be disabled when environment is 'production'")
        return self


class ServerSettings(BaseModel):
    """How the local API server binds.

    This is where the frozen security guardrail lives: KingSec binds to
    loopback (127.0.0.1) by default, and refuses to bind to a wildcard address
    unless an operator explicitly opts in. The guardrail is a *default in code*,
    not a line in a runbook — so the safe path is the path of least resistance.
    """

    model_config = _FROZEN

    host: str = "127.0.0.1"
    # ge/le make the port range a validation rule; anything outside 1–65535 is
    # rejected at load time with a precise message.
    port: int = Field(default=8765, ge=1, le=65535)
    # The explicit escape hatch. Defaulting to False means "external exposure is
    # never accidental" — it has to be typed out on purpose.
    allow_external_bind: bool = False

    @field_validator("host")
    @classmethod
    def _host_not_empty(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("server host must not be empty")
        return stripped

    @model_validator(mode="after")
    def _guard_wildcard_bind(self) -> ServerSettings:
        if self.host in _WILDCARD_HOSTS and not self.allow_external_bind:
            raise ValueError(
                f"refusing to bind to {self.host!r}, which exposes KingSec on all "
                "network interfaces. KingSec defaults to loopback for safety. Only "
                "set server.allow_external_bind=true inside a trusted, authorized "
                "network segment."
            )
        return self


class SecuritySettings(BaseModel):
    """Product-level trust guardrails expressed as configuration."""

    model_config = _FROZEN

    # Phase 3 (auth hardening): self-registration defaults to DISABLED.
    # Enabled by default, the first unauthenticated caller to reach
    # /auth/register on a network-reachable instance could win the
    # first-user-becomes-admin race. RegisterUser no longer grants ADMIN
    # via this path regardless of this flag (see save_new_user) - but an
    # open signup flow is still a real product decision, not a safe default.
    allow_self_registration: bool = False

    # Phase 4 (authorization scope enforcement): defaults to ENABLED,
    # matching this file's trust-default convention (safe unless someone
    # deliberately turns it off). Read directly by
    # bootstrap/composition.py's adapter registration: when True, the real
    # AuthorizationGrantRepository/ScannerPluginRegistry/ExecutionPlanner
    # are wired into CreateAssessment; when False, CreateAssessment is
    # constructed exactly as before this feature existed (all three
    # optional deps left None), so an operator can roll back enforcement
    # without a redeploy if something goes wrong. Unlike the deleted
    # require_authorization, this flag has a real, tested effect on the
    # composition root in both states.
    enforce_authorization_scope: bool = True


class JWTSettings(BaseModel):
    """JWT authentication configuration.

    All secrets are ``SecretStr`` so they are masked in logs and repr().
    The secret_key MUST be overridden in production via env var or .env file.
    """

    model_config = _FROZEN

    # HMAC signing secret. Default is INSECURE — production MUST override.
    secret_key: SecretStr = SecretStr(DEFAULT_SECRET_PLACEHOLDER)
    # Algorithm: HS256 is sufficient for HMAC-signed local-first tokens.
    algorithm: str = "HS256"
    # Access token lifetime in minutes.
    access_token_expire_minutes: int = Field(default=30, ge=1, le=1440)
    # Refresh token lifetime in days.
    refresh_token_expire_days: int = Field(default=7, ge=1, le=90)
    # Issuer claim for token validation.
    issuer: str = "kingsec"

    @field_validator("algorithm")
    @classmethod
    def _algorithm_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("jwt algorithm must not be empty")
        return value.strip()


class AISettings(BaseModel):
    """Bring-Your-Own-Key AI provider settings.

    KingSec's business model is BYO-key, so the API key is *optional at
    startup*: a user may run the app and configure their key later through the
    UI. Config's job here is only to (a) carry the values and (b) validate their
    shape if present — never to require a key or talk to a provider.

    The key is a ``SecretStr`` so it is masked in every ``repr()``/log line by
    construction. That single type choice satisfies "API keys must never appear
    in logs" without relying on anyone remembering to redact.
    """

    model_config = _FROZEN

    provider: str = "anthropic"
    base_url: str | None = None
    api_key: SecretStr | None = None
    # A neutral default; the real model is user-selectable and the AI module
    # (out of scope here) owns model-capability concerns.
    model: str = "claude-sonnet-4-5"
    request_timeout_seconds: float = Field(default=30.0, gt=0)

    # --- Module 5.2 additions (AI enrichment adapter) -----------------------
    # Low temperature by default: security guidance should be deterministic and
    # conservative rather than creative.
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    # Upper bound on generated tokens per enrichment (cost/latency guard).
    max_tokens: int = Field(default=1024, gt=0)
    # Transient-failure retries (0 = no retry) and the base back-off delay.
    retry_count: int = Field(default=2, ge=0)
    retry_delay: float = Field(default=0.5, ge=0.0)
    # TLS verification. Secure by default; only an explicit False disables it.
    verify_ssl: bool = True
    # SSRF guard for base_url (Phase 14): private/loopback addresses (e.g. a
    # local Ollama/LM Studio/vLLM server) are refused by default, since
    # base_url can also arrive as request input via the Settings UI. A
    # deliberate operator opt-in - deployment-time configuration, not a
    # per-request field - is required to permit them. Cloud-metadata
    # (link-local, e.g. 169.254.169.254), multicast, and reserved addresses
    # stay blocked regardless of this flag.
    allow_private_base_url: bool = False

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith(("http://", "https://")):
            raise ValueError("ai base_url must start with http:// or https://")
        # Normalise so downstream URL joins are predictable.
        return value.rstrip("/")


class LoggingSettings(BaseModel):
    """Desired logging behaviour — the seam for Module 2.2.

    Important boundary: this class holds *what the operator wants*; it does NOT
    configure any logging library. Module 2.2 (structlog) will read these values
    and set up handlers/processors. Keeping the values here means the log level
    is validated at startup and Module 2.2 receives an already-valid object.
    """

    model_config = _FROZEN

    level: LogLevel = LogLevel.INFO
    # False -> human-friendly console output for development.
    # True  -> structured JSON, appropriate for production log ingestion.
    json_format: bool = False


class StorageSettings(BaseModel):
    """Where KingSec keeps its local data.

    Only the *location* is configuration. Creating directories, opening the
    database, or running migrations belongs to the persistence module (out of
    scope for 2.1). We expose the path so later modules have a single, validated
    source of truth for it.
    """

    model_config = _FROZEN

    # default_factory (not a bare default) because the value depends on the
    # current user's home directory, resolved at load time.
    data_dir: Path = Field(default_factory=lambda: Path.home() / ".kingsec")


class ScannerSettings(BaseModel):
    """Settings for the external scanner engine (Module 5.1, Nuclei).

    Only *how to invoke* the scanner is configuration; running it is the
    infrastructure adapter's job. The binary path and templates directory are
    operator-controlled (trusted config): pointing them at untrusted paths is a
    supply-chain risk, so they are treated like any other privileged setting.
    """

    model_config = _FROZEN

    # Path or name of the scanner binary. Default resolves "nuclei" from PATH.
    binary_path: str = "nuclei"
    # Directory of templates. None -> let the scanner use its own default set.
    templates_dir: Path | None = None
    # Hard wall-clock timeout for a single scan, in seconds (must be positive).
    # Phase 2B-c small item: raised from 300s to 600s. Task 6's real E2E run
    # (docs/E2E-EVIDENCE-PHASE2B.md Defect 1) reproduced nuclei genuinely
    # timing out at 300s against DVWA with the full ~13,900-template set,
    # while the identical binary/templates completed against Juice Shop -
    # 300s was too tight for a real target, not just a worst case. Already
    # operator-configurable via KINGSEC_SCANNER__TIMEOUT_SECONDS, same as
    # every other field on this settings class - this only changes the
    # shipped default.
    timeout_seconds: float = Field(default=600.0, gt=0)
    # Requests-per-second cap: a politeness/safety control (must be positive).
    rate_limit: int = Field(default=150, gt=0)

    @field_validator("binary_path")
    @classmethod
    def _binary_path_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("scanner binary_path must not be empty")
        return value


class NmapSettings(BaseModel):
    """Settings for the Nmap network scanner.

    Nmap performs host discovery, port scanning, and service/version detection.
    The binary path and scan timeout are operator-controlled.
    """

    model_config = _FROZEN

    binary_path: str = "nmap"
    timeout_seconds: float = Field(default=600.0, gt=0)
    # Scan arguments. The adapter appends the target automatically.
    # Default: service version detection (-sV), no reverse-DNS lookups (-n —
    # without this, nmap does a PTR lookup per discovered host/port, which on
    # an unresponsive or slow resolver can add minutes to a hostname scan
    # that an equivalent IP-address scan never pays), XML output to stdout.
    scan_args: tuple[str, ...] = ("-sV", "-n")

    @field_validator("binary_path")
    @classmethod
    def _binary_path_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("nmap binary_path must not be empty")
        return value


class NiktoSettings(BaseModel):
    """Settings for the Nikto web server scanner.

    Nikto performs web server scanning for misconfigurations, dangerous files,
    and outdated software. The binary path and scan timeout are operator-controlled.
    """

    model_config = _FROZEN

    binary_path: str = "nikto"
    timeout_seconds: float = Field(default=600.0, gt=0)
    # Scan arguments. The adapter appends the target automatically.
    # Default: tuning options for common checks, no SSL warnings.
    scan_args: tuple[str, ...] = ("-Tuning", "1234567890abc", "-nointeractive")

    @field_validator("binary_path")
    @classmethod
    def _binary_path_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("nikto binary_path must not be empty")
        return value


class TrivySettings(BaseModel):
    """Settings for the Trivy vulnerability scanner.

    Trivy scans filesystems and container images for vulnerabilities and
    misconfigurations. The binary path and scan timeout are operator-controlled.
    """

    model_config = _FROZEN

    binary_path: str = "trivy"
    timeout_seconds: float = Field(default=600.0, gt=0)
    # Scan type: "fs" for filesystem, "image" for container images.
    scan_type: str = "fs"
    # Scan arguments. The adapter appends --format json <target>.
    scan_args: tuple[str, ...] = ()

    @field_validator("binary_path")
    @classmethod
    def _binary_path_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("trivy binary_path must not be empty")
        return value

    @field_validator("scan_type")
    @classmethod
    def _scan_type_valid(cls, value: str) -> str:
        if value not in ("fs", "image"):
            raise ValueError("trivy scan_type must be 'fs' or 'image'")
        return value


class ZapSettings(BaseModel):
    """Settings for the OWASP ZAP web application scanner.

    ZAP performs automated web application security testing. The binary
    path and scan timeout are operator-controlled.
    """

    model_config = _FROZEN

    binary_path: str = "zap"
    timeout_seconds: float = Field(default=1200.0, gt=0)
    # Scan arguments. The adapter appends -quickurl <target> -quickout json.
    scan_args: tuple[str, ...] = ()

    @field_validator("binary_path")
    @classmethod
    def _binary_path_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("zap binary_path must not be empty")
        return value


class SemgrepSettings(BaseModel):
    """Settings for the Semgrep static analysis scanner.

    Semgrep performs pattern-based code analysis. The binary path, rules,
    and scan timeout are operator-controlled.
    """

    model_config = _FROZEN

    binary_path: str = "semgrep"
    timeout_seconds: float = Field(default=600.0, gt=0)
    # Optional rules directory or rule ID. Empty means use default rules.
    rules: str = ""
    # Scan arguments. The adapter appends scan --json <target>.
    scan_args: tuple[str, ...] = ()

    @field_validator("binary_path")
    @classmethod
    def _binary_path_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("semgrep binary_path must not be empty")
        return value


class AmassSettings(BaseModel):
    """Settings for the OWASP Amass subdomain enumerator.

    Amass performs passive and active subdomain enumeration. The binary
    path and scan timeout are operator-controlled.
    """

    model_config = _FROZEN

    binary_path: str = "amass"
    timeout_seconds: float = Field(default=900.0, gt=0)
    # Scan arguments. The adapter appends enum -passive -json - -d <target>.
    scan_args: tuple[str, ...] = ()

    @field_validator("binary_path")
    @classmethod
    def _binary_path_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("amass binary_path must not be empty")
        return value


class GobusterSettings(BaseModel):
    """Settings for the Gobuster directory enumerator.

    Gobuster performs directory, DNS, and vhost brute-forcing. The binary
    path, wordlist, and scan timeout are operator-controlled.
    """

    model_config = _FROZEN

    binary_path: str = "gobuster"
    # Path to the wordlist file. Must be provided by the operator.
    wordlist: str = ""
    timeout_seconds: float = Field(default=600.0, gt=0)
    # Scan arguments. The adapter appends dir -u <target> -w <wordlist>.
    scan_args: tuple[str, ...] = ()
    # Phase 2B-c Priority 3: per-request delay in milliseconds (gobuster's
    # own --delay flag), applied unless the operator's scan_args already
    # sets --delay. A conservative default (100ms) rather than 0/unlimited -
    # real throughput also depends on thread count (-t in scan_args),
    # unmanaged here by design (deliberately narrow, matching port_specification's
    # own precedent of not becoming a generic "scan parameters" bag).
    delay_ms: int = Field(default=100, ge=0)

    @field_validator("binary_path")
    @classmethod
    def _binary_path_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("gobuster binary_path must not be empty")
        return value


class FfufSettings(BaseModel):
    """Settings for the ffuf web fuzzer.

    ffuf performs directory and parameter fuzzing against web servers.
    The binary path, wordlist, and scan timeout are operator-controlled.
    """

    model_config = _FROZEN

    binary_path: str = "ffuf"
    # Path to the wordlist file. Must be provided by the operator.
    wordlist: str = ""
    timeout_seconds: float = Field(default=600.0, gt=0)
    # Scan arguments. The adapter appends -u <target>/FUZZ -w <wordlist> -json.
    scan_args: tuple[str, ...] = ()
    # Phase 2B-c Priority 3: requests/second (ffuf's own -rate flag),
    # applied unless the operator's scan_args already sets -rate. A
    # conservative default rather than 0/unlimited - Task 6's real E2E run
    # against Juice Shop had no rate limit at all. 0 disables limiting.
    rate_limit_per_second: int = Field(default=40, ge=0)

    @field_validator("binary_path")
    @classmethod
    def _binary_path_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("ffuf binary_path must not be empty")
        return value


class SecurityHeadersSettings(BaseModel):
    """HTTP security headers configuration.

    Defaults follow OWASP recommendations. Disable individual headers
    only if they conflict with legitimate use cases.
    """

    model_config = _FROZEN

    x_content_type_options: str = "nosniff"
    x_frame_options: str = "DENY"
    referrer_policy: str = "strict-origin-when-cross-origin"
    content_security_policy: str = "default-src 'none'"
    hsts_max_age: int = 0
    # Disable server header leakage.
    remove_server_header: bool = True
    remove_x_powered_by: bool = True


class CORSSettings(BaseModel):
    """CORS configuration.

    Defaults are restrictive (no origins allowed). Override via env vars
    for production deployments.
    """

    model_config = _FROZEN

    allow_origins: list[str] = Field(default_factory=list)
    allow_methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "PATCH"])
    allow_headers: list[str] = Field(default_factory=lambda: ["Authorization", "Content-Type", "X-Request-ID"])
    allow_credentials: bool = False
    expose_headers: list[str] = Field(
        default_factory=lambda: ["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"]
    )
    max_age: int = Field(default=600, ge=0)

    @model_validator(mode="after")
    def _guard_wildcard_with_credentials(self) -> CORSSettings:
        # KSEC-86-03 (CORS wildcard + credentials guard, Phase-84
        # carry-forward): "*" combined with allow_credentials=True lets any
        # origin's script read authenticated responses - most modern
        # browsers already refuse to honor Allow-Credentials on a wildcard
        # origin, but the application must not attempt to configure this
        # unsafe combination in the first place (older/non-browser clients
        # and the principle that this should never be reachable are both
        # reasons not to rely solely on browser-side enforcement). Same
        # fail-fast-at-load-time pattern as ServerSettings.
        # _guard_wildcard_bind() above.
        if "*" in self.allow_origins and self.allow_credentials:
            raise ValueError(
                "CORS allow_origins must not include '*' when allow_credentials is "
                "True - this configuration would let any origin's script read "
                "authenticated responses. List explicit allowed origins instead."
            )
        return self


class RateLimitSettings(BaseModel):
    """Rate limiting configuration.

    Limits are per-IP. Separate limits for authentication endpoints
    (login, register) and general API endpoints.
    """

    model_config = _FROZEN

    enabled: bool = True
    # General API rate limit: requests per minute.
    api_requests_per_minute: int = Field(default=120, ge=1)
    # Auth endpoint rate limit: requests per minute (stricter). Applies to
    # the RateLimitMiddleware token bucket for /auth/register and the MFA
    # endpoints. Login is governed solely by login_max_attempts/
    # login_window_seconds below — see rate_limit_deps.py.
    auth_requests_per_minute: int = Field(default=20, ge=1)
    # Burst size for the token bucket.
    burst_size: int = Field(default=30, ge=1)
    # The one authoritative login-throttling policy (brute-force
    # protection): max attempts per IP+user within the window below.
    # Previously this was a second, hardcoded (5, 900) tuple in
    # rate_limit_deps.py that this setting had no effect on; it is now the
    # sole source of truth for /auth/login. Defaults preserve the exact
    # values already in production.
    login_max_attempts: int = Field(default=5, ge=1)
    login_window_seconds: int = Field(default=900, ge=1)
    # Account lockout policy (a distinct mechanism from the login throttle
    # above: this tracks failed attempts per account, not per IP+user
    # request volume, and persists a lockout across the throttle window
    # resetting). Previously these were hardcoded (5, 900) constructor
    # defaults on RecordFailedAuthentication that this setting had no
    # effect on; composition.py now sources them from here via a real
    # LockoutPolicy. Defaults preserve the values already in use.
    account_lockout_max_attempts: int = Field(default=5, ge=1)
    account_lockout_duration_seconds: int = Field(default=900, ge=1)


class SecretsSettings(BaseModel):
    """Sensitive cryptographic secrets loaded from configuration.

    All values are ``SecretStr`` so they are masked in logs and ``repr()``.
    Production deployments MUST override these defaults.
    """

    model_config = _FROZEN

    # HMAC pepper for API key hashing. MUST be overridden in production.
    api_key_pepper: SecretStr = SecretStr(DEFAULT_SECRET_PLACEHOLDER)
    # Fernet symmetric encryption key (base64-urlsafe-encoded, 32 bytes).
    # REQUIRED for secret persistence. Startup fails if absent.
    encryption_key: SecretStr | None = None
    # Retired encryption keys, newest first — accepted for decrypting
    # existing secrets only, never used to encrypt new ones (Phase 57 /
    # Finding E-01). Populate this when rotating `encryption_key`: move
    # the old value here *before* removing it from `encryption_key`, so
    # secrets already encrypted under it remain readable across the
    # restart. See docs/ADMIN_GUIDE.md's "Secret and Key Rotation"
    # section for the full operator procedure.
    legacy_encryption_keys: list[SecretStr] = Field(default_factory=list)


class MiddlewareSettings(BaseModel):
    """Middleware configuration."""

    model_config = _FROZEN

    # Enable GZip compression.
    gzip_enabled: bool = True
    # Minimum response size in bytes before compression.
    gzip_minimum_size: int = Field(default=500, ge=0)
    # Trusted hosts (empty = no trusted host restriction).
    trusted_hosts: list[str] = Field(default_factory=list)
    # Enable structured request logging.
    request_logging: bool = True
    # KSEC-84-01: maximum accepted request body size, in bytes. Enforced by
    # RequestSizeLimitMiddleware BEFORE any route parses the body - without
    # this, every POST/PUT endpoint (including pre-auth ones like login/
    # register) buffers an arbitrarily large body in memory first.
    max_request_body_bytes: int = Field(default=10 * 1024 * 1024, ge=1024)


class PerformanceSettings(BaseModel):
    """Performance tuning configuration."""

    _FROZEN = ConfigDict(frozen=True, extra="forbid")

    # --- Cache ---
    cache_default_ttl: int = Field(default=300, ge=0, description="Default cache TTL in seconds")
    cache_max_size: int = Field(default=10000, ge=100, description="Max entries in memory cache")
    cache_enabled: bool = Field(default=True, description="Enable in-memory cache")

    # --- Workers ---
    worker_count: int = Field(default=2, ge=1, le=64, description="Number of background workers")
    worker_poll_interval: float = Field(default=5.0, ge=0.5, le=60.0, description="Worker poll interval in seconds")
    worker_heartbeat_interval: float = Field(default=30.0, ge=5.0, description="Heartbeat interval in seconds")

    # --- Queue ---
    queue_max_size: int = Field(default=10000, ge=100, description="Max queued jobs")
    queue_lock_timeout: float = Field(default=300.0, ge=30.0, description="Job lock timeout in seconds")

    # --- Timeouts ---
    request_timeout: float = Field(default=30.0, ge=1.0, le=300.0, description="Default request timeout in seconds")
    scanner_timeout: float = Field(default=600.0, ge=30.0, le=3600.0, description="Scanner timeout in seconds")
    report_timeout: float = Field(default=120.0, ge=10.0, le=600.0, description="Report generation timeout")

    # --- Concurrency ---
    max_concurrent_assessments: int = Field(default=5, ge=1, le=50, description="Max concurrent assessments")
    max_concurrent_scans: int = Field(default=10, ge=1, le=100, description="Max concurrent scans")
    assessment_batch_size: int = Field(default=50, ge=10, le=500, description="Batch size for large assessments")

    # --- Pagination ---
    default_page_size: int = Field(default=25, ge=5, le=200, description="Default API page size")
    max_page_size: int = Field(default=100, ge=10, le=1000, description="Max API page size")

    # --- Request body ---
    max_request_body_bytes: int = Field(default=10 * 1024 * 1024, ge=1024, description="Max request body size (bytes)")

    # --- Health checks ---
    health_check_interval: float = Field(default=60.0, ge=10.0, description="Health check interval in seconds")


class IntegrationSettings(BaseModel):
    """Enterprise integration configuration.

    Each integration group stores its connection details as a single JSON string
    per endpoint. Environment variable examples::

        KINGSEC_INTEGRATIONS__SLACK_WEBHOOK_URL=https://hooks.slack.com/...
        KINGSEC_INTEGRATIONS__SMTP_HOST=smtp.example.com
        KINGSEC_INTEGRATIONS__SMTP_PORT=587
        KINGSEC_INTEGRATIONS__JIRA_URL=https://jira.example.com
        KINGSEC_INTEGRATIONS__JIRA_EMAIL=bot@example.com
    """

    model_config = _FROZEN

    # --- Webhook / Chat ---
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""
    discord_webhook_url: str = ""
    generic_webhook_url: str = ""
    webhook_secret: SecretStr = SecretStr("")

    # --- SMTP ---
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_from_address: str = ""
    smtp_use_tls: bool = True

    # --- Jira ---
    jira_url: str = ""
    jira_email: str = ""
    jira_api_token: SecretStr = SecretStr("")
    jira_project_key: str = ""

    # --- GitHub Issues ---
    github_token: SecretStr = SecretStr("")
    github_repo: str = ""

    # --- GitLab Issues ---
    gitlab_url: str = ""
    gitlab_token: SecretStr = SecretStr("")
    gitlab_project_id: str = ""

    # --- SIEM ---
    splunk_hec_url: str = ""
    splunk_hec_token: SecretStr = SecretStr("")
    sentinel_workspace_id: str = ""
    sentinel_shared_key: SecretStr = SecretStr("")
    sentinel_dce_url: str = ""
    elastic_cloud_id: str = ""
    elastic_api_key: SecretStr = SecretStr("")
    elastic_url: str = ""
