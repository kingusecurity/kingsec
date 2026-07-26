"""The root configuration aggregate.

This is the *only* object that knows configuration can come from the outside
world (environment variables and a ``.env`` file). Everything it exposes is a
frozen, already-validated value object from ``models.py``. That single-entry-
point design means:

  * There is exactly one place that reads ``os.environ`` / ``.env``.
  * The rest of the app receives plain, typed, immutable data.
  * The domain layer never imports this module — configuration is loaded at the
    composition root and passed inward as arguments (dependency inversion).

Environment variable convention
    prefix ``KINGSEC_`` + group + delimiter ``__`` + field. Examples:

        KINGSEC_SERVER__PORT=9000        -> settings.server.port
        KINGSEC_AI__API_KEY=sk-...        -> settings.ai.api_key (masked)
        KINGSEC_LOGGING__LEVEL=DEBUG      -> settings.logging.level

    Names are case-insensitive. Precedence (highest first) is:
    explicit init args > environment variables > ``.env`` file > defaults.
"""

from __future__ import annotations

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .enums import Environment
from .models import (
    AISettings,
    AmassSettings,
    AppSettings,
    CORSSettings,
    FfufSettings,
    GobusterSettings,
    JWTSettings,
    LoggingSettings,
    MiddlewareSettings,
    NiktoSettings,
    NmapSettings,
    RateLimitSettings,
    ScannerSettings,
    SecretsSettings,
    SecurityHeadersSettings,
    SecuritySettings,
    SemgrepSettings,
    ServerSettings,
    StorageSettings,
    TrivySettings,
    ZapSettings,
)


class Settings(BaseSettings):
    """Immutable, fully validated application configuration."""

    model_config = SettingsConfigDict(
        # All KingSec settings share one prefix so they never collide with
        # unrelated environment variables on the host.
        env_prefix="KINGSEC_",
        # Lets a single env var reach into a nested group (SERVER__PORT).
        env_nested_delimiter="__",
        # Load a local .env for developer/CI convenience. Real secrets in
        # production are expected to come from the environment or a secret store
        # (see the keyring integration note in loader.py), never from a
        # committed file.
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        # Requirement 7: the whole tree is immutable after construction.
        frozen=True,
        # Ignore unrelated env vars on the host (there are always many). Typos in
        # KingSec's OWN keys are still caught because the nested groups use
        # extra="forbid"; an unknown nested key surfaces as a validation error.
        extra="ignore",
    )

    # default_factory so each field is a fresh, independent group instance and
    # so nested env vars can populate it even when no group block is provided.
    app: AppSettings = Field(default_factory=AppSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    jwt: JWTSettings = Field(default_factory=JWTSettings)
    ai: AISettings = Field(default_factory=AISettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    scanner: ScannerSettings = Field(default_factory=ScannerSettings)
    nmap: NmapSettings = Field(default_factory=NmapSettings)
    nikto: NiktoSettings = Field(default_factory=NiktoSettings)
    ffuf: FfufSettings = Field(default_factory=FfufSettings)
    gobuster: GobusterSettings = Field(default_factory=GobusterSettings)
    amass: AmassSettings = Field(default_factory=AmassSettings)
    trivy: TrivySettings = Field(default_factory=TrivySettings)
    zap: ZapSettings = Field(default_factory=ZapSettings)
    semgrep: SemgrepSettings = Field(default_factory=SemgrepSettings)
    security_headers: SecurityHeadersSettings = Field(default_factory=SecurityHeadersSettings)
    cors: CORSSettings = Field(default_factory=CORSSettings)
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    secrets: SecretsSettings = Field(default_factory=SecretsSettings)
    middleware: MiddlewareSettings = Field(default_factory=MiddlewareSettings)

    @model_validator(mode="after")
    def _guard_default_secrets_in_production(self) -> Settings:
        if self.app.environment is not Environment.PRODUCTION:
            return self
        _default = "CHANGE-ME-IN-PRODUCTION-DO-NOT-USE-DEFAULT"
        jwt_secret = self.jwt.secret_key.get_secret_value()
        if jwt_secret == _default:
            raise ValueError(
                "KINGSEC_JWT__SECRET_KEY is still set to the insecure default. "
                "Set it to a unique random value in production."
            )
        if len(jwt_secret.encode()) < 32:
            raise ValueError(
                "KINGSEC_JWT__SECRET_KEY is too short (minimum 32 bytes). "
                'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
            )
        pepper = self.secrets.api_key_pepper.get_secret_value()
        if pepper == _default:
            raise ValueError(
                "KINGSEC_SECRETS__API_KEY_PEPPER is still set to the insecure default. "
                "Set it to a unique random value in production."
            )
        if len(pepper.encode()) < 32:
            raise ValueError(
                "KINGSEC_SECRETS__API_KEY_PEPPER is too short (minimum 32 bytes). "
                'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )
        return self
