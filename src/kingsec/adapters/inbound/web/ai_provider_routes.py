"""Backend routes for the AI Provider Settings UI.

Exposes the DB-backed ``AIProviderConfigRepository`` (the same store
``AIConfigResolver`` reads from on every AI call - see
``infrastructure/ai/config_resolver.py``) through a small admin-only API:
view the current (masked) configuration, save a new one, and test a
candidate configuration for real before saving it.

Security properties:
    * The plaintext API key is never returned in any response after the
      request that set it - GET always shows a masked form only (last 4
      characters), matching the pattern this codebase already uses for its
      own API keys (shown once at creation, never again).
    * Saving with no ``api_key`` in the body keeps whatever is already
      saved rather than clearing it - a "Change" action retypes a new key,
      it doesn't silently wipe a working one.
    * The key is Fernet-encrypted at rest (``EncryptionServicePort``,
      keyed by ``SecretsSettings.encryption_key``) and only ever decrypted
      in-process, for the duration of a single request.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from kingsec.application.ports import AuditPublisher
from kingsec.application.ports.outbound.ai_provider_config_repository import (
    AIProviderConfigRecord,
    AIProviderConfigRepository,
)
from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.infrastructure.ai.client import AIClient
from kingsec.infrastructure.ai.errors import AIError
from kingsec.infrastructure.ai.providers import default_model_for, resolve_provider

from .auth import CurrentUser, require_admin
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(
    prefix="/api/v1/settings/ai-provider",
    tags=["settings"],
    dependencies=[Depends(require_admin)],
)


def _resolve(request: Request, service_type: type) -> Any:
    app: Application = get_application(request)
    svc = app.resolve(service_type)
    if svc is None:
        raise HTTPException(status_code=500, detail=f"{service_type.__name__} not available")
    return svc


def _mask(plaintext_key: str) -> str:
    """Show only the last 4 characters — enough for a human to recognise
    which key is saved, never enough to reconstruct it."""
    if len(plaintext_key) <= 4:
        return "*" * len(plaintext_key)
    return f"{'*' * 8}{plaintext_key[-4:]}"


class SaveAIProviderConfigBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str = Field(..., min_length=1)
    api_key: str | None = Field(
        default=None,
        description="Omit or leave null to keep the currently saved key unchanged.",
    )
    model: str | None = None
    base_url: str | None = None


class TestAIProviderConfigBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str = Field(..., min_length=1)
    api_key: str = Field(..., min_length=1)
    model: str | None = None
    base_url: str | None = None


@router.get("")
async def get_ai_provider_config(request: Request) -> dict[str, Any]:
    """Return the effective configuration - masked, never the real key."""
    app: Application = get_application(request)
    repo: AIProviderConfigRepository = _resolve(request, AIProviderConfigRepository)
    encryption: EncryptionServicePort = _resolve(request, EncryptionServicePort)
    env_settings = app.settings.ai

    record = repo.get()
    if record is not None:
        masked_key = None
        if record.api_key_encrypted is not None:
            try:
                masked_key = _mask(encryption.decrypt(record.api_key_encrypted))
            except Exception:
                masked_key = None
        return {
            "provider": record.provider,
            "model": record.model,
            "effective_model": record.model or default_model_for(record.provider),
            "base_url": record.base_url,
            "api_key_masked": masked_key,
            "source": "database",
            "updated_at": record.updated_at,
        }

    env_key = env_settings.api_key
    effective_model = env_settings.model
    if (
        effective_model == default_model_for("anthropic")
        and env_settings.provider.strip().lower() not in ("anthropic", "claude")
    ):
        # Same untouched-default heuristic as AIConfigResolver._from_env().
        effective_model = default_model_for(env_settings.provider)
    return {
        "provider": env_settings.provider,
        "model": env_settings.model,
        "effective_model": effective_model,
        "base_url": env_settings.base_url,
        "api_key_masked": _mask(env_key.get_secret_value()) if env_key is not None else None,
        "source": "environment" if env_key is not None else "none",
        "updated_at": None,
    }


@router.put("")
async def save_ai_provider_config(
    body: SaveAIProviderConfigBody,
    request: Request,
    user: CurrentUser = Depends(require_admin),
) -> dict[str, Any]:
    repo: AIProviderConfigRepository = _resolve(request, AIProviderConfigRepository)
    encryption: EncryptionServicePort = _resolve(request, EncryptionServicePort)
    audit: AuditPublisher = _resolve(request, AuditPublisher)

    try:
        resolve_provider(body.provider)
    except AIError:
        raise HTTPException(status_code=400, detail=f"Unsupported AI provider: {body.provider!r}") from None

    key_changed = bool(body.api_key)
    api_key_encrypted: bytes | None
    if body.api_key:
        api_key_encrypted = encryption.encrypt(body.api_key)
    else:
        # No new key submitted - keep whatever is already saved. A "Change"
        # action in the UI retypes a key; leaving the masked field alone
        # must never silently clear a working one.
        existing = repo.get()
        api_key_encrypted = existing.api_key_encrypted if existing is not None else None

    repo.save(
        AIProviderConfigRecord(
            provider=body.provider,
            api_key_encrypted=api_key_encrypted,
            model=body.model,
            base_url=body.base_url,
            updated_at=datetime.now(UTC).isoformat(),
        )
    )

    audit.record(
        AuditEntry(
            action=AuditAction.AI_PROVIDER_CONFIGURED,
            resource_type="ai_provider_config",
            success=True,
            user_id=user.user_id,
            username=user.username,
            metadata={"provider": body.provider, "key_changed": key_changed},
        )
    )

    return {"status": "saved", "provider": body.provider}


@router.post("/test")
async def test_ai_provider_config(
    body: TestAIProviderConfigBody,
    request: Request,
    user: CurrentUser = Depends(require_admin),
) -> dict[str, Any]:
    """Test the submitted (not necessarily saved) configuration for real.

    Makes one genuine, minimal outbound call through the same per-provider
    strategy classes used for real enrichment - the user finds out whether
    a key actually works before saving it, not later when a report falls
    back silently.
    """
    audit: AuditPublisher = _resolve(request, AuditPublisher)

    try:
        provider = resolve_provider(body.provider)
    except AIError as exc:
        return {"success": False, "message": str(exc)}

    # A blank model must default to something this specific provider
    # actually has - app.settings.ai.model is an Anthropic model name and
    # produces a real 404 against, e.g., Gemini when used unconditionally.
    model = body.model or default_model_for(body.provider)
    base_url = body.base_url or provider.default_base_url
    client = AIClient(timeout=15, retry_count=0, retry_delay=0, verify_ssl=True)
    try:
        url = provider.build_endpoint(base_url, model)
        headers = provider.build_headers(body.api_key)
        payload = provider.build_payload(
            "You are a connectivity test. Reply with exactly one word.",
            "Reply with the single word: OK",
            model,
            0.0,
            8,
        )
        provider.extract_text(client.post_json(url, headers, payload))
    except AIError as exc:
        audit.record(
            AuditEntry(
                action=AuditAction.AI_PROVIDER_TEST_FAILED,
                resource_type="ai_provider_config",
                success=False,
                reason=str(exc),
                user_id=user.user_id,
                username=user.username,
                metadata={"provider": body.provider},
            )
        )
        return {"success": False, "message": str(exc)}
    finally:
        client.close()

    return {"success": True, "message": f"Connected to {provider.name} successfully."}
