"""Use case: create a new API key."""

from __future__ import annotations

import secrets

from kingsec.application.dto import CreateApiKeyRequest, CreateApiKeyResponse
from kingsec.application.errors import ApplicationError, LicenseRequiredError
from kingsec.application.ports import ApiKeyHasher, ApiKeyRepository
from kingsec.application.services.licensing import LicenseGate
from kingsec.domain.api_key import ApiKey, ApiKeyScope, ApiKeyStatus


class CreateApiKey:
    """Create a new API key for programmatic access.

    The key is returned as ``ks_<uuid>_<secret>`` where the UUID is the key's
    database identifier. The full key is hashed before storage; the plaintext
    is returned once and cannot be recovered.
    """

    def __init__(
        self,
        repo: ApiKeyRepository,
        hasher: ApiKeyHasher,
        license_gate: LicenseGate | None = None,
    ) -> None:
        self._repo = repo
        self._hasher = hasher
        self._license_gate = license_gate

    def execute(self, request: CreateApiKeyRequest) -> CreateApiKeyResponse:
        import uuid

        if self._license_gate is not None:
            # Two independent checks, in order: entitlement, then the count
            # limit. A stock Community license has no "api_keys" feature at
            # all (see EDITION_FEATURES), so it is rejected here regardless
            # of how many keys already exist. The limit below only becomes
            # reachable for a license that DOES carry the "api_keys"
            # entitlement - Professional/Enterprise (unlimited), or a custom
            # signed license that grants "api_keys" as an add-on feature on
            # top of a Community edition (whose max_api_keys stays 3, since
            # EDITION_LIMITS has no per-license override for it).
            if not self._license_gate.can_use_api_keys():
                raise LicenseRequiredError("API keys", self._license_gate.current_edition().value)

            limit = self._license_gate.max_api_keys()
            # ``max_api_keys() is None`` means unlimited (Professional/Enterprise).
            # The count is installation-wide (server-side, never client-supplied)
            # because the license model is per-installation, not per-user.
            if limit is not None and self._repo.count_all() >= limit:
                raise LicenseRequiredError(
                    f"API keys (limit of {limit} reached)",
                    self._license_gate.current_edition().value,
                    required="an edition with a higher API key limit",
                )

        key_id = str(uuid.uuid4())
        secret = secrets.token_urlsafe(40)
        plaintext = f"ks_{key_id}_{secret}"

        try:
            scope = ApiKeyScope(request.scope)
        except ValueError as exc:
            raise ApiKeyError(f"invalid scope: {request.scope}") from exc

        key = ApiKey(
            id=key_id,
            user_id=request.user_id,
            name=request.name,
            key_hash=self._hasher.hash(plaintext),
            scope=scope,
            status=ApiKeyStatus.ACTIVE,
        )

        self._repo.save(key)

        return CreateApiKeyResponse(
            api_key_id=key.id,
            name=key.name,
            plaintext_key=plaintext,
            scope=key.scope.value,
            created_at=key.created_at.isoformat(),
        )


class ApiKeyError(ApplicationError):
    """Raised when an API key operation fails."""
