"""Tests for API key use cases."""

from __future__ import annotations

import pytest

from kingsec.application.dto import (
    CreateApiKeyRequest,
    ListApiKeysRequest,
    RevokeApiKeyRequest,
    RotateApiKeyRequest,
    ValidateApiKeyRequest,
)
from kingsec.application.errors import ApplicationError
from kingsec.application.ports import ApiKeyHasher, ApiKeyRepository
from kingsec.application.use_cases.create_api_key import ApiKeyError, CreateApiKey
from kingsec.application.use_cases.list_api_keys import ListApiKeys
from kingsec.application.use_cases.revoke_api_key import (
    ApiKeyNotFoundError,
    ApiKeyUnauthorizedError,
    RevokeApiKey,
)
from kingsec.application.use_cases.rotate_api_key import RotateApiKey
from kingsec.application.use_cases.validate_api_key import ValidateApiKey
from kingsec.domain.api_key import ApiKey, ApiKeyScope, ApiKeyStatus

# ── Stubs ──────────────────────────────────────────────────────────────────────


class StubApiKeyHasher(ApiKeyHasher):
    def hash(self, plaintext_key: str) -> str:
        return f"hashed:{plaintext_key}"

    def verify(self, plaintext_key: str, key_hash: str) -> bool:
        return key_hash == f"hashed:{plaintext_key}"


class StubApiKeyRepository(ApiKeyRepository):
    def __init__(self) -> None:
        self._keys: dict[str, ApiKey] = {}

    def find_by_id(self, api_key_id: str) -> ApiKey | None:
        return self._keys.get(api_key_id)

    def find_by_user_id(self, user_id: str, limit: int = 50, offset: int = 0) -> list[ApiKey]:
        items = sorted(
            [k for k in self._keys.values() if k.user_id == user_id],
            key=lambda k: k.created_at,
            reverse=True,
        )
        return items[offset : offset + limit]

    def save(self, key: ApiKey) -> None:
        self._keys[key.id] = key

    def delete(self, api_key_id: str) -> None:
        self._keys.pop(api_key_id, None)

    def count_by_user(self, user_id: str) -> int:
        return sum(1 for k in self._keys.values() if k.user_id == user_id)

    def count_all(self) -> int:
        return len(self._keys)


# ── Tests ──────────────────────────────────────────────────────────────────────


class TestCreateApiKey:
    def test_successful_creation(self) -> None:
        repo = StubApiKeyRepository()
        hasher = StubApiKeyHasher()
        uc = CreateApiKey(repo, hasher)

        request = CreateApiKeyRequest(
            user_id="user-1",
            name="CI/CD Pipeline",
            scope="read_only",
        )
        result = uc.execute(request)

        assert result.name == "CI/CD Pipeline"
        assert result.scope == "read_only"
        assert result.plaintext_key.startswith("ks_")
        assert result.api_key_id is not None
        assert result.created_at is not None

        # Verify the key was stored with the hash.
        stored = repo.find_by_id(result.api_key_id)
        assert stored is not None
        assert stored.key_hash == f"hashed:{result.plaintext_key}"
        assert stored.status == ApiKeyStatus.ACTIVE
        assert stored.scope == ApiKeyScope.READ_ONLY

    def test_full_access_scope(self) -> None:
        repo = StubApiKeyRepository()
        hasher = StubApiKeyHasher()
        uc = CreateApiKey(repo, hasher)

        request = CreateApiKeyRequest(
            user_id="user-1",
            name="Full Access Key",
            scope="full_access",
        )
        result = uc.execute(request)
        assert result.scope == "full_access"

        stored = repo.find_by_id(result.api_key_id)
        assert stored is not None
        assert stored.scope == ApiKeyScope.FULL_ACCESS

    def test_invalid_scope_raises_error(self) -> None:
        repo = StubApiKeyRepository()
        hasher = StubApiKeyHasher()
        uc = CreateApiKey(repo, hasher)

        request = CreateApiKeyRequest(
            user_id="user-1",
            name="Bad Key",
            scope="invalid_scope",
        )
        with pytest.raises(ApiKeyError):
            uc.execute(request)


class TestListApiKeys:
    def test_list_keys_for_user(self) -> None:
        repo = StubApiKeyRepository()
        hasher = StubApiKeyHasher()
        create_uc = CreateApiKey(repo, hasher)
        list_uc = ListApiKeys(repo)

        create_uc.execute(CreateApiKeyRequest(user_id="user-1", name="Key 1"))
        create_uc.execute(CreateApiKeyRequest(user_id="user-1", name="Key 2"))
        create_uc.execute(CreateApiKeyRequest(user_id="user-2", name="Other Key"))

        result = list_uc.execute(ListApiKeysRequest(user_id="user-1"))
        assert len(result) == 2
        assert all(item.user_id == "user-1" for item in result)

    def test_list_keys_empty(self) -> None:
        repo = StubApiKeyRepository()
        list_uc = ListApiKeys(repo)

        result = list_uc.execute(ListApiKeysRequest(user_id="user-1"))
        assert len(result) == 0


class TestRevokeApiKey:
    def test_revoke_own_key(self) -> None:
        repo = StubApiKeyRepository()
        hasher = StubApiKeyHasher()
        create_uc = CreateApiKey(repo, hasher)
        revoke_uc = RevokeApiKey(repo)

        created = create_uc.execute(CreateApiKeyRequest(user_id="user-1", name="My Key"))
        revoke_uc.execute(
            RevokeApiKeyRequest(
                api_key_id=created.api_key_id,
                requesting_user_id="user-1",
            )
        )

        stored = repo.find_by_id(created.api_key_id)
        assert stored is not None
        assert stored.status == ApiKeyStatus.REVOKED

    def test_revoke_other_users_key_raises_error(self) -> None:
        repo = StubApiKeyRepository()
        hasher = StubApiKeyHasher()
        create_uc = CreateApiKey(repo, hasher)
        revoke_uc = RevokeApiKey(repo)

        created = create_uc.execute(CreateApiKeyRequest(user_id="user-1", name="My Key"))
        with pytest.raises(ApiKeyUnauthorizedError):
            revoke_uc.execute(
                RevokeApiKeyRequest(
                    api_key_id=created.api_key_id,
                    requesting_user_id="user-2",
                )
            )

    def test_revoke_nonexistent_key_raises_error(self) -> None:
        repo = StubApiKeyRepository()
        revoke_uc = RevokeApiKey(repo)

        with pytest.raises(ApiKeyNotFoundError):
            revoke_uc.execute(
                RevokeApiKeyRequest(
                    api_key_id="nonexistent",
                    requesting_user_id="user-1",
                )
            )


class TestRotateApiKey:
    def test_rotate_own_key(self) -> None:
        repo = StubApiKeyRepository()
        hasher = StubApiKeyHasher()
        create_uc = CreateApiKey(repo, hasher)
        rotate_uc = RotateApiKey(repo, hasher)

        created = create_uc.execute(CreateApiKeyRequest(user_id="user-1", name="My Key"))
        original_hash = repo.find_by_id(created.api_key_id).key_hash

        result = rotate_uc.execute(
            RotateApiKeyRequest(
                api_key_id=created.api_key_id,
                requesting_user_id="user-1",
            )
        )

        assert result.api_key_id == created.api_key_id
        assert result.plaintext_key.startswith("ks_")
        assert result.plaintext_key != created.plaintext_key

        stored = repo.find_by_id(created.api_key_id)
        assert stored.key_hash != original_hash
        assert stored.status == ApiKeyStatus.ACTIVE

    def test_rotate_other_users_key_raises_error(self) -> None:
        repo = StubApiKeyRepository()
        hasher = StubApiKeyHasher()
        create_uc = CreateApiKey(repo, hasher)
        rotate_uc = RotateApiKey(repo, hasher)

        created = create_uc.execute(CreateApiKeyRequest(user_id="user-1", name="My Key"))
        with pytest.raises(ApiKeyUnauthorizedError):
            rotate_uc.execute(
                RotateApiKeyRequest(
                    api_key_id=created.api_key_id,
                    requesting_user_id="user-2",
                )
            )


class TestValidateApiKey:
    def test_validate_valid_key(self) -> None:
        repo = StubApiKeyRepository()
        hasher = StubApiKeyHasher()
        create_uc = CreateApiKey(repo, hasher)
        validate_uc = ValidateApiKey(repo, hasher)

        created = create_uc.execute(CreateApiKeyRequest(user_id="user-1", name="My Key"))
        result = validate_uc.execute(ValidateApiKeyRequest(api_key=created.plaintext_key))

        assert result.api_key_id == created.api_key_id
        assert result.user_id == "user-1"
        assert result.scope == "read_only"
        assert result.status == "active"

    def test_validate_revoked_key_raises_error(self) -> None:
        repo = StubApiKeyRepository()
        hasher = StubApiKeyHasher()
        create_uc = CreateApiKey(repo, hasher)
        revoke_uc = RevokeApiKey(repo)
        validate_uc = ValidateApiKey(repo, hasher)

        created = create_uc.execute(CreateApiKeyRequest(user_id="user-1", name="My Key"))
        revoke_uc.execute(
            RevokeApiKeyRequest(
                api_key_id=created.api_key_id,
                requesting_user_id="user-1",
            )
        )

        with pytest.raises(ApplicationError, match="revoked"):
            validate_uc.execute(ValidateApiKeyRequest(api_key=created.plaintext_key))

    def test_validate_nonexistent_key_raises_error(self) -> None:
        repo = StubApiKeyRepository()
        hasher = StubApiKeyHasher()
        validate_uc = ValidateApiKey(repo, hasher)

        with pytest.raises(ApiKeyNotFoundError):
            validate_uc.execute(ValidateApiKeyRequest(api_key="ks_nonexistent_secret"))

    def test_validate_bad_format_raises_error(self) -> None:
        repo = StubApiKeyRepository()
        hasher = StubApiKeyHasher()
        validate_uc = ValidateApiKey(repo, hasher)

        with pytest.raises(ApplicationError, match="start with"):
            validate_uc.execute(ValidateApiKeyRequest(api_key="invalid_format"))

    def test_validate_records_usage(self) -> None:
        repo = StubApiKeyRepository()
        hasher = StubApiKeyHasher()
        create_uc = CreateApiKey(repo, hasher)
        validate_uc = ValidateApiKey(repo, hasher)

        created = create_uc.execute(CreateApiKeyRequest(user_id="user-1", name="My Key"))
        stored = repo.find_by_id(created.api_key_id)
        assert stored.last_used_at is None

        validate_uc.execute(ValidateApiKeyRequest(api_key=created.plaintext_key))
        stored = repo.find_by_id(created.api_key_id)
        assert stored.last_used_at is not None
