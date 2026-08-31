from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports import TokenService, UserRepository
from kingsec.application.ports.outbound.session_repository import SessionRepository
from kingsec.application.use_cases.session_dto import (
    RefreshSessionRequest,
    RefreshSessionResponse,
)


class RefreshSession:
    """Session-aware refresh: rotates the session's tracked JTIs and
    detects refresh-token reuse (replay).

    KSEC-75-04: this must not trust the OLD refresh token's own
    username/role claims when minting the new access token - it
    re-fetches the user from UserRepository and rejects the refresh if
    the account no longer exists or is no longer active, exactly like
    RefreshToken (the /auth/refresh use case) already does. This keeps
    both refresh endpoints in agreement on security-critical user
    state while this use case keeps its own distinct responsibility:
    session-row rotation and replay/reuse detection.
    """

    def __init__(self, repo: SessionRepository, tokens: TokenService, users: UserRepository) -> None:
        self._repo = repo
        self._tokens = tokens
        self._users = users

    def execute(self, request: RefreshSessionRequest) -> RefreshSessionResponse:
        active = self._repo.find_active_by_user(request.user_id)

        matching = [s for s in active if s.refresh_jti == request.old_refresh_jti]

        if not matching:
            if active:
                # The presented refresh_jti doesn't match any currently
                # active session for this user, but active sessions DO
                # exist - a rotated-out (already-used) refresh token was
                # replayed. Revoke everything as a precaution.
                for s in active:
                    self._tokens.revoke_token(s.jti)
                    self._tokens.revoke_token(s.refresh_jti)
                self._repo.revoke_all_by_user(request.user_id)
                return RefreshSessionResponse(valid=False, replay_detected=True)
            return RefreshSessionResponse(valid=False, replay_detected=False)

        session = matching[0]

        # KSEC-75-04: re-fetch the user and re-validate current account
        # state - never trust the old refresh token's embedded identity/
        # role as authoritative. A deactivated or deleted account must
        # not be able to refresh through this endpoint, matching
        # RefreshToken's existing is_active check.
        user = self._users.find_by_id(request.user_id)
        if user is None or not user.is_active:
            return RefreshSessionResponse(valid=False, replay_detected=False)

        new_access_token = self._tokens.create_access_token(
            user_id=user.id, username=user.username, role=user.role.label
        )
        new_refresh_token = self._tokens.create_refresh_token(
            user_id=user.id, username=user.username, role=user.role.label
        )
        new_access_claims = self._tokens.verify_access_token(new_access_token)
        new_refresh_claims = self._tokens.verify_refresh_token(new_refresh_token)

        self._tokens.revoke_token(session.refresh_jti)
        self._tokens.revoke_token(session.jti)
        self._repo.update_refresh_jti(str(session.id), new_refresh_claims.jti)
        self._repo.update_access_jti(str(session.id), new_access_claims.jti)
        now_iso = datetime.fromtimestamp(datetime.now(UTC).timestamp(), tz=UTC).isoformat()
        self._repo.update_activity(str(session.id), now_iso)

        return RefreshSessionResponse(
            valid=True,
            replay_detected=False,
            access_token=new_access_token,
            refresh_token=new_refresh_token,
        )
