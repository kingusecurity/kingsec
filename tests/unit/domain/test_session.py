from __future__ import annotations

from kingsec.domain.session import (
    DeviceInfo,
    Session,
    SessionId,
    SessionStatus,
    SessionType,
)


class TestSessionId:
    def test_generate_creates_id(self) -> None:
        sid = SessionId.generate()
        assert len(sid.value) == 32
        assert isinstance(sid.value, str)

    def test_str_returns_value(self) -> None:
        sid = SessionId(value="abc123")
        assert str(sid) == "abc123"

    def test_frozen(self) -> None:
        sid = SessionId(value="abc")
        try:
            sid.value = "def"
            assert False
        except AttributeError:
            pass


class TestDeviceInfo:
    def test_default_empty(self) -> None:
        di = DeviceInfo()
        assert di.device_name == ""
        assert di.platform == ""
        assert di.browser == ""

    def test_frozen(self) -> None:
        di = DeviceInfo(device_name="phone")
        try:
            di.device_name = "tablet"
            assert False
        except AttributeError:
            pass


class TestSession:
    def test_create_session(self) -> None:
        session = Session(
            id=SessionId(value="s1"),
            user_id="u1",
            session_type=SessionType.USER,
            jti="jti1",
            refresh_jti="rjti1",
            issued_at="2025-01-01T00:00:00+00:00",
            expires_at="2025-01-08T00:00:00+00:00",
            last_activity="2025-01-01T00:00:00+00:00",
            client_ip="1.2.3.4",
            user_agent="Mozilla/5.0",
            device_info=DeviceInfo(platform="Windows", browser="Chrome"),
        )
        assert session.is_active()
        assert session.status == SessionStatus.ACTIVE
        assert session.session_type == SessionType.USER

    def test_not_active_when_revoked(self) -> None:
        session = Session(
            id=SessionId(value="s1"),
            user_id="u1",
            session_type=SessionType.USER,
            jti="jti1",
            refresh_jti="rjti1",
            issued_at="2025-01-01T00:00:00+00:00",
            expires_at="2025-01-08T00:00:00+00:00",
            last_activity="2025-01-01T00:00:00+00:00",
            client_ip="1.2.3.4",
            user_agent="Mozilla/5.0",
            status=SessionStatus.REVOKED,
        )
        assert not session.is_active()

    def test_is_expired(self) -> None:
        session = Session(
            id=SessionId(value="s1"),
            user_id="u1",
            session_type=SessionType.USER,
            jti="jti1",
            refresh_jti="rjti1",
            issued_at="2025-01-01T00:00:00+00:00",
            expires_at="2025-01-01T00:00:00+00:00",
            last_activity="2025-01-01T00:00:00+00:00",
            client_ip="1.2.3.4",
            user_agent="Mozilla/5.0",
        )
        assert session.is_expired("2025-01-02T00:00:00+00:00")

    def test_not_expired(self) -> None:
        session = Session(
            id=SessionId(value="s1"),
            user_id="u1",
            session_type=SessionType.USER,
            jti="jti1",
            refresh_jti="rjti1",
            issued_at="2025-01-01T00:00:00+00:00",
            expires_at="2025-01-08T00:00:00+00:00",
            last_activity="2025-01-01T00:00:00+00:00",
            client_ip="1.2.3.4",
            user_agent="Mozilla/5.0",
        )
        assert not session.is_expired("2025-01-01T12:00:00+00:00")

    def test_is_idle(self) -> None:
        session = Session(
            id=SessionId(value="s1"),
            user_id="u1",
            session_type=SessionType.USER,
            jti="jti1",
            refresh_jti="rjti1",
            issued_at="2025-01-01T00:00:00+00:00",
            expires_at="2025-01-08T00:00:00+00:00",
            last_activity="2025-01-01T00:00:00+00:00",
            client_ip="1.2.3.4",
            user_agent="Mozilla/5.0",
            idle_timeout_seconds=60,
        )
        assert session.is_idle("2025-01-01T00:02:00+00:00")

    def test_not_idle(self) -> None:
        session = Session(
            id=SessionId(value="s1"),
            user_id="u1",
            session_type=SessionType.USER,
            jti="jti1",
            refresh_jti="rjti1",
            issued_at="2025-01-01T00:00:00+00:00",
            expires_at="2025-01-08T00:00:00+00:00",
            last_activity="2025-01-01T00:01:00+00:00",
            client_ip="1.2.3.4",
            user_agent="Mozilla/5.0",
            idle_timeout_seconds=120,
        )
        assert not session.is_idle("2025-01-01T00:02:00+00:00")

    def test_frozen(self) -> None:
        session = Session(
            id=SessionId(value="s1"),
            user_id="u1",
            session_type=SessionType.USER,
            jti="jti1",
            refresh_jti="rjti1",
            issued_at="2025-01-01T00:00:00+00:00",
            expires_at="2025-01-08T00:00:00+00:00",
            last_activity="2025-01-01T00:00:00+00:00",
            client_ip="1.2.3.4",
            user_agent="Mozilla/5.0",
        )
        try:
            session.status = SessionStatus.REVOKED
            assert False
        except AttributeError:
            pass
