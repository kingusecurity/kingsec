"""Tests for audit domain value objects."""

from __future__ import annotations

import pytest

from kingsec.domain.audit import AuditAction, AuditEntry


class TestAuditAction:
    def test_all_actions_defined(self) -> None:
        expected = {
            "login",
            "failed_login",
            "logout",
            "token_refreshed",
            "user_registered",
            "admin_bootstrapped",
            "role_changed",
            "password_changed",
            "password_reset",
            "user_activated",
            "user_deactivated",
            "assessment_created",
            "assessment_started",
            "assessment_completed",
            "assessment_failed",
            "assessment_cancelled",
            "assessment_deleted",
            "assessment_submitted",
            "report_generated",
            "authorization_failure",
            "authorization_grant_created",
            "authorization_grant_revoked",
            "scope_check_refused",
            "scope_check_overridden",
            "schedule_created",
            "schedule_updated",
            "schedule_deleted",
            "schedule_triggered",
            "schedule_paused",
            "schedule_resumed",
            "schedule_enabled",
            "schedule_disabled",
            "schedule_occurrence_unresolved",
            "execution_inspected",
            "execution_reconciled",
            "notification_sent",
            "notification_failed",
            "notification_retried",
            "notification_read",
            "notification_deleted",
            "plugin_installed",
            "plugin_updated",
            "plugin_uninstalled",
            "plugin_enabled",
            "plugin_disabled",
            "plugin_validated",
            "plugin_rolled_back",
            "agent_registered",
            "agent_heartbeat",
            "agent_disabled",
            "agent_enabled",
            "agent_removed",
            "agent_job_assigned",
            "agent_job_completed",
            "agent_job_failed",
            "pipeline_started",
            "pipeline_advanced",
            "pipeline_cancelled",
            "pipeline_paused",
            "pipeline_resumed",
            "pipeline_retried",
            "backup_created",
            "backup_completed",
            "backup_failed",
            "backup_restored",
            "backup_deleted",
            "snapshot_created",
            "snapshot_restored",
            "health_check",
            "liveness_check",
            "readiness_check",
            "system_stopped",
            "system_restarted",
            "metrics_collected",
            "startup_validated",
            "integration_connected",
            "integration_disconnected",
            "integration_test_failed",
            "ai_provider_configured",
            "ai_provider_test_failed",
            "webhook_sent",
            "email_sent",
            "ticket_created",
            "export_completed",
            "connection_failed",
            "license_activated",
            "license_expired",
            "license_renewed",
            "license_validation_failed",
            "license_deactivated",
            "edition_changed",
            "compliance_report_generated",
            "compliance_exported",
            "copilot_ask",
            "copilot_conversation_deleted",
            "note_created",
            "note_pinned",
            "note_unpinned",
            "note_deleted",
        }
        actual = {a.value for a in AuditAction}
        assert actual == expected

    def test_action_is_str(self) -> None:
        assert isinstance(AuditAction.LOGIN, str)
        assert AuditAction.LOGIN == "login"

    def test_action_comparison(self) -> None:
        assert AuditAction.LOGIN == AuditAction.LOGIN
        assert AuditAction.LOGIN != AuditAction.LOGOUT


class TestAuditEntry:
    def test_frozen_dataclass(self) -> None:
        entry = AuditEntry(action=AuditAction.LOGIN)
        with pytest.raises(AttributeError):
            entry.action = AuditAction.LOGOUT  # type: ignore[misc]

    def test_default_values(self) -> None:
        entry = AuditEntry(action=AuditAction.LOGIN)
        assert entry.action == AuditAction.LOGIN
        assert entry.resource_type == ""
        assert entry.resource_id == ""
        assert entry.success is True
        assert entry.reason == ""
        assert entry.timestamp != ""  # auto-generated
        assert entry.user_id == ""
        assert entry.username == ""
        assert entry.role == ""
        assert entry.ip_address == ""
        assert entry.user_agent == ""
        assert entry.correlation_id == ""
        assert entry.metadata == {}

    def test_full_entry(self) -> None:
        entry = AuditEntry(
            action=AuditAction.ASSESSMENT_CREATED,
            resource_type="assessment",
            resource_id="abc-123",
            success=True,
            reason="",
            timestamp="2025-01-01T00:00:00+00:00",
            user_id="user-1",
            username="admin",
            role="ADMIN",
            ip_address="127.0.0.1",
            user_agent="Mozilla/5.0",
            correlation_id="req-123",
            metadata={"target": "10.0.0.1"},
        )
        assert entry.action == AuditAction.ASSESSMENT_CREATED
        assert entry.resource_type == "assessment"
        assert entry.resource_id == "abc-123"
        assert entry.success is True
        assert entry.user_id == "user-1"
        assert entry.username == "admin"
        assert entry.role == "ADMIN"
        assert entry.ip_address == "127.0.0.1"
        assert entry.user_agent == "Mozilla/5.0"
        assert entry.correlation_id == "req-123"
        assert entry.metadata == {"target": "10.0.0.1"}

    def test_metadata_default_is_empty_dict(self) -> None:
        entry1 = AuditEntry(action=AuditAction.LOGIN)
        entry2 = AuditEntry(action=AuditAction.LOGIN)
        # Default metadata dicts are independent (not shared).
        assert entry1.metadata is not entry2.metadata

    def test_failed_entry(self) -> None:
        entry = AuditEntry(
            action=AuditAction.FAILED_LOGIN,
            success=False,
            reason="invalid credentials",
            username="attacker",
        )
        assert entry.success is False
        assert entry.reason == "invalid credentials"

    def test_equality(self) -> None:
        entry1 = AuditEntry(
            action=AuditAction.LOGIN,
            timestamp="2025-01-01T00:00:00+00:00",
        )
        entry2 = AuditEntry(
            action=AuditAction.LOGIN,
            timestamp="2025-01-01T00:00:00+00:00",
        )
        assert entry1 == entry2

    def test_inequality(self) -> None:
        entry1 = AuditEntry(action=AuditAction.LOGIN)
        entry2 = AuditEntry(action=AuditAction.LOGOUT)
        assert entry1 != entry2
