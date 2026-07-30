"""Security tests: input validation, path traversal, SSRF, sanitization."""

from __future__ import annotations

from pathlib import Path

import pytest

from kingsec.infrastructure.security.input_validation import (
    detect_sql_injection,
    escape_html,
    sanitize_filename,
    sanitize_path_component,
    validate_backup_id,
    validate_identifier,
    validate_plugin_id,
    validate_url_for_ssrf,
)

# ============================================================================
# Identifier validation
# ============================================================================

class TestValidateIdentifier:
    def test_valid_alphanumeric(self) -> None:
        validate_identifier("backup-123")
        validate_identifier("plugin_v2.1")
        validate_identifier("scan_2024-01")

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValueError, match="Invalid"):
            validate_identifier("")

    def test_rejects_path_traversal(self) -> None:
        with pytest.raises(ValueError, match="Invalid"):
            validate_identifier("../../../etc/passwd")

    def test_rejects_slash(self) -> None:
        with pytest.raises(ValueError, match="Invalid"):
            validate_identifier("backup/subdir")

    def test_rejects_backslash(self) -> None:
        with pytest.raises(ValueError, match="Invalid"):
            validate_identifier("backup\\subdir")

    def test_rejects_special_chars(self) -> None:
        with pytest.raises(ValueError, match="Invalid"):
            validate_identifier("backup; rm -rf /")

    def test_custom_label(self) -> None:
        with pytest.raises(ValueError, match="backup_id"):
            validate_backup_id("bad/id")


class TestValidateBackupId:
    def test_valid(self) -> None:
        validate_backup_id("bkp-123")

    def test_invalid(self) -> None:
        with pytest.raises(ValueError):
            validate_backup_id("../../etc/passwd")


class TestValidatePluginId:
    def test_valid(self) -> None:
        validate_plugin_id("my-plugin_v2")

    def test_invalid(self) -> None:
        with pytest.raises(ValueError):
            validate_plugin_id("malicious/../plugin")


# ============================================================================
# Path sanitization
# ============================================================================

class TestSanitizePathComponent:
    def test_removes_dotdot(self) -> None:
        result = sanitize_path_component("../../../etc/passwd")
        assert ".." not in result
        assert "/" not in result

    def test_normal_string(self) -> None:
        result = sanitize_path_component("normal-file")
        assert result == "normal-file"

    def test_removes_backslash(self) -> None:
        result = sanitize_path_component("path\\to\\file")
        assert "\\" not in result


# ============================================================================
# SSRF protection
# ============================================================================

class TestValidateUrlForSsrf:
    def test_valid_public_url(self) -> None:
        validate_url_for_ssrf("https://api.example.com/v1/data")

    def test_rejects_http(self) -> None:
        with pytest.raises(ValueError, match="http or https"):
            validate_url_for_ssrf("ftp://example.com/file")

    def test_rejects_loopback(self) -> None:
        with pytest.raises(ValueError, match="loopback"):
            validate_url_for_ssrf("http://127.0.0.1/admin")

    def test_rejects_private_10(self) -> None:
        with pytest.raises(ValueError, match="private"):
            validate_url_for_ssrf("http://10.0.0.1/internal")

    def test_rejects_private_172(self) -> None:
        with pytest.raises(ValueError, match="private"):
            validate_url_for_ssrf("http://172.16.0.1/internal")

    def test_rejects_private_192(self) -> None:
        with pytest.raises(ValueError, match="private"):
            validate_url_for_ssrf("http://192.168.1.1/internal")

    def test_rejects_link_local(self) -> None:
        with pytest.raises(ValueError, match="private|link-local"):
            validate_url_for_ssrf("http://169.254.169.254/metadata")

    def test_rejects_localhost(self) -> None:
        with pytest.raises(ValueError, match="internal"):
            validate_url_for_ssrf("http://localhost/admin")

    def test_rejects_no_hostname(self) -> None:
        with pytest.raises(ValueError, match="no hostname"):
            validate_url_for_ssrf("http:///path")

    def test_rejects_reserved(self) -> None:
        with pytest.raises(ValueError, match="reserved|private"):
            validate_url_for_ssrf("http://0.0.0.0/admin")

    def test_ipv6_loopback(self) -> None:
        with pytest.raises(ValueError, match="loopback"):
            validate_url_for_ssrf("http://[::1]/admin")

    def test_ipv6_private(self) -> None:
        with pytest.raises(ValueError, match="private"):
            validate_url_for_ssrf("http://[fd00::1]/internal")


# ============================================================================
# SQL injection detection
# ============================================================================

class TestDetectSqlInjection:
    def test_normal_input(self) -> None:
        assert detect_sql_injection("normal user input") is False

    def test_semicolon_drop(self) -> None:
        assert detect_sql_injection("'; DROP TABLE users; --") is True

    def test_comment_sequence(self) -> None:
        assert detect_sql_injection("admin'--") is True

    def test_union_select(self) -> None:
        assert detect_sql_injection("1 UNION SELECT * FROM users --") is True

    def test_insert_attempt(self) -> None:
        assert detect_sql_injection("; INSERT INTO admins VALUES") is True

    def test_empty_string(self) -> None:
        assert detect_sql_injection("") is False


# ============================================================================
# HTML escaping
# ============================================================================

class TestEscapeHtml:
    def test_escapes_angle_brackets(self) -> None:
        assert escape_html("<script>") == "&lt;script&gt;"

    def test_escapes_quotes(self) -> None:
        assert escape_html('"hello"') == "&quot;hello&quot;"

    def test_escapes_ampersand(self) -> None:
        assert escape_html("a & b") == "a &amp; b"

    def test_escapes_single_quote(self) -> None:
        assert escape_html("it's") == "it&#x27;s"

    def test_no_escape_needed(self) -> None:
        assert escape_html("hello world") == "hello world"


# ============================================================================
# Filename sanitization
# ============================================================================

class TestSanitizeFilename:
    def test_normal_filename(self) -> None:
        assert sanitize_filename("report.pdf") == "report.pdf"

    def test_removes_angle_brackets(self) -> None:
        result = sanitize_filename("<script>alert(1)</script>.pdf")
        assert "<" not in result
        assert ">" not in result

    def test_removes_null_bytes(self) -> None:
        result = sanitize_filename("file\x00.pdf")
        assert "\x00" not in result

    def test_strips_dots(self) -> None:
        result = sanitize_filename("...hidden...")
        assert not result.startswith(".")

    def test_empty_becomes_unnamed(self) -> None:
        assert sanitize_filename("") == "unnamed"

    def test_max_length(self) -> None:
        long_name = "a" * 300
        result = sanitize_filename(long_name)
        assert len(result) <= 255

    def test_path_separators_replaced(self) -> None:
        result = sanitize_filename("path/to/file.txt")
        assert "/" not in result
        assert "\\" not in result


# ============================================================================
# Backup storage path traversal
# ============================================================================

class TestBackupStorageSecurity:
    def test_rejects_traversal_in_write(self) -> None:
        from kingsec.infrastructure.backup.storage import FilesystemBackupStorage

        storage = FilesystemBackupStorage("/tmp/test-backups")
        with pytest.raises(ValueError, match="Invalid"):
            storage.write("../../../etc/passwd", b"data")

    def test_rejects_traversal_in_read(self) -> None:
        from kingsec.infrastructure.backup.storage import FilesystemBackupStorage

        storage = FilesystemBackupStorage("/tmp/test-backups")
        with pytest.raises(ValueError, match="Invalid"):
            storage.read("../../etc/shadow")

    def test_rejects_traversal_in_delete(self) -> None:
        from kingsec.infrastructure.backup.storage import FilesystemBackupStorage

        storage = FilesystemBackupStorage("/tmp/test-backups")
        with pytest.raises(ValueError, match="Invalid"):
            storage.delete("backup; rm -rf /")

    def test_valid_id_works(self) -> None:
        from kingsec.infrastructure.backup.storage import FilesystemBackupStorage

        storage = FilesystemBackupStorage("/tmp/test-backups-security")
        path = storage.write("bkp-123", b"test data")
        assert Path(path).exists()
        data = storage.read("bkp-123")
        assert data == b"test data"
        storage.delete("bkp-123")


# ============================================================================
# Plugin installer path traversal
# ============================================================================

class TestPluginInstallerSecurity:
    def test_rejects_traversal_in_plugin_id(self) -> None:
        from kingsec.infrastructure.plugin.installer import PluginInstaller

        installer = PluginInstaller("/tmp/test-plugins")
        with pytest.raises(ValueError, match="Invalid"):
            installer._plugin_dir("../../../malicious")

    def test_valid_plugin_id(self) -> None:
        from kingsec.infrastructure.plugin.installer import PluginInstaller

        installer = PluginInstaller("/tmp/test-plugins")
        result = installer._plugin_dir("my-plugin_v2")
        assert "my-plugin_v2" in result
