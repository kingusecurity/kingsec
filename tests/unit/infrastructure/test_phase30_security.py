"""Phase 30 security tests: sandboxing, signature validation, lockout, upload hardening."""

from __future__ import annotations

import tempfile
import time
import zipfile
from pathlib import Path

import pytest

from kingsec.domain.plugin_package import PluginSignature
from kingsec.infrastructure.plugin.sandbox import (
    ExecutionTimeout,
    PluginSandbox,
    SandboxViolation,
    build_sandbox_for_plugin,
)
from kingsec.infrastructure.plugin.validator import _TRUSTED_PUBLISHER_FINGERPRINTS, PluginValidator
from kingsec.infrastructure.security.lockout import AccountLockoutService

# ---------------------------------------------------------------------------
# Plugin Sandbox Tests
# ---------------------------------------------------------------------------


class TestPluginSandbox:
    """Test sandbox creation, path validation, timeout, and cleanup."""

    def test_sandbox_basic_creation(self) -> None:
        sandbox = PluginSandbox("test-plugin")
        assert sandbox.plugin_id == "test-plugin"

    def test_sandbox_context_manager(self) -> None:
        sandbox = PluginSandbox("test-plugin", execution_timeout=10)
        with sandbox:
            assert sandbox._start_time is not None
        assert sandbox._start_time is None

    def test_sandbox_temp_dir_created(self) -> None:
        sandbox = PluginSandbox("test-plugin")
        temp = sandbox.temp_dir
        assert temp.exists()
        assert "test-plugin" in str(temp)
        sandbox.cleanup()
        assert not temp.exists()

    def test_sandbox_temp_dir_reused(self) -> None:
        sandbox = PluginSandbox("test-plugin")
        t1 = sandbox.temp_dir
        t2 = sandbox.temp_dir
        assert t1 == t2
        sandbox.cleanup()

    def test_sandbox_validate_read_access_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            allowed = Path(tmpdir)
            sandbox = PluginSandbox("test-plugin", allowed_read_paths=(allowed,))
            # Should not raise
            sandbox.validate_file_access(allowed / "subdir" / "file.txt")

    def test_sandbox_validate_read_access_denied(self) -> None:
        with tempfile.TemporaryDirectory() as allowed:
            with tempfile.TemporaryDirectory() as denied:
                sandbox = PluginSandbox("test-plugin", allowed_read_paths=(Path(allowed),))
                with pytest.raises(SandboxViolation, match="denied read access"):
                    sandbox.validate_file_access(Path(denied) / "file.txt")

    def test_sandbox_validate_write_access_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            allowed = Path(tmpdir)
            sandbox = PluginSandbox("test-plugin", allowed_write_paths=(allowed,))
            sandbox.validate_file_access(allowed / "output.txt", for_write=True)

    def test_sandbox_validate_write_access_denied(self) -> None:
        with tempfile.TemporaryDirectory() as allowed:
            with tempfile.TemporaryDirectory() as denied:
                sandbox = PluginSandbox("test-plugin", allowed_write_paths=(Path(allowed),))
                with pytest.raises(SandboxViolation, match="denied write access"):
                    sandbox.validate_file_access(Path(denied) / "file.txt", for_write=True)

    def test_sandbox_validate_network_access_http(self) -> None:
        sandbox = PluginSandbox("test-plugin")
        # Should not raise for valid external HTTP URL
        sandbox.validate_network_access("https://example.com/api")

    def test_sandbox_validate_network_access_ftp_denied(self) -> None:
        sandbox = PluginSandbox("test-plugin")
        with pytest.raises(SandboxViolation, match="denied network access"):
            sandbox.validate_network_access("ftp://example.com/file")

    def test_sandbox_validate_network_access_ssrf_denied(self) -> None:
        sandbox = PluginSandbox("test-plugin")
        with pytest.raises(SandboxViolation, match="denied network access"):
            sandbox.validate_network_access("http://127.0.0.1/admin")

    def test_sandbox_check_timeout_no_start(self) -> None:
        sandbox = PluginSandbox("test-plugin", execution_timeout=1)
        # Should not raise if not started
        sandbox.check_timeout()

    def test_sandbox_check_timeout_within_limit(self) -> None:
        sandbox = PluginSandbox("test-plugin", execution_timeout=10)
        sandbox.start()
        sandbox.check_timeout()  # Should not raise
        sandbox.stop()

    def test_sandbox_check_timeout_exceeded(self) -> None:
        sandbox = PluginSandbox("test-plugin", execution_timeout=0)
        sandbox.start()
        time.sleep(0.01)
        with pytest.raises(ExecutionTimeout, match="exceeded execution timeout"):
            sandbox.check_timeout()
        sandbox.stop()

    def test_sandbox_cleanup_idempotent(self) -> None:
        sandbox = PluginSandbox("test-plugin")
        _ = sandbox.temp_dir
        sandbox.cleanup()
        sandbox.cleanup()  # Should not raise

    def test_sandbox_custom_temp_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            custom = Path(tmpdir) / "custom"
            sandbox = PluginSandbox("test-plugin", temp_dir=custom)
            assert sandbox.temp_dir == custom


class TestBuildSandboxForPlugin:
    """Test the sandbox builder from permissions."""

    def test_build_sandbox_basic(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            sandbox = build_sandbox_for_plugin(
                "test-plugin",
                permissions=("filesystem_read",),
                data_dir=data_dir,
            )
            assert sandbox.plugin_id == "test-plugin"
            sandbox.cleanup()

    def test_build_sandbox_with_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            sandbox = build_sandbox_for_plugin(
                "test-plugin",
                permissions=("filesystem_read", "filesystem_write"),
                data_dir=data_dir,
            )
            # Output directory should be created
            output_dir = data_dir / "plugins" / "test-plugin" / "output"
            assert output_dir.exists()
            sandbox.cleanup()

    def test_build_sandbox_custom_limits(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = build_sandbox_for_plugin(
                "test-plugin",
                permissions=(),
                data_dir=Path(tmpdir),
                execution_timeout=60,
                memory_limit_mb=512,
            )
            assert sandbox._execution_timeout == 60
            assert sandbox._memory_limit_mb == 512
            sandbox.cleanup()


# ---------------------------------------------------------------------------
# Plugin Signature Validation Tests
# ---------------------------------------------------------------------------


class TestPluginSignatureValidation:
    """Test the enhanced plugin validator signature checks."""

    def setup_method(self) -> None:
        self.validator = PluginValidator()

    def test_validate_signature_untrusted_publisher(self) -> None:
        sig = PluginSignature(
            algorithm="hmac-sha256",
            value="a" * 64,
            public_key_fingerprint="unknown-publisher",
        )
        assert self.validator.validate_signature("/nonexistent", sig) is False

    def test_validate_signature_trusted_publisher(self) -> None:
        sig = PluginSignature(
            algorithm="hmac-sha256",
            value="a" * 64,
            public_key_fingerprint="kingsec-official",
        )
        assert self.validator.validate_signature("/nonexistent", sig) is True

    def test_validate_signature_unsupported_algorithm(self) -> None:
        sig = PluginSignature(
            algorithm="rsa-sha256",
            value="a" * 64,
            public_key_fingerprint="kingsec-official",
        )
        assert self.validator.validate_signature("/nonexistent", sig) is False

    def test_validate_signature_short_value(self) -> None:
        sig = PluginSignature(
            algorithm="hmac-sha256",
            value="tooshort",
            public_key_fingerprint="kingsec-official",
        )
        assert self.validator.validate_signature("/nonexistent", sig) is False

    def test_validate_signature_empty_value(self) -> None:
        sig = PluginSignature(
            algorithm="hmac-sha256",
            value="",
            public_key_fingerprint="kingsec-official",
        )
        assert self.validator.validate_signature("/nonexistent", sig) is False

    def test_trusted_publishers_contains_expected(self) -> None:
        assert "kingsec-official" in _TRUSTED_PUBLISHER_FINGERPRINTS
        assert "kingsec-plugins" in _TRUSTED_PUBLISHER_FINGERPRINTS

    def test_validate_manifest_with_signature(self) -> None:
        manifest_data = {
            "id": "test-plugin",
            "name": "Test Plugin",
            "version": "1.0.0",
            "signature": {
                "algorithm": "hmac-sha256",
                "value": "a" * 64,
                "public_key_fingerprint": "kingsec-official",
            },
        }
        manifest = self.validator.validate_manifest(manifest_data)
        assert manifest.signature is not None
        assert manifest.signature.algorithm == "hmac-sha256"

    def test_validate_manifest_without_signature(self) -> None:
        manifest_data = {
            "id": "test-plugin",
            "name": "Test Plugin",
            "version": "1.0.0",
        }
        manifest = self.validator.validate_manifest(manifest_data)
        assert manifest.signature is None


# ---------------------------------------------------------------------------
# Account Lockout Tests
# ---------------------------------------------------------------------------


class TestAccountLockoutService:
    """Test account lockout with progressive delays."""

    def test_no_lockout_initially(self) -> None:
        lockout = AccountLockoutService(max_failures=3, lockout_window=60)
        assert lockout.is_locked_out("alice") is False

    def test_lockout_after_threshold(self) -> None:
        lockout = AccountLockoutService(max_failures=3, lockout_window=60)
        lockout.record_failure("alice")
        lockout.record_failure("alice")
        assert lockout.is_locked_out("alice") is False
        lockout.record_failure("alice")
        assert lockout.is_locked_out("alice") is True

    def test_lockout_retry_after(self) -> None:
        lockout = AccountLockoutService(max_failures=2, lockout_window=60)
        lockout.record_failure("alice")
        lockout.record_failure("alice")
        retry = lockout.retry_after("alice")
        assert retry > 0

    def test_clear_resets_lockout(self) -> None:
        lockout = AccountLockoutService(max_failures=2, lockout_window=60)
        lockout.record_failure("alice")
        lockout.record_failure("alice")
        assert lockout.is_locked_out("alice") is True
        lockout.clear("alice")
        assert lockout.is_locked_out("alice") is False

    def test_different_users_independent(self) -> None:
        lockout = AccountLockoutService(max_failures=2, lockout_window=60)
        lockout.record_failure("alice")
        lockout.record_failure("alice")
        assert lockout.is_locked_out("alice") is True
        assert lockout.is_locked_out("bob") is False

    def test_progressive_lockout_duration(self) -> None:
        lockout = AccountLockoutService(max_failures=1, lockout_window=60)
        # First lockout: 60s
        lockout.record_failure("alice")
        assert lockout.is_locked_out("alice") is True
        first_retry = lockout.retry_after("alice")
        lockout.clear("alice")
        # Second lockout: 120s
        lockout.record_failure("alice")
        second_retry = lockout.retry_after("alice")
        assert second_retry > first_retry
        lockout.clear("alice")

    def test_eviction_cleans_old_records(self) -> None:
        lockout = AccountLockoutService(max_failures=2, lockout_window=1, eviction_interval=2)
        lockout.record_failure("alice")
        lockout.record_failure("alice")
        lockout.clear("alice")
        time.sleep(1.5)
        # Trigger eviction with more failures than eviction_interval
        lockout.record_failure("bob")
        lockout.record_failure("bob")
        # Alice should have been evicted
        assert "alice" not in lockout._records


# ---------------------------------------------------------------------------
# Upload Hardening Tests
# ---------------------------------------------------------------------------


class TestUploadHardening:
    """Test upload validation helpers from plugin_routes."""

    def _make_valid_zip(self, tmpdir: Path, entries: int = 1, entry_size: int = 100) -> Path:
        """Create a valid ZIP file for testing."""
        zip_path = tmpdir / "test_plugin.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("plugin.json", '{"id": "test", "name": "test", "version": "1.0.0"}')
            for i in range(entries):
                zf.writestr(f"file_{i}.py", "x" * entry_size)
        return zip_path

    def test_validate_upload_extension_zip(self) -> None:
        from kingsec.adapters.inbound.web.plugin_routes import _validate_upload_extension
        # Should not raise for .zip
        _validate_upload_extension("plugin.zip")

    def test_validate_upload_extension_txt_rejected(self) -> None:
        from fastapi import HTTPException

        from kingsec.adapters.inbound.web.plugin_routes import _validate_upload_extension
        with pytest.raises(HTTPException, match="not allowed"):
            _validate_upload_extension("malware.txt")

    def test_validate_upload_extension_exe_rejected(self) -> None:
        from fastapi import HTTPException

        from kingsec.adapters.inbound.web.plugin_routes import _validate_upload_extension
        with pytest.raises(HTTPException, match="not allowed"):
            _validate_upload_extension("payload.exe")

    def test_validate_upload_extension_no_filename(self) -> None:
        from fastapi import HTTPException

        from kingsec.adapters.inbound.web.plugin_routes import _validate_upload_extension
        with pytest.raises(HTTPException, match="Filename is required"):
            _validate_upload_extension(None)

    def test_validate_upload_content_valid_zip(self) -> None:
        from kingsec.adapters.inbound.web.plugin_routes import _validate_upload_content
        # ZIP magic number: PK\x03\x04
        data = b"PK\x03\x04" + b"\x00" * 100
        _validate_upload_content(data, "plugin.zip")  # Should not raise

    def test_validate_upload_content_not_zip(self) -> None:
        from fastapi import HTTPException

        from kingsec.adapters.inbound.web.plugin_routes import _validate_upload_content
        with pytest.raises(HTTPException, match="does not appear to be a valid ZIP"):
            _validate_upload_content(b"MZ\x90\x00" + b"\x00" * 100, "malware.zip")

    def test_validate_upload_content_too_small(self) -> None:
        from fastapi import HTTPException

        from kingsec.adapters.inbound.web.plugin_routes import _validate_upload_content
        with pytest.raises(HTTPException, match="too small"):
            _validate_upload_content(b"PK", "tiny.zip")

    def test_validate_archive_safety_normal(self) -> None:
        from kingsec.adapters.inbound.web.plugin_routes import _validate_archive_safety
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = self._make_valid_zip(Path(tmpdir))
            _validate_archive_safety(str(zip_path))  # Should not raise

    def test_validate_archive_safety_too_many_entries(self) -> None:
        from fastapi import HTTPException

        from kingsec.adapters.inbound.web.plugin_routes import _validate_archive_safety
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = self._make_valid_zip(Path(tmpdir), entries=10001)
            with pytest.raises(HTTPException, match="too many entries"):
                _validate_archive_safety(str(zip_path))

    def test_validate_archive_safety_oversized_entry(self) -> None:
        from fastapi import HTTPException

        from kingsec.adapters.inbound.web.plugin_routes import _validate_archive_safety
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "big.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                # Write 51 MB of zeros (highly compressible to trigger ratio check)
                data = b"\x00" * (51 * 1024 * 1024)
                zf.writestr("huge.bin", data)
            with pytest.raises(HTTPException, match="too large|suspicious"):
                _validate_archive_safety(str(zip_path))

    def test_validate_archive_safety_bad_zip(self) -> None:
        from fastapi import HTTPException

        from kingsec.adapters.inbound.web.plugin_routes import _validate_archive_safety
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_zip = Path(tmpdir) / "bad.zip"
            bad_zip.write_bytes(b"PK\x03\x04\x00" + b"\x00" * 100)
            with pytest.raises(HTTPException):
                _validate_archive_safety(str(bad_zip))
