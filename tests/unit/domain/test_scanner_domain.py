"""Scanner plugin domain: immutability, validation, identity, and enums."""

from __future__ import annotations

import dataclasses

import pytest
from tests.unit.domain.conftest import make_finding

from kingsec.domain import (
    Finding,
    InvariantViolation,
    OutputFormat,
    PluginAvailability,
    PluginConfig,
    ScanCategory,
    ScannerCapability,
    ScannerId,
    ScannerPluginMetadata,
    ScannerResult,
    Severity,
    TargetType,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_metadata(
    *,
    plugin_id: str = "nuclei",
    name: str = "Nuclei Scanner",
    version: str = "1.0.0",
    author: str = "KingSec Team",
    description: str = "Template-based vulnerability scanner",
    api_version: str = "1.0",
) -> ScannerPluginMetadata:
    return ScannerPluginMetadata(
        id=ScannerId(plugin_id),
        name=name,
        version=version,
        author=author,
        description=description,
        api_version=api_version,
    )


def _make_capability() -> ScannerCapability:
    return ScannerCapability(
        target_types=frozenset({TargetType.IP_ADDRESS, TargetType.HOSTNAME}),
        scan_categories=frozenset({ScanCategory.VULNERABILITY}),
        output_format=OutputFormat.STRUCTURED_JSON,
    )


def _make_result(*, findings: tuple[Finding, ...] = ()) -> ScannerResult:
    return ScannerResult(
        scanner_id=ScannerId("nuclei"),
        findings=findings,
        raw_output="some output",
        duration_seconds=1.5,
    )


# ===========================================================================
# ScannerId
# ===========================================================================


class TestScannerId:
    def test_valid_id(self) -> None:
        sid = ScannerId("nuclei")
        assert sid.value == "nuclei"
        assert str(sid) == "nuclei"

    def test_valid_with_hyphens(self) -> None:
        sid = ScannerId("owasp-zap")
        assert sid.value == "owasp-zap"

    def test_valid_with_digits(self) -> None:
        sid = ScannerId("scanner1")
        assert sid.value == "scanner1"

    def test_rejects_empty_string(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerId("")

    def test_rejects_blank_string(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerId("   ")

    def test_rejects_uppercase(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerId("Nuclei")

    def test_rejects_underscores(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerId("my_scanner")

    def test_rejects_special_characters(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerId("scanner@v1")

    def test_rejects_leading_hyphen(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerId("-nuclei")

    def test_rejects_trailing_hyphen(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerId("nuclei-")

    def test_immutable(self) -> None:
        with pytest.raises(dataclasses.FrozenInstanceError):
            ScannerId("nuclei").value = "other"  # type: ignore[misc]

    def test_equality_by_value(self) -> None:
        assert ScannerId("nuclei") == ScannerId("nuclei")
        assert ScannerId("nuclei") != ScannerId("nmap")

    def test_hash_consistent_with_equality(self) -> None:
        a, b = ScannerId("nuclei"), ScannerId("nuclei")
        assert hash(a) == hash(b)

    def test_hashable(self) -> None:
        ids = {ScannerId("nuclei"), ScannerId("nmap"), ScannerId("nuclei")}
        assert len(ids) == 2


# ===========================================================================
# ScannerPluginMetadata
# ===========================================================================


class TestScannerPluginMetadata:
    def test_valid_metadata(self) -> None:
        m = _make_metadata()
        assert m.id == ScannerId("nuclei")
        assert m.name == "Nuclei Scanner"
        assert m.version == "1.0.0"
        assert m.api_version == "1.0"

    def test_rejects_empty_name(self) -> None:
        with pytest.raises(InvariantViolation):
            _make_metadata(name="")

    def test_rejects_empty_author(self) -> None:
        with pytest.raises(InvariantViolation):
            _make_metadata(author="")

    def test_rejects_empty_description(self) -> None:
        with pytest.raises(InvariantViolation):
            _make_metadata(description="")

    def test_rejects_invalid_version_format(self) -> None:
        with pytest.raises(InvariantViolation):
            _make_metadata(version="1.0")

    def test_rejects_non_semver_version(self) -> None:
        with pytest.raises(InvariantViolation):
            _make_metadata(version="v1.0.0")

    def test_rejects_invalid_api_version(self) -> None:
        with pytest.raises(InvariantViolation):
            _make_metadata(api_version="1")

    def test_rejects_non_numeric_api_version(self) -> None:
        with pytest.raises(InvariantViolation):
            _make_metadata(api_version="v1.0")

    def test_rejects_non_scanner_id_type(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerPluginMetadata(
                id="nuclei",  # type: ignore[arg-type]
                name="Test",
                version="1.0.0",
                author="Author",
                description="Desc",
                api_version="1.0",
            )

    def test_immutable(self) -> None:
        m = _make_metadata()
        with pytest.raises(dataclasses.FrozenInstanceError):
            m.name = "Other"  # type: ignore[misc]

    def test_equality_by_value(self) -> None:
        a = _make_metadata()
        b = _make_metadata()
        assert a == b

    def test_inequality(self) -> None:
        a = _make_metadata()
        b = _make_metadata(version="2.0.0")
        assert a != b

    def test_hashable(self) -> None:
        m = _make_metadata()
        assert hash(m) == hash(_make_metadata())


# ===========================================================================
# ScanCategory
# ===========================================================================


class TestScanCategory:
    def test_all_members(self) -> None:
        members = set(ScanCategory)
        assert len(members) == 5
        assert ScanCategory.VULNERABILITY in members
        assert ScanCategory.DISCOVERY in members
        assert ScanCategory.CONFIGURATION in members
        assert ScanCategory.COMPLIANCE in members
        assert ScanCategory.INFORMATION in members

    def test_values_are_strings(self) -> None:
        assert ScanCategory.VULNERABILITY.value == "vulnerability"
        assert ScanCategory.DISCOVERY.value == "discovery"

    def test_not_ordered(self) -> None:
        with pytest.raises(TypeError):
            ScanCategory.VULNERABILITY > ScanCategory.DISCOVERY  # type: ignore[comparison-overlap]


# ===========================================================================
# OutputFormat
# ===========================================================================


class TestOutputFormat:
    def test_all_members(self) -> None:
        members = set(OutputFormat)
        assert len(members) == 3
        assert OutputFormat.FINDINGS in members
        assert OutputFormat.RAW_TEXT in members
        assert OutputFormat.STRUCTURED_JSON in members

    def test_values_are_strings(self) -> None:
        assert OutputFormat.FINDINGS.value == "findings"
        assert OutputFormat.RAW_TEXT.value == "raw_text"
        assert OutputFormat.STRUCTURED_JSON.value == "structured_json"


# ===========================================================================
# ScannerCapability
# ===========================================================================


class TestScannerCapability:
    def test_valid_capability(self) -> None:
        cap = _make_capability()
        assert TargetType.IP_ADDRESS in cap.target_types
        assert ScanCategory.VULNERABILITY in cap.scan_categories
        assert cap.output_format is OutputFormat.STRUCTURED_JSON

    def test_rejects_empty_target_types(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerCapability(
                target_types=frozenset(),
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.RAW_TEXT,
            )

    def test_rejects_empty_scan_categories(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerCapability(
                target_types=frozenset({TargetType.URL}),
                scan_categories=frozenset(),
                output_format=OutputFormat.RAW_TEXT,
            )

    def test_rejects_non_target_type_in_set(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerCapability(
                target_types=frozenset({"ip_address"}),  # type: ignore[arg-type]
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.RAW_TEXT,
            )

    def test_rejects_non_scan_category_in_set(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerCapability(
                target_types=frozenset({TargetType.IP_ADDRESS}),
                scan_categories=frozenset({"vulnerability"}),  # type: ignore[arg-type]
                output_format=OutputFormat.RAW_TEXT,
            )

    def test_rejects_non_frozenset_target_types(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerCapability(
                target_types={TargetType.IP_ADDRESS},  # type: ignore[arg-type]
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.RAW_TEXT,
            )

    def test_rejects_invalid_output_format(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerCapability(
                target_types=frozenset({TargetType.IP_ADDRESS}),
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format="raw_text",  # type: ignore[arg-type]
            )

    def test_immutable(self) -> None:
        cap = _make_capability()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cap.output_format = OutputFormat.RAW_TEXT  # type: ignore[misc]

    def test_equality_by_value(self) -> None:
        a = _make_capability()
        b = _make_capability()
        assert a == b

    def test_hashable(self) -> None:
        cap = _make_capability()
        assert hash(cap) == hash(_make_capability())


# ===========================================================================
# PluginConfig
# ===========================================================================


class TestPluginConfig:
    def test_default_is_empty(self) -> None:
        cfg = PluginConfig()
        assert cfg.settings == {}

    def test_valid_settings(self) -> None:
        cfg = PluginConfig(settings={
            "binary_path": "/usr/bin/nuclei",
            "timeout": 300,
            "rate_limit": 150,
            "verbose": True,
            "templates_dir": None,
        })
        assert cfg.settings["binary_path"] == "/usr/bin/nuclei"
        assert cfg.settings["timeout"] == 300

    def test_rejects_empty_key(self) -> None:
        with pytest.raises(InvariantViolation):
            PluginConfig(settings={"": "value"})

    def test_rejects_blank_key(self) -> None:
        with pytest.raises(InvariantViolation):
            PluginConfig(settings={"  ": "value"})

    def test_rejects_non_string_key(self) -> None:
        with pytest.raises(InvariantViolation):
            PluginConfig(settings={123: "value"})  # type: ignore[dict-item]

    def test_rejects_list_value(self) -> None:
        with pytest.raises(InvariantViolation):
            PluginConfig(settings={"key": [1, 2, 3]})  # type: ignore[dict-item]

    def test_rejects_dict_value(self) -> None:
        with pytest.raises(InvariantViolation):
            PluginConfig(settings={"key": {"nested": "dict"}})  # type: ignore[dict-item]

    def test_allows_none_value(self) -> None:
        cfg = PluginConfig(settings={"key": None})
        assert cfg.settings["key"] is None

    def test_allows_string_value(self) -> None:
        cfg = PluginConfig(settings={"key": "hello"})
        assert cfg.settings["key"] == "hello"

    def test_allows_int_value(self) -> None:
        cfg = PluginConfig(settings={"key": 42})
        assert cfg.settings["key"] == 42

    def test_allows_float_value(self) -> None:
        cfg = PluginConfig(settings={"key": 3.14})
        assert cfg.settings["key"] == 3.14

    def test_allows_bool_value(self) -> None:
        cfg = PluginConfig(settings={"key": True})
        assert cfg.settings["key"] is True

    def test_immutable(self) -> None:
        cfg = PluginConfig()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.settings = {"key": "value"}  # type: ignore[misc]

    def test_equality_by_value(self) -> None:
        a = PluginConfig(settings={"timeout": 300})
        b = PluginConfig(settings={"timeout": 300})
        assert a == b


# ===========================================================================
# PluginAvailability
# ===========================================================================


class TestPluginAvailability:
    def test_available(self) -> None:
        pa = PluginAvailability(available=True)
        assert pa.available is True
        assert pa.reason is None
        assert pa.required_dependencies == ()

    def test_unavailable_with_reason(self) -> None:
        pa = PluginAvailability(
            available=False,
            reason="nuclei binary not found in PATH",
            required_dependencies=("nuclei",),
        )
        assert pa.available is False
        assert pa.reason == "nuclei binary not found in PATH"
        assert pa.required_dependencies == ("nuclei",)

    def test_unavailable_without_reason_is_rejected(self) -> None:
        with pytest.raises(InvariantViolation):
            PluginAvailability(available=False)

    def test_rejects_empty_dependency_string(self) -> None:
        with pytest.raises(InvariantViolation):
            PluginAvailability(
                available=True,
                required_dependencies=("",),
            )

    def test_rejects_blank_dependency_string(self) -> None:
        with pytest.raises(InvariantViolation):
            PluginAvailability(
                available=True,
                required_dependencies=("  ",),
            )

    def test_rejects_non_string_dependency(self) -> None:
        with pytest.raises(InvariantViolation):
            PluginAvailability(
                available=True,
                required_dependencies=(123,),  # type: ignore[list-item]
            )

    def test_immutable(self) -> None:
        pa = PluginAvailability(available=True)
        with pytest.raises(dataclasses.FrozenInstanceError):
            pa.available = False  # type: ignore[misc]

    def test_equality_by_value(self) -> None:
        a = PluginAvailability(available=True)
        b = PluginAvailability(available=True)
        assert a == b

    def test_hashable(self) -> None:
        a = PluginAvailability(available=True)
        b = PluginAvailability(available=True)
        assert hash(a) == hash(b)


# ===========================================================================
# ScannerResult
# ===========================================================================


class TestScannerResult:
    def test_valid_result(self) -> None:
        finding = make_finding()
        r = _make_result(findings=(finding,))
        assert r.scanner_id == ScannerId("nuclei")
        assert len(r.findings) == 1
        assert r.raw_output == "some output"
        assert r.duration_seconds == 1.5

    def test_empty_findings(self) -> None:
        r = _make_result()
        assert r.findings == ()

    def test_rejects_non_scanner_id(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerResult(
                scanner_id="nuclei",  # type: ignore[arg-type]
                findings=(),
                raw_output="",
                duration_seconds=0.0,
            )

    def test_rejects_non_tuple_findings(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerResult(
                scanner_id=ScannerId("nuclei"),
                findings=[],  # type: ignore[arg-type]
                raw_output="",
                duration_seconds=0.0,
            )

    def test_rejects_negative_duration(self) -> None:
        with pytest.raises(InvariantViolation):
            ScannerResult(
                scanner_id=ScannerId("nuclei"),
                findings=(),
                raw_output="",
                duration_seconds=-1.0,
            )

    def test_allows_zero_duration(self) -> None:
        r = ScannerResult(
            scanner_id=ScannerId("nuclei"),
            findings=(),
            raw_output="",
            duration_seconds=0.0,
        )
        assert r.duration_seconds == 0.0

    def test_optional_fields(self) -> None:
        r = ScannerResult(
            scanner_id=ScannerId("nuclei"),
            findings=(),
            raw_output="",
            duration_seconds=0.0,
            scanner_version="nuclei v3.1.2",
            warnings=("deprecation notice",),
        )
        assert r.scanner_version == "nuclei v3.1.2"
        assert r.warnings == ("deprecation notice",)

    def test_immutable(self) -> None:
        r = _make_result()
        with pytest.raises(dataclasses.FrozenInstanceError):
            r.scanner_id = ScannerId("nmap")  # type: ignore[misc]

    def test_equality_by_value(self) -> None:
        a = _make_result()
        b = _make_result()
        assert a == b

    def test_hashable(self) -> None:
        a = _make_result()
        b = _make_result()
        assert hash(a) == hash(b)

    def test_findings_tuple_is_immutable(self) -> None:
        finding = make_finding()
        r = _make_result(findings=(finding,))
        with pytest.raises(TypeError):
            r.findings[0] = "other"  # type: ignore[index]


# ===========================================================================
# Cross-cutting: severity ordering with ScannerResult
# ===========================================================================


class TestCrossCutting:
    def test_scanner_id_as_dict_key(self) -> None:
        d = {ScannerId("nuclei"): "first", ScannerId("nmap"): "second"}
        assert d[ScannerId("nuclei")] == "first"

    def test_frozenset_of_capabilities(self) -> None:
        caps = {_make_capability(), _make_capability()}
        assert len(caps) == 1

    def test_frozenset_of_availability(self) -> None:
        items = {
            PluginAvailability(available=True),
            PluginAvailability(available=True),
        }
        assert len(items) == 1

    def test_severity_max_in_result_findings(self) -> None:
        low = make_finding(severity=Severity.LOW)
        critical = make_finding(severity=Severity.CRITICAL)
        r = _make_result(findings=(low, critical))
        worst = max(f.severity for f in r.findings)
        assert worst is Severity.CRITICAL
