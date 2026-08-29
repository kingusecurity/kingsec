"""Phase 28: automated guard against the exact class of drift Phase 26/27
found by manual audit — a `KINGSEC_*` variable documented in a deployment
file that is not actually a `Settings` field (or vice versa: a migration-
only variable that quietly becomes a real, accepted field without anyone
updating the documentation that currently says otherwise).

Before this phase, nothing in the test suite ever cross-referenced
`.env.example`, `README.md`, or `docs/INSTALL.md` against `Settings`'
real, introspected field set (confirmed by search — no existing test
mentions `.env.example`, `model_fields`, or either documentation file).
Phase 26 found `KINGSEC_STORAGE__DATABASE_URL` documented as a general
database override across all three files when it is not a `Settings`
field at all; nothing caught this automatically, it was found only by a
manual, ad hoc audit.

This module tests the *contract*, not runtime behavior: it makes no
change to `Settings`, `.env.example`'s content, or any documentation file.
It only adds a test-side check that would have failed loudly the moment
that documentation drifted from the real field set, instead of silently
sitting wrong until the next manual audit.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from kingsec.infrastructure.config.settings import Settings

_REPO_ROOT = Path(__file__).resolve().parents[4]

# The one KINGSEC_* name that is deliberately documented but is NOT a
# Settings field: it is read directly by the Alembic CLI (env.py, raw
# os.environ access) as a migration-only override, independent of the
# running server (see Phase 26/27 reports). Setting it makes the running
# server refuse to start (extra_forbidden). If this set ever needs a
# second entry, that is a real, visible signal that another migration-only
# (or otherwise deliberately non-Settings) variable has been documented -
# not something that should pass silently.
_DOCUMENTED_NON_SETTINGS_VARS = frozenset({"KINGSEC_STORAGE__DATABASE_URL"})

_KINGSEC_VAR_PATTERN = re.compile(r"KINGSEC_[A-Z0-9_]+")


def _real_settings_field_paths() -> set[str]:
    """Every `KINGSEC_<GROUP>__<FIELD>` path Settings actually accepts.

    Mirrors pydantic-settings' own env-var naming convention
    (env_prefix="KINGSEC_", env_nested_delimiter="__") by walking the real,
    live `Settings.model_fields` tree - not a hand-maintained list that
    could itself drift from the code.
    """
    paths: set[str] = set()
    for group_name, group_field in Settings.model_fields.items():
        group_type = group_field.annotation
        if hasattr(group_type, "model_fields"):
            for field_name in group_type.model_fields:
                paths.add(f"KINGSEC_{group_name.upper()}__{field_name.upper()}")
    return paths


def _documented_vars(text: str) -> set[str]:
    """Every KINGSEC_* token mentioned anywhere in a documentation file."""
    return set(_KINGSEC_VAR_PATTERN.findall(text))


def _undocumented_field_mismatches(documented: set[str], real_fields: set[str]) -> set[str]:
    """Documented names that are neither a real field nor a known exception."""
    return documented - real_fields - _DOCUMENTED_NON_SETTINGS_VARS


class TestDetectionLogicCatchesTheHistoricalDefectShape:
    """Proves the detection function itself works, using a synthetic
    reproduction of the exact pre-Phase-26 documentation shape - not the
    real files (which are already correct) - so this test's pass/fail does
    not depend on the current state of any documentation file.
    """

    def test_flags_a_documented_variable_that_is_not_a_real_field(self) -> None:
        real_fields = _real_settings_field_paths()
        # Reproduces the historical defect: KINGSEC_STORAGE__DATABASE_URL
        # documented as if it were a general Settings field, with nothing
        # yet recognizing it as an intentional migration-only exception.
        synthetic_doc = "KINGSEC_STORAGE__DATABASE_URL overrides DATA_DIR for PostgreSQL/external DB."
        documented = _documented_vars(synthetic_doc)

        # Without the allowlist, this is exactly what Phase 26 found by hand.
        mismatches_without_allowlist = documented - real_fields
        assert "KINGSEC_STORAGE__DATABASE_URL" in mismatches_without_allowlist

    def test_flags_a_completely_invented_variable_name(self) -> None:
        real_fields = _real_settings_field_paths()
        synthetic_doc = "Set KINGSEC_MADE_UP__NONSENSE=1 to enable the thing."
        documented = _documented_vars(synthetic_doc)
        mismatches = _undocumented_field_mismatches(documented, real_fields)
        assert mismatches == {"KINGSEC_MADE_UP__NONSENSE"}

    def test_does_not_flag_a_real_field_or_the_known_exception(self) -> None:
        real_fields = _real_settings_field_paths()
        synthetic_doc = "KINGSEC_JWT__SECRET_KEY=... and KINGSEC_STORAGE__DATABASE_URL=... are both mentioned here."
        documented = _documented_vars(synthetic_doc)
        assert _undocumented_field_mismatches(documented, real_fields) == set()


class TestDeploymentDocumentationMatchesRealSettingsFields:
    """The actual regression guard: run the same detection logic against
    the real, current deployment documentation files. This is what would
    have failed at the time Phase 26's defect was introduced, and is what
    now fails if a future edit reintroduces the same class of drift.
    """

    @pytest.mark.parametrize(
        "relative_path",
        [".env.example", "README.md", "docs/INSTALL.md"],
    )
    def test_documented_variables_are_real_fields_or_known_exceptions(self, relative_path: str) -> None:
        real_fields = _real_settings_field_paths()
        text = (_REPO_ROOT / relative_path).read_text(encoding="utf-8")
        documented = _documented_vars(text)
        mismatches = _undocumented_field_mismatches(documented, real_fields)
        assert mismatches == set(), (
            f"{relative_path} documents KINGSEC_* variable(s) that are neither a real "
            f"Settings field nor in the known migration-only exception list: {sorted(mismatches)}. "
            "If this is a new, intentional migration-only/Compose-only variable, add it to "
            "_DOCUMENTED_NON_SETTINGS_VARS in this test file. If it's a typo or a renamed "
            "field, fix the documentation instead."
        )


class TestMigrationOnlyVariablesRemainRejectedByTheRunningServer:
    """Pins the other half of the same contract: a variable documented as
    migration-only must actually still be rejected by Settings. If it were
    ever silently promoted to a real, accepted field without anyone
    updating the documentation that currently calls it migration-only,
    that is exactly "a migration-only environment variable is accidentally
    treated as a server setting" - this test turns that into a loud,
    immediate failure instead of stale documentation nobody notices.
    """

    @pytest.mark.parametrize("var_name", sorted(_DOCUMENTED_NON_SETTINGS_VARS))
    def test_documented_non_settings_var_is_still_rejected(self, monkeypatch: pytest.MonkeyPatch, var_name: str) -> None:
        monkeypatch.setenv(var_name, "a-synthetic-non-secret-test-value")
        with pytest.raises(Exception) as excinfo:
            Settings()
        # Never assert on the literal value above - only on the field name,
        # which is not secret.
        assert "extra" in str(excinfo.value).lower() or "not permitted" in str(excinfo.value).lower()

    def test_allowlist_has_no_stale_entries(self) -> None:
        # If an allowlisted name is now a genuine Settings field, the
        # allowlist itself has drifted and needs a deliberate update - this
        # keeps that visible instead of silently correct-by-accident.
        real_fields = _real_settings_field_paths()
        stale = _DOCUMENTED_NON_SETTINGS_VARS & real_fields
        assert stale == set(), f"These allowlisted names are now real Settings fields and should be removed from the allowlist: {sorted(stale)}"
