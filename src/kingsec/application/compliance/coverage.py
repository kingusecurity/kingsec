from __future__ import annotations

from collections.abc import Sequence

from kingsec.domain.compliance import (
    ComplianceFramework,
    FindingControlMapping,
    FrameworkControl,
    FrameworkCoverage,
)

from .framework_definitions import FRAMEWORK_DEFINITIONS


class ComplianceCoverageCalculator:
    """Calculates compliance coverage percentages per framework."""

    def calculate(
        self,
        mappings: Sequence[FindingControlMapping],
        enabled_frameworks: list[ComplianceFramework] | None = None,
    ) -> list[FrameworkCoverage]:
        frameworks = enabled_frameworks or list(ComplianceFramework)
        coverages: list[FrameworkCoverage] = []

        for framework in frameworks:
            total_controls = len(FRAMEWORK_DEFINITIONS.get(framework, ()))
            if total_controls == 0:
                continue

            mapped_control_ids: set[str] = set()
            for fcm in mappings:
                for ctrl in fcm.controls:
                    if ctrl.framework == framework:
                        mapped_control_ids.add(ctrl.control_id.value)

            passed = len(mapped_control_ids)
            failed = 0
            not_assessed = total_controls - passed

            coverages.append(
                FrameworkCoverage(
                    framework=framework,
                    total_controls=total_controls,
                    passed=passed,
                    failed=failed,
                    not_assessed=not_assessed,
                )
            )

        return coverages

    def get_unmapped_controls(
        self,
        framework: ComplianceFramework,
        mappings: Sequence[FindingControlMapping],
    ) -> list[FrameworkControl]:
        mapped_ids: set[str] = set()
        for fcm in mappings:
            for ctrl in fcm.controls:
                if ctrl.framework == framework:
                    mapped_ids.add(ctrl.control_id.value)

        all_controls = FRAMEWORK_DEFINITIONS.get(framework, ())
        return [c for c in all_controls if c.control_id.value not in mapped_ids]
