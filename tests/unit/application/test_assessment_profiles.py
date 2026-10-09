"""Purpose-built profile contracts for non-network assessment targets."""

from __future__ import annotations

import pytest

from kingsec.application.assessment_profiles import ExecutionPlanner
from kingsec.domain import TargetType


@pytest.mark.parametrize(
    ("profile_id", "target_type", "scanners"),
    [
        ("code-review", TargetType.SOURCE_PATH, ("semgrep", "trivy")),
        ("container-scan", TargetType.CONTAINER_IMAGE, ("trivy",)),
        ("domain-enumeration", TargetType.DOMAIN, ("amass",)),
    ],
)
def test_purpose_built_profile_has_one_exact_target_type_and_requires_every_scanner(
    profile_id: str,
    target_type: TargetType,
    scanners: tuple[str, ...],
) -> None:
    planner = ExecutionPlanner()

    profile = planner.get_profile(profile_id)

    assert profile is not None
    assert profile.supported_target_types == (target_type,)
    assert profile.scanners == scanners
    assert profile.required_scanners == scanners
    assert planner.get_profiles_for_target_type(target_type) == (profile,)
    assert planner.profile_to_dict(profile)["supported_target_types"] == [target_type.value]


def test_network_profiles_do_not_absorb_local_resource_or_domain_scanners() -> None:
    planner = ExecutionPlanner()

    footprint = planner.get_profile("external-footprint")
    full = planner.get_profile("full-assessment")

    assert footprint is not None
    assert footprint.supported_target_types == (TargetType.HOSTNAME, TargetType.IP_ADDRESS)
    assert footprint.scanners == ("nmap",)

    assert full is not None
    assert not {
        TargetType.DOMAIN,
        TargetType.SOURCE_PATH,
        TargetType.CONTAINER_IMAGE,
    }.intersection(full.supported_target_types)
    assert not {"amass", "semgrep", "trivy"}.intersection(full.scanners)
