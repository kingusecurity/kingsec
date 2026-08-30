"""Dedicated unit tests for check_pipeline_access (KSEC-71-01 fix).

Phase 72 / mirrors test_support_check_schedule_access.py's structure:
proves the ownership-check helper in isolation, independent of any use
case that calls it.
"""

from __future__ import annotations

import pytest

from kingsec.application._support import check_pipeline_access
from kingsec.application.errors import PipelineNotFoundError
from kingsec.domain.pipeline import PipelineExecution, PipelineId, PipelineState


def _make_execution(owner_user_id: str) -> PipelineExecution:
    return PipelineExecution(
        pipeline_id=PipelineId(value="pl-1"),
        target="10.0.0.1",
        state=PipelineState.QUEUED,
        owner_user_id=owner_user_id,
    )


class TestCheckPipelineAccess:
    def test_admin_is_allowed_regardless_of_ownership(self) -> None:
        execution = _make_execution(owner_user_id="alice")
        check_pipeline_access(execution, requesting_user="admin1", is_admin=True)

    def test_owner_is_allowed(self) -> None:
        execution = _make_execution(owner_user_id="alice")
        check_pipeline_access(execution, requesting_user="alice", is_admin=False)

    def test_non_owner_non_admin_raises_not_found(self) -> None:
        execution = _make_execution(owner_user_id="alice")
        with pytest.raises(PipelineNotFoundError):
            check_pipeline_access(execution, requesting_user="mallory", is_admin=False)

    def test_missing_owner_fails_closed_for_non_admin(self) -> None:
        """A pipeline with no recorded owner is Admin-only, not open to everyone."""
        execution = _make_execution(owner_user_id="")
        with pytest.raises(PipelineNotFoundError):
            check_pipeline_access(execution, requesting_user="anyone", is_admin=False)

    def test_missing_owner_still_allowed_for_admin(self) -> None:
        execution = _make_execution(owner_user_id="")
        check_pipeline_access(execution, requesting_user="admin1", is_admin=True)

    def test_empty_requesting_user_never_matches_a_real_owner(self) -> None:
        execution = _make_execution(owner_user_id="alice")
        with pytest.raises(PipelineNotFoundError):
            check_pipeline_access(execution, requesting_user="", is_admin=False)
