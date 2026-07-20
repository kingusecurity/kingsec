from __future__ import annotations

from kingsec.domain.pipeline import (
    PipelineExecution,
    PipelineId,
    PipelineStage,
    PipelineState,
)
from kingsec.infrastructure.pipeline.repository import InMemoryPipelineRepository


class TestInMemoryPipelineRepository:
    def test_save_and_find_by_id(self) -> None:
        repo = InMemoryPipelineRepository()
        stages = (PipelineStage(name="queued", status="completed"),)
        exec_ = PipelineExecution(
            pipeline_id=PipelineId(value="pl-1"),
            target="10.0.0.1",
            state=PipelineState.QUEUED,
            stages=stages,
        )
        repo.save(exec_)
        found = repo.find_by_id("pl-1")
        assert found is not None
        assert found.pipeline_id.value == "pl-1"
        assert found.target == "10.0.0.1"

    def test_find_by_id_missing(self) -> None:
        repo = InMemoryPipelineRepository()
        assert repo.find_by_id("pl-missing") is None

    def test_find_all(self) -> None:
        repo = InMemoryPipelineRepository()
        repo.save(PipelineExecution(
            pipeline_id=PipelineId(value="pl-1"), target="a", state=PipelineState.QUEUED,
        ))
        repo.save(PipelineExecution(
            pipeline_id=PipelineId(value="pl-2"), target="b", state=PipelineState.RUNNING,
        ))
        assert len(repo.find_all()) == 2

    def test_find_by_state(self) -> None:
        repo = InMemoryPipelineRepository()
        repo.save(PipelineExecution(
            pipeline_id=PipelineId(value="pl-1"), target="a", state=PipelineState.QUEUED,
        ))
        repo.save(PipelineExecution(
            pipeline_id=PipelineId(value="pl-2"), target="b", state=PipelineState.RUNNING,
        ))
        results = repo.find_by_state("queued")
        assert len(results) == 1
        assert results[0].pipeline_id.value == "pl-1"

    def test_delete(self) -> None:
        repo = InMemoryPipelineRepository()
        repo.save(PipelineExecution(
            pipeline_id=PipelineId(value="pl-1"), target="a", state=PipelineState.QUEUED,
        ))
        repo.delete("pl-1")
        assert repo.find_by_id("pl-1") is None

    def test_save_overwrites(self) -> None:
        repo = InMemoryPipelineRepository()
        repo.save(PipelineExecution(
            pipeline_id=PipelineId(value="pl-1"), target="a", state=PipelineState.QUEUED,
        ))
        repo.save(PipelineExecution(
            pipeline_id=PipelineId(value="pl-1"), target="b", state=PipelineState.RUNNING,
        ))
        found = repo.find_by_id("pl-1")
        assert found is not None
        assert found.target == "b"
        assert found.state == PipelineState.RUNNING
