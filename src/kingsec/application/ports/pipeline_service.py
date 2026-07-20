from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.pipeline import PipelineExecution


class PipelineServicePort(ABC):
    @abstractmethod
    def start_pipeline(self, target: str, owner_user_id: str = "",
                       scanner_ids: list[str] | None = None,
                       priority: str = "normal") -> PipelineExecution:
        ...

    @abstractmethod
    def get_pipeline(self, pipeline_id: str) -> PipelineExecution:
        ...

    @abstractmethod
    def list_pipelines(self) -> list[PipelineExecution]:
        ...

    @abstractmethod
    def cancel_pipeline(self, pipeline_id: str) -> PipelineExecution:
        ...

    @abstractmethod
    def retry_pipeline(self, pipeline_id: str) -> PipelineExecution:
        ...

    @abstractmethod
    def resume_pipeline(self, pipeline_id: str) -> PipelineExecution:
        ...

    @abstractmethod
    def pause_pipeline(self, pipeline_id: str) -> PipelineExecution:
        ...
