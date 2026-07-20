from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.pipeline import PipelineExecution


class PipelineRepositoryPort(ABC):
    @abstractmethod
    def save(self, execution: PipelineExecution) -> None:
        ...

    @abstractmethod
    def find_by_id(self, pipeline_id: str) -> PipelineExecution | None:
        ...

    @abstractmethod
    def find_all(self) -> list[PipelineExecution]:
        ...

    @abstractmethod
    def find_by_state(self, state: str) -> list[PipelineExecution]:
        ...

    @abstractmethod
    def delete(self, pipeline_id: str) -> None:
        ...
