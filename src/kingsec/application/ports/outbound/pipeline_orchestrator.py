from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.pipeline import PipelineExecution


class PipelineOrchestratorPort(ABC):
    @abstractmethod
    def advance(self, execution: PipelineExecution) -> PipelineExecution:
        ...

    @abstractmethod
    def cancel(self, execution: PipelineExecution) -> PipelineExecution:
        ...

    @abstractmethod
    def retry(self, execution: PipelineExecution) -> PipelineExecution:
        ...

    @abstractmethod
    def pause(self, execution: PipelineExecution) -> PipelineExecution:
        ...

    @abstractmethod
    def resume(self, execution: PipelineExecution) -> PipelineExecution:
        ...
