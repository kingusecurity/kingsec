from __future__ import annotations

import json

from kingsec.application.ports.outbound import PipelineRepositoryPort
from kingsec.domain.pipeline import (
    PipelineExecution,
    PipelineId,
    PipelineResult,
    PipelineStage,
    PipelineState,
)


class InMemoryPipelineRepository(PipelineRepositoryPort):
    def __init__(self) -> None:
        self._executions: dict[str, PipelineExecution] = {}

    def save(self, execution: PipelineExecution) -> None:
        self._executions[execution.pipeline_id.value] = execution

    def find_by_id(self, pipeline_id: str) -> PipelineExecution | None:
        return self._executions.get(pipeline_id)

    def find_all(self) -> list[PipelineExecution]:
        return list(self._executions.values())

    def find_by_state(self, state: str) -> list[PipelineExecution]:
        return [e for e in self._executions.values() if e.state.value == state]

    def delete(self, pipeline_id: str) -> None:
        self._executions.pop(pipeline_id, None)


class SQLAlchemyPipelineRepository(PipelineRepositoryPort):
    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    def save(self, execution: PipelineExecution) -> None:
        from sqlalchemy import text
        with self._session_factory() as session:
            existing = session.execute(
                text("SELECT pipeline_id FROM scan_pipeline WHERE pipeline_id = :pid"),
                {"pid": execution.pipeline_id.value},
            ).fetchone()
            if existing:
                session.execute(
                    text("""
                        UPDATE scan_pipeline SET state=:state, stages_json=:stages,
                            result_json=:result, updated_at=:updated_at
                        WHERE pipeline_id=:pipeline_id
                    """),
                    {
                        "pipeline_id": execution.pipeline_id.value,
                        "state": execution.state.value,
                        "stages": json.dumps([s.__dict__ for s in execution.stages], default=str),
                        "result": json.dumps(execution.result.__dict__, default=str),
                        "updated_at": execution.updated_at,
                    },
                )
            else:
                session.execute(
                    text("""
                        INSERT INTO scan_pipeline
                            (pipeline_id, target, state, stages_json, result_json,
                             owner_user_id, scanner_ids, priority, created_at, updated_at)
                        VALUES
                            (:pipeline_id, :target, :state, :stages, :result,
                             :owner_user_id, :scanner_ids, :priority, :created_at, :updated_at)
                    """),
                    {
                        "pipeline_id": execution.pipeline_id.value,
                        "target": execution.target,
                        "state": execution.state.value,
                        "stages": json.dumps([s.__dict__ for s in execution.stages], default=str),
                        "result": json.dumps(execution.result.__dict__, default=str),
                        "owner_user_id": execution.owner_user_id,
                        "scanner_ids": ",".join(execution.scanner_ids),
                        "priority": execution.priority,
                        "created_at": execution.created_at,
                        "updated_at": execution.updated_at,
                    },
                )
            session.commit()

    def find_by_id(self, pipeline_id: str) -> PipelineExecution | None:
        from sqlalchemy import text
        with self._session_factory() as session:
            row = session.execute(
                text("SELECT * FROM scan_pipeline WHERE pipeline_id = :pid"),
                {"pid": pipeline_id},
            ).fetchone()
            if not row:
                return None
            return self._row_to_execution(row._mapping)

    def find_all(self) -> list[PipelineExecution]:
        from sqlalchemy import text
        with self._session_factory() as session:
            rows = session.execute(text("SELECT * FROM scan_pipeline ORDER BY created_at DESC")).fetchall()
            return [self._row_to_execution(r._mapping) for r in rows]

    def find_by_state(self, state: str) -> list[PipelineExecution]:
        from sqlalchemy import text
        with self._session_factory() as session:
            rows = session.execute(
                text("SELECT * FROM scan_pipeline WHERE state = :state ORDER BY created_at DESC"),
                {"state": state},
            ).fetchall()
            return [self._row_to_execution(r._mapping) for r in rows]

    def delete(self, pipeline_id: str) -> None:
        from sqlalchemy import text
        with self._session_factory() as session:
            session.execute(
                text("DELETE FROM scan_pipeline WHERE pipeline_id = :pid"),
                {"pid": pipeline_id},
            )
            session.commit()

    def _row_to_execution(self, row) -> PipelineExecution:
        import json
        stages_raw = row.get("stages_json", "[]")
        result_raw = row.get("result_json", "{}")
        try:
            stages_list = json.loads(stages_raw) if isinstance(stages_raw, str) else []
        except (json.JSONDecodeError, TypeError):
            stages_list = []
        try:
            result_dict = json.loads(result_raw) if isinstance(result_raw, str) else {}
        except (json.JSONDecodeError, TypeError):
            result_dict = {}
        return PipelineExecution(
            pipeline_id=PipelineId(value=row.get("pipeline_id", "")),
            target=row.get("target", ""),
            state=PipelineState(row.get("state", "queued")),
            stages=tuple(PipelineStage(**s) for s in stages_list if isinstance(s, dict)),
            result=PipelineResult(**result_dict) if result_dict else PipelineResult(),
            owner_user_id=row.get("owner_user_id", ""),
            scanner_ids=tuple(row.get("scanner_ids", "").split(",")) if row.get("scanner_ids") else (),
            priority=row.get("priority", "normal"),
            created_at=row.get("created_at", ""),
            updated_at=row.get("updated_at", ""),
        )
