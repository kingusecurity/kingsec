"""JSON Report Renderer — complete lossless serialization of a Report.

Pure formatting, no business logic, no calculations, no analysis.
Supports nested dataclasses, enums, tuples, datetime, Path, and None.
Deterministic ordering, UTF-8, pretty-printed with 4-space indentation.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from kingsec.application.report import Report


# ---------------------------------------------------------------------------
# Recursive serializer
# ---------------------------------------------------------------------------


def _serialize_value(obj: Any) -> Any:
    """Recursively serialize a Python value to a JSON-safe structure."""
    if obj is None:
        return None
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float)):
        return obj
    if isinstance(obj, str):
        return obj
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, tuple):
        return [_serialize_value(item) for item in obj]
    if isinstance(obj, (list, set, frozenset)):
        return [_serialize_value(item) for item in obj]
    if isinstance(obj, dict):
        return {_serialize_value(k): _serialize_value(v) for k, v in obj.items()}
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        fields = dataclasses.fields(obj)
        result: dict[str, Any] = {}
        for f in fields:
            val = getattr(obj, f.name)
            result[f.name] = _serialize_value(val)
        return result
    return str(obj)


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------


class JsonReportRenderer:
    """Lossless JSON renderer for the KingSec Report model."""

    def render(self, report: Report) -> str:
        """Render a Report to a pretty-printed JSON string."""
        data = _serialize_value(report)
        return json.dumps(data, indent=4, ensure_ascii=False, sort_keys=True)

    def write(self, report: Report, path: Path) -> None:
        """Render and write JSON to a file."""
        path.write_text(self.render(report), encoding="utf-8")
