"""Standard API response models.

Every error response follows this schema — deterministic, consistent,
and information-safe.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ApiError(BaseModel):
    """Standard error response body for every KingSec API endpoint."""

    timestamp: datetime = Field(description="When the error occurred (UTC)")
    request_id: str = Field(description="Unique request identifier (UUID4)")
    status: int = Field(description="HTTP status code")
    error: str = Field(description="Short, stable error-type name")
    message: str = Field(description="User-safe error description")
    path: str = Field(description="The request URL path")
    details: dict | None = Field(default=None, description="Optional structured context")
