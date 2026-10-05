"""API request/response schemas (Pydantic)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str
    categories: list[str] | None = None
    test_ids: list[str] | None = None
    dry_run: bool = False
    workers: int | None = Field(default=None, ge=1, le=32)


class MessageOut(BaseModel):
    message: str


class RetestOut(BaseModel):
    finding_id: str
    previous_status: str
    new_status: str
    result_status: str
    retest_number: int
    explanation: str
