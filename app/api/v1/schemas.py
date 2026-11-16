"""Request/response contracts for the public API."""

from __future__ import annotations

import datetime as dt
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.config import get_settings


class AnalyzeRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=2,
        description="Security log, alert, IOC list or question.",
        examples=["sshd[2211]: Failed password for root from 185.220.101.4 port 52144 ssh2"],
    )
    session_id: str = Field(default="default", max_length=64, pattern=r"^[A-Za-z0-9_\-:.]+$")

    @field_validator("message")
    @classmethod
    def _bounded(cls, v: str) -> str:
        limit = get_settings().max_input_chars
        if len(v) > limit:
            raise ValueError(f"message exceeds {limit} characters")
        return v


class TraceStep(BaseModel):
    node: str
    label: str
    status: str
    detail: str = ""
    ms: float = 0.0


class AnalyzeResponse(BaseModel):
    incident_id: int
    route: str
    blocked: bool
    engine: str
    latency_ms: int
    guard: dict
    report: dict
    output_guard: dict = {}
    trace: list[TraceStep]


class IncidentSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: dt.datetime
    title: str
    route: str
    blocked: bool
    severity: str
    risk_score: int
    engine: str
    latency_ms: int


class IncidentDetail(IncidentSummary):
    payload: str
    payload_sha256: str
    guard_score: float
    report: dict
    trace: list
    decisions: dict


class DecisionRequest(BaseModel):
    action_index: int = Field(ge=0, le=50)
    decision: Literal["approved", "rejected"]
