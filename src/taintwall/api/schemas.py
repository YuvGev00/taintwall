"""Request and response models (Pydantic v2)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class SessionCreate(BaseModel):
    suite: str = Field(description="Tool-registry name, i.e. a file in policies/ (banking, slack, ...).")
    user_prompt: str = Field(description="The user's request; the only text that is trusted a priori.")


class SessionOut(BaseModel):
    session_id: str
    suite: str
    created_at: float


class ToolOutputCheck(BaseModel):
    session_id: str
    tool_name: str
    text: str


class ToolOutputVerdict(BaseModel):
    is_injection: bool
    score: float
    action: Literal["allow", "redact"]
    latency_ms: float
    cached: bool = False


class ToolCallCheck(BaseModel):
    session_id: str
    tool_name: str
    args: dict[str, Any] = Field(default_factory=dict)


class ToolCallVerdict(BaseModel):
    decision: Literal["allow", "block"]
    reason: str | None = None
    tainted_args: list[str] = Field(default_factory=list)
    latency_ms: float


class TraceEvent(BaseModel):
    seq: int
    ts: float
    kind: Literal["tool_output", "tool_call"]
    tool_name: str
    payload: dict[str, Any]
    decision: dict[str, Any]


class Trace(BaseModel):
    session: SessionOut
    user_prompt: str
    events: list[TraceEvent]
