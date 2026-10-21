"""FastAPI app factory. Handlers are sync (`def`) so blocking DB and model calls run in the threadpool."""

from __future__ import annotations

import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from functools import cache
from typing import Any, Literal

from agentdojo.functions_runtime import FunctionCall
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from taintwall.api.detector import CachedDetector, Detector, build_detector
from taintwall.api.metrics import Metrics
from taintwall.api.schemas import (
    SessionCreate,
    SessionOut,
    ToolCallCheck,
    ToolCallVerdict,
    ToolOutputCheck,
    ToolOutputVerdict,
    Trace,
    TraceEvent,
)
from taintwall.api.storage import Repository, SessionRecord
from taintwall.api.telemetry import setup_tracing, span
from taintwall.policy import TaintPolicy, load_registry

REDACT_THRESHOLD = 0.5


@dataclass
class Settings:
    database_url: str = field(
        default_factory=lambda: os.environ.get("TAINTWALL_DATABASE_URL", "sqlite:///taintwall.db")
    )
    detector: str = field(default_factory=lambda: os.environ.get("TAINTWALL_DETECTOR", "noop"))
    threshold: float = field(default_factory=lambda: float(os.environ.get("TAINTWALL_THRESHOLD", REDACT_THRESHOLD)))
    cache_size: int = field(default_factory=lambda: int(os.environ.get("TAINTWALL_CACHE_SIZE", "4096")))


@cache
def _policy(suite: str) -> TaintPolicy:
    return TaintPolicy(load_registry(suite))


def _out(s: SessionRecord) -> SessionOut:
    return SessionOut(session_id=s.id, suite=s.suite, created_at=s.created_at)


def create_app(settings: Settings | None = None, detector: Detector | None = None) -> FastAPI:
    settings = settings or Settings()
    repo = Repository(settings.database_url)
    cached = CachedDetector(detector or build_detector(settings.detector), settings.cache_size)
    metrics = Metrics()
    app = FastAPI(title="taintwall", version="0.1.0")
    setup_tracing(app)

    @app.middleware("http")
    async def _time(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        route = request.scope.get("route")
        endpoint = getattr(route, "path", "unmatched")
        metrics.requests.labels(endpoint, str(response.status_code)).observe(time.perf_counter() - start)
        return response

    def session_or_404(session_id: str) -> SessionRecord:
        found = repo.get_session(session_id)
        if found is None:
            raise HTTPException(404, f"unknown session {session_id!r}")
        return found

    @app.post("/v1/sessions", response_model=SessionOut, status_code=201)
    def create_session(body: SessionCreate) -> SessionOut:
        try:
            load_registry(body.suite)
        except FileNotFoundError:
            raise HTTPException(422, f"unknown suite {body.suite!r}") from None
        return _out(repo.create_session(body.suite, body.user_prompt))

    @app.get("/v1/sessions/{session_id}/trace", response_model=Trace)
    def trace(session_id: str) -> Trace:
        s = session_or_404(session_id)
        events = [TraceEvent(**e.__dict__) for e in repo.events(session_id)]
        return Trace(session=_out(s), user_prompt=s.user_prompt, events=events)

    @app.post("/v1/check/tool_output", response_model=ToolOutputVerdict)
    def check_tool_output(body: ToolOutputCheck) -> ToolOutputVerdict:
        session_or_404(body.session_id)
        start = time.perf_counter()
        with span("detector.score", detector=cached.name, chars=len(body.text)):
            score, hit = cached.score(body.text)
        metrics.cache.labels("hit" if hit else "miss").inc()
        flagged = score >= settings.threshold
        action: Literal["allow", "redact"] = "redact" if flagged else "allow"
        metrics.tool_outputs.labels(action).inc()
        verdict = ToolOutputVerdict(
            is_injection=flagged,
            score=score,
            action=action,
            latency_ms=(time.perf_counter() - start) * 1000,
            cached=hit,
        )
        # The text is stored even when redacted: the agent never sees it, but the policy
        # must still treat values from it as untrusted (conservative).
        repo.add_event(
            body.session_id,
            "tool_output",
            body.tool_name,
            {"text": body.text},
            verdict.model_dump(exclude={"latency_ms"}),
        )
        return verdict

    @app.post("/v1/check/tool_call", response_model=ToolCallVerdict)
    def check_tool_call(body: ToolCallCheck) -> ToolCallVerdict:
        s = session_or_404(body.session_id)
        start = time.perf_counter()
        history: list[ChatMessage] = []
        for e in repo.events(body.session_id, "tool_output"):
            call = FunctionCall(function=e.tool_name, args={})
            history.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(e.payload["text"])],
                    tool_call=call,
                    tool_call_id=None,
                    error=None,
                )
            )
        call = FunctionCall(function=body.tool_name, args=body.args)
        with span("policy.check", tool=body.tool_name):
            reason = _policy(s.suite).check(call, s.user_prompt, history)
        tainted = [reason.split("=", 1)[0]] if reason and "appears only in untrusted" in reason else []
        decision: Literal["allow", "block"] = "block" if reason else "allow"
        metrics.tool_calls.labels(decision).inc()
        verdict = ToolCallVerdict(
            decision=decision,
            reason=reason,
            tainted_args=tainted,
            latency_ms=(time.perf_counter() - start) * 1000,
        )
        repo.add_event(
            body.session_id,
            "tool_call",
            body.tool_name,
            {"args": body.args},
            verdict.model_dump(exclude={"latency_ms"}),
        )
        return verdict

    @app.get("/healthz")
    def healthz() -> Any:
        try:
            repo.ping()
        except Exception as exc:
            return JSONResponse({"status": "unhealthy", "error": type(exc).__name__}, status_code=503)
        return {"status": "ok", "detector": cached.name}

    @app.get("/metrics")
    def prometheus() -> Response:
        return Response(generate_latest(metrics.registry), media_type=CONTENT_TYPE_LATEST)

    return app


def __getattr__(name: str) -> FastAPI:
    """`uvicorn taintwall.api.app:app` builds the app lazily from the environment."""
    if name == "app":
        return create_app()
    raise AttributeError(name)
