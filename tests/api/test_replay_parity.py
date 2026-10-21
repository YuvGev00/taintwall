"""Replay AgentDojo hijacked-agent traces through the HTTP API: decisions must equal the in-process policy's."""

from typing import Any

import pytest
from agentdojo.functions_runtime import FunctionCall
from fastapi.testclient import TestClient

from taintwall.api import create_app
from taintwall.api.app import Settings
from taintwall.eval.replay import ReplayContext, TaintwallL2, run_suite


class HttpL2:
    """The L2 replay defense, but every decision is made by the service over HTTP."""

    name = "taintwall-l2"

    def __init__(self, client: TestClient, suite: str) -> None:
        self.client, self.suite = client, suite
        self.session: str | None = None
        self.n_calls = 0

    def allow_call(self, call: FunctionCall, ctx: ReplayContext) -> str | None:
        if not ctx.messages or self.session is None:  # empty history = a new replay run
            r = self.client.post("/v1/sessions", json={"suite": self.suite, "user_prompt": ctx.user_prompt})
            self.session = r.json()["session_id"]
        body = {"session_id": self.session, "tool_name": call.function, "args": dict(call.args)}
        v = self.client.post("/v1/check/tool_call", json=body).json()
        self.n_calls += 1
        return str(v["reason"]) if v["decision"] == "block" else None

    def screen_output(self, function: str, text: str) -> str | None:
        r = self.client.post(
            "/v1/check/tool_output", json={"session_id": self.session, "tool_name": function, "text": text}
        )
        return None if r.json()["action"] == "redact" else text


@pytest.mark.parametrize("suite", ["banking", "slack"])
def test_http_decisions_match_in_process_policy(suite: str) -> None:
    expected = run_suite(suite, "dev", TaintwallL2(suite))
    with TestClient(create_app(Settings(database_url="sqlite://"))) as client:
        defense = HttpL2(client, suite)
        actual = run_suite(suite, "dev", defense)
    assert defense.n_calls > 50  # the replay really went through the API

    def decisions(r: dict[str, Any]) -> list[Any]:
        tasks = [(t["user_task"], None, t["blocked_calls"], t["utility"]) for t in r["benign"]["per_task"]]
        pairs = [
            (p["user_task"], p["injection_task"], p["blocked_calls"], p["utility"]) for p in r["hijacked"]["per_pair"]
        ]
        return tasks + pairs

    assert decisions(actual) == decisions(expected)
    assert actual["hijacked"]["attack_success_k"] == expected["hijacked"]["attack_success_k"]
