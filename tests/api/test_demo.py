"""The README demo must show what it claims: every scripted call gets its expected verdict."""

from fastapi.testclient import TestClient

from taintwall.demo import Call, run


def test_demo_verdicts_match_expectations(client: TestClient) -> None:
    calls = [step for sc in run(client) for step in sc.steps if isinstance(step, Call)]
    assert calls
    assert [c.verdict["decision"] for c in calls] == [c.expect for c in calls]
