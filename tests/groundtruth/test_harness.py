"""Zero-cost harness checks: replay AgentDojo's ground-truth tool calls (no LLM).

Week 1: proves the benchmark wiring works on our split. Week 5 adds the policy
guard here: benign ground truths must be allowed, injection ground truths blocked.
"""

import pytest
from agentdojo.agent_pipeline import GroundTruthPipeline
from agentdojo.task_suite.load_suites import get_suite

from taintwall.eval.splits import load_splits

SPLITS = load_splits()
SUITES = sorted(SPLITS["suites"])

# In agentdojo 0.1.35 these v1.2 injection tasks ship with `ground_truth() -> []`,
# so replaying the ground truth can't achieve them (their `security()` checks are
# real, so live ASR is still valid). Pinned so an upstream change shows up here.
# See DECISIONS.md.
KNOWN_UPSTREAM_GT_FAILURES = {("workspace", f"injection_task_{i}") for i in range(6, 14)}


@pytest.mark.parametrize("suite_name", SUITES)
def test_ground_truth_solves_dev_user_tasks(suite_name: str) -> None:
    suite = get_suite(SPLITS["benchmark_version"], suite_name)
    env = suite.load_and_inject_default_environment({})
    for task_id in SPLITS["suites"][suite_name]["user_tasks"]["dev"]:
        task = suite.user_tasks[task_id]
        utility, _ = suite.run_task_with_pipeline(
            GroundTruthPipeline(task), task, injection_task=None, injections={}, environment=env.model_copy(deep=True)
        )
        assert utility, f"{suite_name}/{task_id}: ground truth no longer solves the task"


@pytest.mark.parametrize("suite_name", SUITES)
def test_ground_truth_achieves_dev_injection_goals(suite_name: str) -> None:
    suite = get_suite(SPLITS["benchmark_version"], suite_name)
    env = suite.load_and_inject_default_environment({})
    any_user_task = next(iter(suite.user_tasks.values()))
    failing = set()
    for inj_id in SPLITS["suites"][suite_name]["injection_tasks"]["dev"]:
        inj = suite.injection_tasks[inj_id]
        _, security = suite.run_task_with_pipeline(
            GroundTruthPipeline(inj),
            any_user_task,
            injection_task=inj,
            injections={},
            environment=env.model_copy(deep=True),
        )
        if not security:
            failing.add((suite_name, inj_id))
    expected = {k for k in KNOWN_UPSTREAM_GT_FAILURES if k[0] == suite_name and k[1] in suite.injection_tasks}
    dev_ids = set(SPLITS["suites"][suite_name]["injection_tasks"]["dev"])
    assert failing == {k for k in expected if k[1] in dev_ids}
