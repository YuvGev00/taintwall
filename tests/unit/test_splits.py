from agentdojo.task_suite.load_suites import get_suites

from taintwall.eval.splits import DEV_FRACTION, load_splits, make_splits, split_ids


def test_committed_split_is_frozen() -> None:
    """eval/splits.json must equal a fresh regeneration. If this fails, someone
    changed the salt, fraction or benchmark version: that invalidates every
    dev/test number already reported."""
    assert load_splits() == make_splits()


def test_axes_are_disjoint_and_complete() -> None:
    splits = load_splits()
    suites = get_suites(splits["benchmark_version"])
    for name, s in splits["suites"].items():
        for axis, all_ids in (
            ("user_tasks", suites[name].user_tasks),
            ("injection_tasks", suites[name].injection_tasks),
        ):
            dev, test = set(s[axis]["dev"]), set(s[axis]["test"])  # type: ignore[literal-required]
            assert not dev & test, f"{name}/{axis} overlaps"
            assert dev | test == set(all_ids), f"{name}/{axis} misses ids"


def test_split_ids_is_deterministic_and_sized() -> None:
    ids = [f"user_task_{i}" for i in range(20)]
    a = split_ids(ids, "suite", "user")
    assert a == split_ids(list(reversed(ids)), "suite", "user")  # input order irrelevant
    assert len(a["dev"]) == round(DEV_FRACTION * 20)
    assert split_ids(["only"], "s", "user")["dev"] == ["only"]  # never an empty dev set
