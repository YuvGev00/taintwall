"""Frozen dev/test split over AgentDojo user tasks AND injection tasks.

Both axes are split so that nothing tuned on dev (detector thresholds, policy
rules) ever sees a test-split injection goal. Dev pairs = dev users x dev
injections; test pairs = test users x test injections. Cross pairs are unused.

The split is a pure function of (benchmark version, salt, task ids), so it can
be regenerated and checked against the committed eval/splits.json in CI.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Literal, TypedDict

from agentdojo.task_suite.load_suites import get_suites

BENCHMARK_VERSION = "v1.2.2"
DEV_FRACTION = 0.3
SALT = "taintwall-split-v1"
SPLITS_PATH = Path(__file__).resolve().parents[3] / "eval" / "splits.json"

Split = Literal["dev", "test"]


class AxisSplit(TypedDict):
    dev: list[str]
    test: list[str]


class SuiteSplit(TypedDict):
    user_tasks: AxisSplit
    injection_tasks: AxisSplit


class Splits(TypedDict):
    benchmark_version: str
    dev_fraction: float
    salt: str
    suites: dict[str, SuiteSplit]


def _natural_key(task_id: str) -> tuple[str, int]:
    match = re.search(r"(\d+)$", task_id)
    return (task_id[: match.start()], int(match.group(1))) if match else (task_id, -1)


def split_ids(ids: list[str], suite: str, axis: str, dev_fraction: float = DEV_FRACTION) -> AxisSplit:
    """Rank ids by a salted hash and take the first round(f * n) as dev (at least 1)."""

    def rank(task_id: str) -> str:
        return hashlib.sha256(f"{SALT}:{suite}:{axis}:{task_id}".encode()).hexdigest()

    ranked = sorted(ids, key=rank)
    n_dev = max(1, round(dev_fraction * len(ids)))
    return AxisSplit(
        dev=sorted(ranked[:n_dev], key=_natural_key),
        test=sorted(ranked[n_dev:], key=_natural_key),
    )


def make_splits(benchmark_version: str = BENCHMARK_VERSION) -> Splits:
    suites: dict[str, SuiteSplit] = {}
    for name, suite in sorted(get_suites(benchmark_version).items()):
        suites[name] = SuiteSplit(
            user_tasks=split_ids(list(suite.user_tasks), name, "user"),
            injection_tasks=split_ids(list(suite.injection_tasks), name, "injection"),
        )
    return Splits(
        benchmark_version=benchmark_version,
        dev_fraction=DEV_FRACTION,
        salt=SALT,
        suites=suites,
    )


def load_splits(path: Path = SPLITS_PATH) -> Splits:
    with path.open() as f:
        splits: Splits = json.load(f)
    return splits


def write_splits(path: Path = SPLITS_PATH) -> Splits:
    splits = make_splits()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(splits, indent=2) + "\n")
    return splits


if __name__ == "__main__":
    written = write_splits()
    for suite_name, s in written["suites"].items():
        u, i = s["user_tasks"], s["injection_tasks"]
        print(
            f"{suite_name:10s} users dev/test {len(u['dev'])}/{len(u['test'])}  "
            f"injections dev/test {len(i['dev'])}/{len(i['test'])}"
        )
    print(f"wrote {SPLITS_PATH}")
