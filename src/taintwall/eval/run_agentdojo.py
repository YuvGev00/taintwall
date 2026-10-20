"""Run AgentDojo on a frozen split and write raw counts (k / n) per suite.

Confidence intervals and paired tests live in eval/stats.py (written by hand,
see SPEC.md section 13). This script only produces the counts they need.

Examples:
    uv run python -m taintwall.eval.run_agentdojo --suite banking --split dev
    uv run python -m taintwall.eval.run_agentdojo summarize --split dev
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite

from taintwall.adapters.agentdojo import DEFENSES, USAGE_DIR, Defense, ModelSpec, _safe, build_pipeline, run_name
from taintwall.eval.splits import load_splits

ROOT = Path(__file__).resolve().parents[3]
RUNS_DIR = ROOT / "runs"  # raw AgentDojo traces, gitignored
RESULTS_DIR = ROOT / "results"  # small committed summaries


def _git_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True)
        return out.stdout.strip() or "uncommitted"
    except OSError:
        return "unknown"


def _result_path(spec: ModelSpec, defense: str, split: str, suite: str) -> Path:
    return RESULTS_DIR / _safe(run_name(spec, defense)) / split / f"{suite}.json"


def run_suite(
    spec: ModelSpec, suite_name: str, split: str, attack_name: str, defense: Defense = "none"
) -> dict[str, Any]:
    splits = load_splits()
    version_ = splits["benchmark_version"]
    suite = get_suite(version_, suite_name)
    s = splits["suites"][suite_name]
    user_tasks = s["user_tasks"][split]  # type: ignore[literal-required]
    injection_tasks = s["injection_tasks"][split]  # type: ignore[literal-required]

    pipeline = build_pipeline(spec, defense=defense, suite_name=suite_name)
    logdir = RUNS_DIR

    started = time.time()
    with OutputLogger(str(logdir)):
        benign = benchmark_suite_without_injections(
            pipeline, suite, logdir=logdir, force_rerun=False, user_tasks=user_tasks, benchmark_version=version_
        )
        attack = load_attack(attack_name, suite, pipeline)
        attacked = benchmark_suite_with_injections(
            pipeline,
            suite,
            attack,
            logdir=logdir,
            force_rerun=False,
            user_tasks=user_tasks,
            injection_tasks=injection_tasks,
            verbose=False,
            benchmark_version=version_,
        )
    wall_s = time.time() - started

    utility = list(attacked["utility_results"].values())
    security = list(attacked["security_results"].values())
    result: dict[str, Any] = {
        "suite": suite_name,
        "split": split,
        "model": spec.model,
        "provider": spec.provider,
        "think": spec.think,
        "effort": spec.effort if spec.provider == "anthropic" else None,
        "defense": defense,
        "attack": attack_name,
        "benchmark_version": version_,
        "agentdojo_version": version("agentdojo"),
        "git_commit": _git_commit(),
        "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "wall_seconds": round(wall_s, 1),
        "benign": {
            "n": len(benign["utility_results"]),
            "utility_k": sum(benign["utility_results"].values()),
            "per_task": {u: ok for (u, _), ok in sorted(benign["utility_results"].items())},
        },
        "under_attack": {
            "n": len(utility),
            "utility_k": sum(utility),
            "attack_success_k": sum(security),
            "per_pair": [
                {
                    "user_task": u,
                    "injection_task": i,
                    "utility": ok,
                    "attack_success": attacked["security_results"][(u, i)],
                }
                for (u, i), ok in sorted(attacked["utility_results"].items())
            ],
        },
    }
    out = _result_path(spec, defense, split, suite_name)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def token_usage(spec: ModelSpec, defense: str) -> dict[str, int]:
    """Total tokens over every call ever logged for this config (all resumed sessions, all splits)."""
    path = USAGE_DIR / f"{_safe(run_name(spec, defense))}.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    return {
        "calls": len(rows),
        "prompt_tokens": sum(r["prompt"] for r in rows),
        "completion_tokens": sum(r["completion"] for r in rows),
    }


def summarize(spec: ModelSpec, split: str, defense: str = "none") -> dict[str, Any]:
    folder = _result_path(spec, defense, split, "x").parent
    rows = [json.loads(p.read_text()) for p in sorted(folder.glob("*.json")) if p.name != "summary.json"]
    total = {
        "suites": [r["suite"] for r in rows],
        "benign_n": sum(r["benign"]["n"] for r in rows),
        "benign_utility_k": sum(r["benign"]["utility_k"] for r in rows),
        "attack_n": sum(r["under_attack"]["n"] for r in rows),
        "attack_utility_k": sum(r["under_attack"]["utility_k"] for r in rows),
        "attack_success_k": sum(r["under_attack"]["attack_success_k"] for r in rows),
        "wall_seconds": round(sum(r["wall_seconds"] for r in rows), 1),
        "tokens": token_usage(spec, defense),
    }
    (folder / "summary.json").write_text(json.dumps(total, indent=2) + "\n")
    return total


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", nargs="?", default="run", choices=["run", "summarize"])
    parser.add_argument("--suite", action="append", help="repeatable; default: all four suites")
    parser.add_argument("--split", default="dev", choices=["dev", "test"])
    parser.add_argument("--provider", default="ollama", choices=["ollama", "openai-compatible", "anthropic"])
    parser.add_argument("--defense", default="none", choices=DEFENSES)
    parser.add_argument("--effort", default="medium", choices=["low", "medium", "high", "xhigh", "max"])
    parser.add_argument("--model", default="qwen3:8b")
    parser.add_argument("--prose-name", default="Qwen", help="how attacks address the model")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--no-think", action="store_true", help="ollama: disable reasoning mode")
    args = parser.parse_args()

    spec = ModelSpec(
        provider=args.provider,
        model=args.model,
        prose_name=args.prose_name,
        think=not args.no_think,
        effort=args.effort,
    )
    if args.command == "summarize":
        print(json.dumps(summarize(spec, args.split, args.defense), indent=2))
        return
    for suite_name in args.suite or ["banking", "slack", "travel", "workspace"]:
        r = run_suite(spec, suite_name, args.split, args.attack, args.defense)
        b, a = r["benign"], r["under_attack"]
        print(
            f"{suite_name}: BU {b['utility_k']}/{b['n']}  UA {a['utility_k']}/{a['n']}  "
            f"ASR {a['attack_success_k']}/{a['n']}  ({r['wall_seconds']}s)"
        )


if __name__ == "__main__":
    main()
