"""Build the README results tables (test split) from results/*.json.

Every proportion gets a 95% percentile-bootstrap CI; every defense is compared to
"no defense" on the same pairs with a paired bootstrap difference and an exact
McNemar p-value (see eval/stats.py). Prints markdown to stdout.

    uv run python -m taintwall.eval.make_report > /tmp/tables.md
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from taintwall.eval.replay import empty_ground_truth_injections
from taintwall.eval.splits import load_splits
from taintwall.eval.stats import bootstrap_ci, mcnemar_exact, paired_bootstrap_diff

RESULTS = Path(__file__).resolve().parents[3] / "results"
SUITES = ("banking", "slack", "travel", "workspace")
R1_DEFENSES = (
    ("none", "none"),
    ("taintwall-l2", "taintwall L2"),
    ("protectai", "ProtectAI"),
    ("protectai+l2", "ProtectAI + L2"),
    ("taintwall-l1", "taintwall L1"),
    ("taintwall-l1+l2", "taintwall L1 + L2"),
)
LIVE_ROWS = (
    (
        "R2",
        "gemini-3.1-flash-lite",
        (
            ("none", "none"),
            ("spotlighting", "spotlighting"),
            ("protectai", "ProtectAI"),
            ("taintwall-l2", "taintwall L2"),
        ),
    ),
    # R3 moved from gemini-3.5-flash (dev) to Claude Haiku 5.5 before the test run, for cost (DECISIONS.md).
    ("R3", "claude-haiku-5-5-medium", (("none", "none"), ("taintwall-l2", "taintwall L2"))),
)

Outcomes = dict[tuple[str, ...], bool]


def _load(folder: Path) -> list[dict[str, Any]]:
    return [json.loads((folder / f"{s}.json").read_text()) for s in SUITES if (folder / f"{s}.json").exists()]


def _r1(defense: str) -> tuple[Outcomes, Outcomes] | None:
    """(benign utility, attack success) keyed by task / pair; injectable pairs only."""
    rows = _load(RESULTS / "r1" / defense / "test")
    if len(rows) != len(SUITES):
        return None
    bu: Outcomes = {}
    asr: Outcomes = {}
    for r in rows:
        for t in r["benign"]["per_task"]:
            bu[(r["suite"], t["user_task"])] = t["utility"]
        for p in r["hijacked"]["per_pair"]:
            if p["injectable"]:
                asr[(r["suite"], p["user_task"], p["injection_task"])] = p["attack_success"]
    return bu, asr


def _live(model: str, defense: str) -> tuple[Outcomes, Outcomes, Outcomes] | None:
    rows = _load(RESULTS / f"{model}-{defense}" / "test")
    if len(rows) != len(SUITES):
        return None
    bu: Outcomes = {}
    ua: Outcomes = {}
    asr: Outcomes = {}
    for r in rows:
        for u, ok in r["benign"]["per_task"].items():
            bu[(r["suite"], u)] = ok
        for p in r["under_attack"]["per_pair"]:
            key = (r["suite"], p["user_task"], p["injection_task"])
            ua[key] = p["utility"]
            asr[key] = p["attack_success"]
    return bu, ua, asr


def _cell(o: Outcomes) -> str:
    vals = list(o.values())
    p, lo, hi = bootstrap_ci(vals)
    return f"{sum(vals)}/{len(vals)} ({p:.1%}, CI {lo:.1%} to {hi:.1%})"


def _side_effecting(o: Outcomes) -> Outcomes:
    """Drop text-only injection tasks (empty ground truth): no tool call for a call-level firewall to stop."""
    version = load_splits()["benchmark_version"]
    text_only = {(s, i) for s in SUITES for i in empty_ground_truth_injections(s, version)}
    return {k: v for k, v in o.items() if (k[0], k[2]) not in text_only}


def _vs_none(o: Outcomes, base: Outcomes, label: str) -> str:
    """Paired difference vs no defense on the shared keys, as 'diff [CI], p'."""
    if label == "none":
        return "—"
    keys = sorted(set(o) & set(base))
    a = [o[k] for k in keys]
    b = [base[k] for k in keys]
    d, lo, hi = paired_bootstrap_diff(a, b)
    p = mcnemar_exact(a, b)
    ptxt = "p<0.001" if p < 0.001 else f"p={p:.3f}"
    return f"{d * 100:+.1f} pts [{lo * 100:+.1f}, {hi * 100:+.1f}], {ptxt}"


def r1_table() -> str:
    data = {d: _r1(d) for d, _ in R1_DEFENSES}
    base = data["none"]
    if base is None:
        return "_R1 test results not found._\n"
    lines = [
        "| Defense | Benign utility | Attack success (injectable pairs) | ASR vs none (paired) |",
        "|---|---|---|---|",
    ]
    for d, name in R1_DEFENSES:
        cur = data[d]
        if cur is None:
            continue
        lines.append(f"| {name} | {_cell(cur[0])} | {_cell(cur[1])} | {_vs_none(cur[1], base[1], d)} |")
    return "\n".join(lines) + "\n"


def live_table() -> str:
    lines = [
        "| Regime | Model | Defense | Benign utility | Utility under attack | Attack success "
        "| Attack success, side-effecting attacks | ASR vs none (paired) | BU vs none (paired) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for regime, model, defenses in LIVE_ROWS:
        base = _live(model, "none")
        for d, name in defenses:
            cur = _live(model, d)
            if cur is None or base is None:
                continue
            lines.append(
                f"| {regime} | `{model}` | {name} | {_cell(cur[0])} | {_cell(cur[1])} | {_cell(cur[2])} | "
                f"{_cell(_side_effecting(cur[2]))} | "
                f"{_vs_none(cur[2], base[2], d)} | {_vs_none(cur[0], base[0], d)} |"
            )
    if len(lines) == 2:
        return "_Live test results not found._\n"
    return "\n".join(lines) + "\n"


def main() -> None:
    print("### R1: hijacked-agent replay (test)\n")
    print(r1_table())
    print("### R2 / R3: live agents (test)\n")
    print(live_table())
    print(
        "95% percentile-bootstrap CIs (10,000 resamples of episodes). Paired columns: difference to no defense "
        "(defense minus none) on the same pairs or tasks, paired-bootstrap CI, exact McNemar p-value. "
        "Side-effecting attacks exclude the 9 injection tasks with an empty ground truth (text-only goals such as "
        "'say that I should visit X'), which a tool-call firewall cannot block by design; R1 excludes them too.\n"
    )


if __name__ == "__main__":
    main()
