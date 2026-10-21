"""Statistics for the results tables (SPEC section 6), stdlib only.

- percentile bootstrap CIs on proportions (resample episodes);
- paired bootstrap of the difference between two defenses on the same pairs;
- exact two-sided McNemar test (binomial on the discordant pairs).
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from math import comb

N_BOOT = 10_000
SEED = 20261021


def _percentile(sorted_vals: Sequence[float], q: float) -> float:
    """Linear-interpolated percentile of an already sorted sequence, q in [0, 1]."""
    pos = q * (len(sorted_vals) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return float(sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo))


def _bootstrap_means(values: Sequence[float], n_boot: int, rng: random.Random) -> list[float]:
    n = len(values)
    if n == 0:
        raise ValueError("cannot bootstrap an empty sample")
    return sorted(sum(values[rng.randrange(n)] for _ in range(n)) / n for _ in range(n_boot))


def bootstrap_ci(
    outcomes: Sequence[bool | int], n_boot: int = N_BOOT, alpha: float = 0.05, seed: int = SEED
) -> tuple[float, float, float]:
    """(point estimate, lo, hi): percentile bootstrap CI for a proportion of 0/1 outcomes."""
    vals = [float(o) for o in outcomes]
    means = _bootstrap_means(vals, n_boot, random.Random(seed))
    return sum(vals) / len(vals), _percentile(means, alpha / 2), _percentile(means, 1 - alpha / 2)


def paired_bootstrap_diff(
    a: Sequence[bool | int],
    b: Sequence[bool | int],
    n_boot: int = N_BOOT,
    alpha: float = 0.05,
    seed: int = SEED,
) -> tuple[float, float, float]:
    """(mean(a) - mean(b), lo, hi): resamples the pairs, so shared difficulty cancels."""
    if len(a) != len(b):
        raise ValueError("paired samples must have equal length")
    diffs = [float(x) - float(y) for x, y in zip(a, b, strict=True)]
    means = _bootstrap_means(diffs, n_boot, random.Random(seed))
    return sum(diffs) / len(diffs), _percentile(means, alpha / 2), _percentile(means, 1 - alpha / 2)


def mcnemar_exact(a: Sequence[bool | int], b: Sequence[bool | int]) -> float:
    """Exact two-sided McNemar p-value: Binomial(b + c, 1/2) on the discordant pairs."""
    if len(a) != len(b):
        raise ValueError("paired samples must have equal length")
    only_a = sum(1 for x, y in zip(a, b, strict=True) if x and not y)
    only_b = sum(1 for x, y in zip(a, b, strict=True) if y and not x)
    n = only_a + only_b
    if n == 0:
        return 1.0
    tail = sum(comb(n, i) for i in range(min(only_a, only_b) + 1)) / 2**n
    return min(1.0, 2 * tail)
