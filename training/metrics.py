"""Detector metrics in plain Python, shared by the Modal job and the tests (no numpy/sklearn needed).

The operating point is chosen on dev only: the lowest threshold whose FPR on dev
negatives is at most the target (DECISIONS.md, 2026-10-20). Test and OOD sets are
then scored at that frozen threshold.
"""

from __future__ import annotations

import math
from collections.abc import Sequence


def auroc(scores: Sequence[float], labels: Sequence[int]) -> float:
    """Area under the ROC curve via the Mann-Whitney U statistic (ties count half)."""
    pairs = sorted(zip(scores, labels, strict=True))
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return math.nan
    rank_sum = 0.0
    i = 0
    while i < len(pairs):
        j = i
        while j < len(pairs) and pairs[j][0] == pairs[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2  # 1-based ranks i+1..j share their mean
        rank_sum += avg_rank * sum(label for _, label in pairs[i:j])
        i = j
    return (rank_sum - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def threshold_at_fpr(scores: Sequence[float], labels: Sequence[int], target_fpr: float) -> float:
    """Lowest threshold t such that the share of negatives with score >= t is at most target_fpr.

    A flag is `score >= t`. Allowing k = floor(target_fpr * n_neg) false positives, t sits
    just above the (k+1)-th highest negative score.
    """
    neg = sorted((s for s, y in zip(scores, labels, strict=True) if y == 0), reverse=True)
    if not neg:
        raise ValueError("need at least one negative to set a threshold")
    k = math.floor(target_fpr * len(neg))
    return math.nextafter(neg[k], math.inf)


def rates(scores: Sequence[float], labels: Sequence[int], threshold: float) -> dict[str, float]:
    tp = sum(1 for s, y in zip(scores, labels, strict=True) if s >= threshold and y == 1)
    fp = sum(1 for s, y in zip(scores, labels, strict=True) if s >= threshold and y == 0)
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    return {
        "threshold": threshold,
        "tpr": tp / n_pos if n_pos else math.nan,
        "fpr": fp / n_neg if n_neg else math.nan,
        "auroc": auroc(scores, labels),
        "n_pos": n_pos,
        "n_neg": n_neg,
    }
