import pytest

from taintwall.eval.stats import bootstrap_ci, mcnemar_exact, paired_bootstrap_diff


def test_mcnemar_known_values() -> None:
    # 10 vs 0 discordant: p = 2 * 0.5**10
    a = [True] * 10 + [True] * 5
    b = [False] * 10 + [True] * 5
    assert mcnemar_exact(a, b) == pytest.approx(2 / 1024)
    # 5 vs 3 discordant: p = 2 * P(X<=3 | n=8) = 2 * 93/256
    a = [True] * 5 + [False] * 3
    b = [False] * 5 + [True] * 3
    assert mcnemar_exact(a, b) == pytest.approx(2 * 93 / 256)
    # 1 vs 6: p = 2 * (1 + 7) / 128
    a = [True] + [False] * 6
    b = [False] + [True] * 6
    assert mcnemar_exact(a, b) == pytest.approx(16 / 128)


def test_mcnemar_no_discordant_is_one() -> None:
    assert mcnemar_exact([True, False], [True, False]) == 1.0


def test_bootstrap_ci_degenerate_and_bracket() -> None:
    p, lo, hi = bootstrap_ci([False] * 50)
    assert (p, lo, hi) == (0.0, 0.0, 0.0)
    p, lo, hi = bootstrap_ci([True] * 30 + [False] * 70)
    assert p == pytest.approx(0.3)
    # analytic normal-approx 95% half-width = 1.96 * sqrt(.3*.7/100) ~ 0.09
    assert lo == pytest.approx(0.21, abs=0.02)
    assert hi == pytest.approx(0.39, abs=0.02)


def test_bootstrap_is_seeded() -> None:
    x = [True, False, True, True, False] * 5
    assert bootstrap_ci(x) == bootstrap_ci(x)


def test_paired_diff_excludes_zero_when_clear() -> None:
    a = [True] * 40 + [False] * 60
    b = [False] * 40 + [False] * 60
    d, lo, hi = paired_bootstrap_diff(a, b)
    assert d == pytest.approx(0.4)
    assert lo > 0.28
    assert hi < 0.52


def test_paired_diff_identical_is_zero() -> None:
    a = [True, False] * 20
    assert paired_bootstrap_diff(a, a) == (0.0, 0.0, 0.0)


def test_length_mismatch_raises() -> None:
    with pytest.raises(ValueError):
        mcnemar_exact([True], [True, False])
    with pytest.raises(ValueError):
        paired_bootstrap_diff([True], [True, False])
