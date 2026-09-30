"""Small-sample statistics for the categorical oracles, in pure stdlib.

Why this module exists
----------------------
The confirmation oracles need to answer "is this difference real, or is it
noise?" with a *number* a reviewer can check, not with a hand-waved threshold.
The obvious move is ``scipy.stats``, but the same constraint that governs
:mod:`web_security_scanner.core.ieee_metrics` applies here: the pipeline that
produces the paper's numbers has to run with the same dependency set as the
scanner, so a reviewer can reproduce it without a scientific-Python install.

So this is a hand-rolled paired t-test and exact sign test on top of the regularised
incomplete beta function, which is what a t-distribution's survival function
reduces to:

.. math::

    P(|T_{df}| > |t|) = I_{\\frac{df}{df + t^2}}\\!\\left(\\tfrac{df}{2}, \\tfrac{1}{2}\\right)

The incomplete beta is evaluated with the Lentz continued fraction (Numerical
Recipes ``betacf``), which converges in well under 50 iterations for every
argument this module can produce.

Why a paired t-test and not a sign test
---------------------------------------
A sign test throws away the *magnitude* of each observation, and with the
three probes the time-based and boolean SQLi oracles are specified to take, it
cannot reach significance at any alpha: the smallest attainable two-sided p for
``n = 3`` is ``0.25``. The paired t-test uses magnitude, so ``n = 3`` is
actually workable — differences of ``(0.20, 0.18, 0.22)`` give ``t = 17.3`` on
2 degrees of freedom, two-sided ``p = 0.0033``. The sign test is still exposed
and reported alongside, as a distribution-free corroboration that does not
assume normality.

Both tests are reported; neither is allowed to silently substitute for the
other. :func:`paired_t_test` is the decision statistic, :func:`sign_test` is
recorded in the same verdict as a second opinion.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

__all__ = [
    "mean",
    "sample_stdev",
    "betai",
    "t_two_sided_p",
    "PairedTResult",
    "paired_t_test",
    "SignTestResult",
    "sign_test",
    "MIN_PROBES",
    "MIN_PROBES_FOR_SIGNIFICANCE",
]

#: Minimum number of paired observations any oracle takes. Three is the floor
#: the time-based oracle needs to tell a plateau from a single spike (Finding:
#: one GC pause gives one slow sample out of three; a real ``SLEEP`` gives all
#: three), and it is the smallest ``n`` for which a *magnitude*-based test has
#: any power at all.
MIN_PROBES = 3

#: Below this ``n`` the exact two-sided sign test cannot reach ``p < 0.05``
#: (``n = 3`` floors at ``0.25``). Oracles report the paired t-test and flag
#: the sign test as underpowered instead of pretending otherwise.
MIN_PROBES_FOR_SIGNIFICANCE = 5

_EPS = 3e-16
_FPMIN = 1e-300


def mean(values: list[float] | tuple[float, ...]) -> float:
    """Arithmetic mean. Returns 0.0 for an empty input rather than raising."""
    if not values:
        return 0.0
    return math.fsum(values) / len(values)


def sample_stdev(values: list[float] | tuple[float, ...]) -> float:
    """Sample standard deviation (Bessel-corrected). 0.0 for fewer than 2 values."""
    n = len(values)
    if n < 2:
        return 0.0
    mu = mean(values)
    var = math.fsum((v - mu) ** 2 for v in values) / (n - 1)
    # Guard against a negative var from catastrophic cancellation on huge inputs.
    return math.sqrt(var) if var > 0.0 else 0.0


def _betacf(a: float, b: float, x: float, itmax: int = 300) -> float:
    """Continued-fraction expansion for the incomplete beta (modified Lentz)."""
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < _FPMIN:
        d = _FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, itmax + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < _FPMIN:
            d = _FPMIN
        c = 1.0 + aa / c
        if abs(c) < _FPMIN:
            c = _FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < _FPMIN:
            d = _FPMIN
        c = 1.0 + aa / c
        if abs(c) < _FPMIN:
            c = _FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPS:
            break
    return h


def betai(a: float, b: float, x: float) -> float:
    """Regularised incomplete beta function ``I_x(a, b)``.

    Uses the symmetry ``I_x(a, b) = 1 - I_{1-x}(b, a)`` to stay in the region
    where the continued fraction converges quickly.
    """
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    ln_beta = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log1p(-x)
    )
    front = math.exp(ln_beta)
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def t_two_sided_p(t: float, df: float) -> float:
    """Two-sided p-value for a Student ``t`` statistic on ``df`` degrees of freedom."""
    if df <= 0:
        return 1.0
    t = abs(t)
    if math.isinf(t):
        return 0.0
    if math.isnan(t):
        return 1.0
    return betai(df / 2.0, 0.5, df / (df + t * t))


@dataclass(frozen=True)
class PairedTResult:
    """Outcome of a one-sided paired t-test on per-replicate differences.

    ``p_value`` is **one-sided** by construction (``H1: mean(d) > 0``), because
    the oracles only ever have a directional hypothesis: the true clause should
    look *more* like the baseline than the false clause does. A two-sided test
    would halve the power for no benefit, and would not be testing the stated
    hypothesis.
    """

    n: int
    mean_difference: float
    stdev_difference: float
    t_statistic: float
    df: int
    p_value: float | None
    significant: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "n": self.n,
            "mean_difference": self.mean_difference,
            "stdev_difference": self.stdev_difference,
            "t": self.t_statistic,
            "df": self.df,
            "p_one_sided": self.p_value,
            "significant": self.significant,
            "reason": self.reason,
        }


def paired_t_test(
    differences: list[float] | tuple[float, ...],
    *,
    alpha: float = 0.05,
    min_probes: int = MIN_PROBES,
) -> PairedTResult:
    """One-sided paired t-test on ``differences`` against ``H0: mean(d) == 0``.

    ``H1: mean(d) > 0`` -- the caller passes differences oriented so that a
    positive value is evidence for the vulnerability.

    Degenerate spread
    -----------------
    When every replicate yields the *same* difference (``stdev == 0``) the
    t statistic is unbounded, which is the correct limit: perfect agreement
    across replicates is stronger evidence than any finite t, not weaker. It
    is reported as ``t = inf`` with ``p = 0.0`` when the mean is positive, and
    as ``t = nan`` with ``p = 1.0`` when the mean is zero (no evidence at all).
    The distinction matters -- collapsing both to "not significant" would throw
    away the case where the effect is real and perfectly reproducible.
    """
    n = len(differences)
    if n < min_probes:
        return PairedTResult(
            n=n,
            mean_difference=mean(list(differences)),
            stdev_difference=sample_stdev(list(differences)),
            t_statistic=float("nan"),
            df=max(0, n - 1),
            p_value=None,
            significant=False,
            reason=(
                f"underpowered: {n} paired observation(s), need at least {min_probes}"
            ),
        )

    mu = mean(list(differences))
    sd = sample_stdev(list(differences))
    df = n - 1

    if sd == 0.0:
        if mu > 0.0:
            return PairedTResult(
                n=n, mean_difference=mu, stdev_difference=0.0,
                t_statistic=math.inf, df=df, p_value=0.0, significant=True,
                reason="zero spread across all replicates with a positive mean.",
            )
        return PairedTResult(
            n=n, mean_difference=mu, stdev_difference=0.0,
            t_statistic=float("nan"), df=df, p_value=1.0, significant=False,
            reason="zero spread across all replicates and a zero mean: no effect.",
        )

    se = sd / math.sqrt(n)
    t_stat = mu / se if se > 0.0 else math.inf
    # One-sided p from the two-sided routine: halve it, because the two-sided
    # test splits its tail mass evenly and we are only asking about one side.
    p_one = t_two_sided_p(t_stat, df) / 2.0 if math.isfinite(t_stat) else (
        0.0 if t_stat > 0 else 1.0
    )

    return PairedTResult(
        n=n,
        mean_difference=mu,
        stdev_difference=sd,
        t_statistic=t_stat,
        df=df,
        p_value=p_one,
        significant=p_one < alpha,
        reason=(
            f"paired t({df}) = {t_stat:.4f}, one-sided p = {p_one:.5f} "
            f"(alpha = {alpha})"
        ),
    )


@dataclass(frozen=True)
class SignTestResult:
    """Outcome of an exact two-sided sign test."""

    n: int
    positives: int
    p_value: float
    significant: bool
    underpowered: bool
    reason: str


def sign_test(
    differences: list[float] | tuple[float, ...],
    *,
    alpha: float = 0.05,
) -> SignTestResult:
    """Exact two-sided sign test on the *sign* of ``differences``.

    Distribution-free, so it survives the small samples and the non-normal
    latency distributions that make the t-test's normality assumption shaky.
    Ties (exactly-zero differences) are dropped, as is conventional.

    Reports ``underpowered`` rather than a bare "not significant" when ``n`` is
    too small for the test to have been able to reach ``alpha`` at all. With
    ``n = 3`` the best possible two-sided p is ``0.25``; silently printing
    "p = 0.25, not significant" reads as a negative result when it is actually
    an absence of power, and those two things must not look the same in a
    results table.
    """
    nonzero = [d for d in differences if d != 0.0]
    n = len(nonzero)
    positives = sum(1 for d in nonzero if d > 0.0)

    if n == 0:
        return SignTestResult(
            n=0, positives=0, p_value=1.0, significant=False, underpowered=True,
            reason="no non-zero differences: the effect is exactly absent.",
        )

    k = min(positives, n - positives)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2.0 ** n)
    p_value = min(1.0, 2.0 * tail)

    min_p = 2.0 / (2.0 ** n)
    underpowered = min_p >= alpha

    if underpowered:
        reason = (
            f"underpowered: n = {n} cannot reach alpha = {alpha} "
            f"(smallest attainable two-sided p = {min_p:.4f})"
        )
    else:
        reason = f"exact two-sided sign test: {positives}/{n} positive, p = {p_value:.5f}"

    return SignTestResult(
        n=n,
        positives=positives,
        p_value=p_value,
        significant=(not underpowered) and p_value < alpha,
        underpowered=underpowered,
        reason=reason,
    )
