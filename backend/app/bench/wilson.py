"""Statistical Wilson Score Confidence Interval Calculator.

Provides calibrated binomial confidence intervals (e.g. 95% Wilson score intervals)
for empirical benchmark reporting, ensuring statistical honesty without hand-typed numbers.
"""

from typing import Tuple
import math


def wilson_score_interval(
    successes: int,
    total: int,
    confidence: float = 0.95,
    as_percentage: bool = True,
    decimals: int = 1,
) -> Tuple[float, float]:
    """Computes the two-sided Wilson score confidence interval for a binomial proportion.

    Args:
        successes: Number of successful/positive trials (k >= 0).
        total: Total number of trials (n >= 0).
        confidence: Desired confidence level (default: 0.95 for 95% CI).
        as_percentage: If True, returns bounds in [0.0, 100.0]; if False, [0.0, 1.0].
        decimals: Decimal places to round output bounds.

    Returns:
        Tuple of (lower_bound, upper_bound).
    """
    if total <= 0:
        return (0.0, 0.0)

    if successes < 0:
        successes = 0
    elif successes > total:
        successes = total

    # Standard normal quantile z for common confidence levels
    # Default to 95% (z ~= 1.95996)
    if abs(confidence - 0.95) < 1e-4:
        z = 1.959963984540054
    elif abs(confidence - 0.99) < 1e-4:
        z = 2.5758293035489004
    elif abs(confidence - 0.90) < 1e-4:
        z = 1.6448536269514722
    else:
        # Fallback to standard 1.96 if outside standard levels
        z = 1.959963984540054

    n = float(total)
    p_hat = float(successes) / n
    z2 = z * z

    denominator = 1.0 + (z2 / n)
    center = (p_hat + (z2 / (2.0 * n))) / denominator
    margin = (z * math.sqrt((p_hat * (1.0 - p_hat) / n) + (z2 / (4.0 * (n * n))))) / denominator

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)

    multiplier = 100.0 if as_percentage else 1.0
    return (round(lower * multiplier, decimals), round(upper * multiplier, decimals))


def format_wilson_ci(
    successes: int,
    total: int,
    confidence: float = 0.95,
    as_percentage: bool = True,
    decimals: int = 1,
) -> str:
    """Formats Wilson score interval as a clean markdown bracket string, e.g. '[88.6%, 100.0%]'."""
    low, high = wilson_score_interval(
        successes=successes,
        total=total,
        confidence=confidence,
        as_percentage=as_percentage,
        decimals=decimals,
    )
    unit = "%" if as_percentage else ""
    return f"[{low:.{decimals}f}{unit}, {high:.{decimals}f}{unit}]"
