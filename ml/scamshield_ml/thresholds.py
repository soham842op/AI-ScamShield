"""Choose the operating thresholds T_s < T_h from validation scores only.

Rule (CP5 design decision, recorded in docs/MODEL_EVALUATION.md):

- T_h (`high_risk`): the lowest score at which validation precision is at least
  HIGH_RISK_MIN_PRECISION, and stays at least that for every higher threshold.
  A classifier-driven `high_risk` should rarely be wrong.
- T_s (`suspicious`): the highest score at which validation recall is at least
  SUSPICIOUS_MIN_RECALL. A missed scam is the costlier error at this level.

T_h is rounded up and T_s down to 4 decimals, so rounding never weakens either
target. If the rule cannot give T_s < T_h the run stops: the trade-off then needs
a human decision, not a silent fallback.
"""

import math
from collections.abc import Sequence
from dataclasses import dataclass

HIGH_RISK_MIN_PRECISION = 0.98
SUSPICIOUS_MIN_RECALL = 0.95
DECIMALS = 4
_SCALE = 10_000  # 10**DECIMALS


class ThresholdError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Thresholds:
    suspicious: float
    high_risk: float


def _floor(value: float) -> float:
    return math.floor(value * _SCALE) / _SCALE


def _ceil(value: float) -> float:
    return min(1.0, math.ceil(value * _SCALE) / _SCALE)


def high_risk_threshold(
    targets: Sequence[int], scores: Sequence[float], min_precision: float
) -> float:
    pairs = sorted(zip(scores, targets, strict=True), reverse=True)
    tp = fp = 0
    best: float | None = None
    index = 0
    # Walk thresholds from the highest score down; each distinct score is a candidate.
    while index < len(pairs):
        score = pairs[index][0]
        while index < len(pairs) and pairs[index][0] == score:
            if pairs[index][1]:
                tp += 1
            else:
                fp += 1
            index += 1
        if tp / (tp + fp) < min_precision:
            break
        best = score
    if best is None:
        raise ThresholdError("no threshold reaches the high-risk precision target")
    return best


def suspicious_threshold(
    targets: Sequence[int], scores: Sequence[float], min_recall: float
) -> float:
    positives = sorted((s for s, t in zip(scores, targets, strict=True) if t), reverse=True)
    if not positives:
        raise ThresholdError("no positive examples")
    # The k-th highest positive score keeps k positives at or above the threshold.
    needed = math.ceil(min_recall * len(positives))
    return positives[needed - 1]


def choose(
    targets: Sequence[int],
    scores: Sequence[float],
    *,
    min_precision: float = HIGH_RISK_MIN_PRECISION,
    min_recall: float = SUSPICIOUS_MIN_RECALL,
) -> Thresholds:
    t_h = _ceil(high_risk_threshold(targets, scores, min_precision))
    t_s = _floor(suspicious_threshold(targets, scores, min_recall))
    if not 0.0 <= t_s < t_h <= 1.0:
        raise ThresholdError(f"rule gives T_s={t_s} and T_h={t_h}; T_s < T_h does not hold")
    return Thresholds(suspicious=t_s, high_risk=t_h)
