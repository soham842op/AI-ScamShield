"""Aggregate metrics. Inputs are labels and scores only; no message text."""

import math
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

from sklearn.metrics import average_precision_score, roc_auc_score

Z_95 = 1.959964


def wilson(successes: int, trials: int, z: float = Z_95) -> tuple[float, float] | None:
    """95% Wilson score interval for a proportion; None when there are no trials."""
    if trials == 0:
        return None
    p = successes / trials
    denom = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


@dataclass(frozen=True, slots=True)
class Confusion:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def false_positive_rate(self) -> float | None:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else None

    @property
    def false_negative_rate(self) -> float | None:
        return self.fn / (self.fn + self.tp) if self.fn + self.tp else None

    def summary(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "precision": self.precision,
            "precision_ci95": wilson(self.tp, self.tp + self.fp),
            "recall": self.recall,
            "recall_ci95": wilson(self.tp, self.tp + self.fn),
            "f1": self.f1,
            "false_positive_rate": self.false_positive_rate,
            "false_positive_rate_ci95": wilson(self.fp, self.fp + self.tn),
            "false_negative_rate": self.false_negative_rate,
        }


def confusion(targets: Sequence[int], scores: Sequence[float], threshold: float) -> Confusion:
    tp = fp = fn = tn = 0
    for target, score in zip(targets, scores, strict=True):
        predicted = score >= threshold
        if predicted and target:
            tp += 1
        elif predicted:
            fp += 1
        elif target:
            fn += 1
        else:
            tn += 1
    return Confusion(tp=tp, fp=fp, fn=fn, tn=tn)


def ranking(targets: Sequence[int], scores: Sequence[float]) -> dict[str, float | None]:
    """Threshold-free metrics. Undefined (None) when only one class is present."""
    if len(set(targets)) < 2:
        return {"average_precision": None, "roc_auc": None}
    return {
        "average_precision": float(average_precision_score(targets, scores)),
        "roc_auc": float(roc_auc_score(targets, scores)),
    }
