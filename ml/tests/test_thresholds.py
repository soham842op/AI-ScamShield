import pytest

from scamshield_ml.thresholds import (
    ThresholdError,
    choose,
    high_risk_threshold,
    suspicious_threshold,
)


def test_high_risk_is_lowest_score_keeping_precision_at_every_higher_cut() -> None:
    scores = [0.95, 0.9, 0.8, 0.7, 0.6, 0.5]
    targets = [1, 1, 1, 0, 1, 0]
    # At 0.8: 3/3. At 0.7: 3/4 < 0.9, so the walk stops; 0.6 (4/5) is never reached.
    assert high_risk_threshold(targets, scores, 0.9) == 0.8


def test_high_risk_handles_tied_scores_together() -> None:
    # 0.9 is shared by a positive and a negative: precision there is 2/3.
    assert high_risk_threshold([1, 1, 0], [0.95, 0.9, 0.9], 0.9) == 0.95


def test_high_risk_fails_when_target_unreachable() -> None:
    with pytest.raises(ThresholdError):
        high_risk_threshold([0, 1], [0.9, 0.1], 0.98)


def test_suspicious_is_highest_score_meeting_recall() -> None:
    scores = [0.9, 0.8, 0.7, 0.6, 0.2, 0.1]
    targets = [1, 1, 1, 1, 0, 1]
    # Five positives; 95% recall needs all five, so the cut is the lowest positive.
    assert suspicious_threshold(targets, scores, 0.95) == 0.1
    assert suspicious_threshold(targets, scores, 0.8) == 0.6


def test_choose_rounds_in_the_safe_direction() -> None:
    scores = [0.912345, 0.81111, 0.70001, 0.300009, 0.2]
    targets = [1, 1, 1, 1, 0]
    result = choose(targets, scores, min_precision=1.0, min_recall=1.0)
    # T_h rounds up (never admits a lower score), T_s rounds down (never drops one).
    assert result.high_risk == 0.3001
    assert result.suspicious == 0.3


def test_choose_refuses_when_order_does_not_hold() -> None:
    with pytest.raises(ThresholdError):
        choose([1, 1, 0], [0.9, 0.9, 0.95], min_precision=0.5, min_recall=0.5)
