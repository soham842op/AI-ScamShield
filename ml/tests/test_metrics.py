import pytest

from scamshield_ml.metrics import confusion, ranking, wilson


def test_confusion_counts_and_rates() -> None:
    result = confusion([1, 1, 0, 0, 1], [0.9, 0.2, 0.6, 0.1, 0.5], 0.5)
    assert (result.tp, result.fp, result.fn, result.tn) == (2, 1, 1, 1)
    assert result.precision == pytest.approx(2 / 3)
    assert result.recall == pytest.approx(2 / 3)
    assert result.false_positive_rate == pytest.approx(0.5)


def test_undefined_rates_are_none() -> None:
    result = confusion([0, 0], [0.1, 0.2], 0.5)
    assert result.precision is None
    assert result.recall is None
    assert result.f1 is None


def test_wilson_interval_matches_known_value() -> None:
    low, high = wilson(8, 10) or (0.0, 0.0)
    assert low == pytest.approx(0.4902, abs=1e-4)
    assert high == pytest.approx(0.9433, abs=1e-4)
    assert wilson(0, 0) is None


def test_ranking_needs_both_classes() -> None:
    assert ranking([1, 1], [0.2, 0.3]) == {"average_precision": None, "roc_auc": None}
    assert ranking([0, 1], [0.2, 0.9])["roc_auc"] == 1.0
