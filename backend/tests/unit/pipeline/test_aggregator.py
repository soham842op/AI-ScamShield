from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import pytest

from app.pipeline.aggregator import (
    Thresholds,
    build_url_check,
    classifier_signal,
    classify,
    merge_signals,
    risk_score,
    url_check_status,
    url_reputation_signal,
)
from app.pipeline.types import ClassifierResult, Signal, UrlCheck, UrlEntry

from .helpers import CLASSIFIER_DOWN, CLASSIFIER_NA, entry, sig

NOW = datetime(2026, 10, 19, tzinfo=UTC)
TH = Thresholds(suspicious=0.5, high_risk=0.9)


def check(*entries: UrlEntry, found: int | None = None, truncated: bool = False) -> UrlCheck:
    return build_url_check(
        entries,
        urls_found=len(entries) if found is None else found,
        truncated=truncated,
        provider="none",
        checked_at=NOW,
    )


def ok(score: float) -> ClassifierResult:
    label = "scam_like" if score >= 0.5 else "not_scam_like"
    return ClassifierResult(status="ok", label=label, raw_score=score)


# Section 5.3 aggregate status.


@pytest.mark.parametrize(
    ("entries", "found", "truncated", "expected"),
    [
        ([], 0, False, "not_applicable"),
        ([entry("flagged")], 1, False, "flagged"),
        (
            [entry("no_match"), entry("flagged"), entry("unknown", "provider_error")],
            3,
            False,
            "flagged",
        ),
        ([entry("no_match"), entry("no_match")], 2, False, "no_match"),
        ([entry("no_match")], 11, True, "inconclusive"),
        ([entry("not_checked", "provider_not_configured")] * 2, 2, False, "not_checked"),
        ([entry("not_checked", "provider_not_configured")], 11, True, "not_checked"),
        ([entry("unknown", "provider_timeout")], 1, False, "inconclusive"),
        ([entry("no_match"), entry("unknown", "provider_error")], 2, False, "inconclusive"),
        ([entry("no_match"), entry("not_checked", "quota_exhausted")], 2, False, "inconclusive"),
    ],
)
def test_url_check_status(
    entries: list[UrlEntry], found: int, truncated: bool, expected: str
) -> None:
    assert url_check_status(entries, urls_found=found, truncated=truncated) == expected


def test_provider_is_none_iff_no_urls() -> None:
    none_found = check()
    assert none_found.provider is None
    assert none_found.status == "not_applicable"
    assert none_found.checked_at is None
    assert check(entry("unknown", "provider_error")).provider == "none"


def test_checked_at_only_when_something_was_checked() -> None:
    assert check(entry("unknown", "provider_error")).checked_at is None
    assert check(entry("not_checked", "provider_not_configured")).checked_at is None
    assert check(entry("no_match")).checked_at == NOW
    assert check(entry("flagged")).checked_at == NOW


def test_urls_checked_counts_flagged_and_no_match() -> None:
    result = check(entry("flagged"), entry("no_match"), entry("unknown", "provider_error"))
    assert result.urls_checked == 2


# Section 6 classification.

NO_URLS = check()
NO_MATCH = check(entry("no_match"))
FLAGGED = check(entry("flagged"))
UNKNOWN = check(entry("unknown", "provider_timeout"))


def run(
    *,
    classifier: ClassifierResult,
    signals: Sequence[Signal] = (),
    url_check: UrlCheck = NO_URLS,
    input_type: str = "message",
    thresholds: Thresholds | None = TH,
) -> str:
    kwargs: dict[str, Any] = {"input_type": input_type}
    return classify(
        classifier=classifier,
        signals=signals,
        url_check=url_check,
        thresholds=thresholds,
        **kwargs,
    )


def test_flagged_url_is_high_risk() -> None:
    assert run(classifier=ok(0.0), url_check=FLAGGED) == "high_risk"
    assert run(classifier=CLASSIFIER_DOWN, url_check=FLAGGED, thresholds=None) == "high_risk"
    assert run(classifier=CLASSIFIER_NA, url_check=FLAGGED, input_type="url") == "high_risk"


def test_score_at_high_threshold_is_high_risk() -> None:
    assert run(classifier=ok(0.9)) == "high_risk"
    assert run(classifier=ok(0.89)) == "suspicious"


def test_two_high_signals_is_high_risk() -> None:
    signals = [sig("credential_request", "high"), sig("payment_request", "high")]
    assert run(classifier=CLASSIFIER_DOWN, signals=signals, thresholds=None) == "high_risk"


def test_one_high_signal_is_suspicious() -> None:
    result = run(classifier=CLASSIFIER_DOWN, signals=[sig("a", "high")], thresholds=None)
    assert result == "suspicious"


def test_two_medium_signals_is_suspicious() -> None:
    result = run(classifier=CLASSIFIER_DOWN, signals=[sig("a"), sig("b")], thresholds=None)
    assert result == "suspicious"


def test_one_medium_signal_without_classifier_is_inconclusive() -> None:
    result = run(classifier=CLASSIFIER_DOWN, signals=[sig("a")], thresholds=None)
    assert result == "inconclusive"


def test_score_at_suspicious_threshold() -> None:
    assert run(classifier=ok(0.5)) == "suspicious"
    assert run(classifier=ok(0.49)) == "likely_legitimate"


def test_classifier_signal_is_not_counted() -> None:
    only_classifier = [sig("classifier_scam_like", "high", "classifier")]
    assert run(classifier=ok(0.1), signals=only_classifier) == "likely_legitimate"
    two = [sig("classifier_scam_like", "high", "classifier"), sig("credential_request", "high")]
    assert run(classifier=ok(0.6), signals=two) == "suspicious"


def test_likely_legitimate_needs_classifier_for_messages() -> None:
    assert run(classifier=ok(0.1)) == "likely_legitimate"
    assert run(classifier=CLASSIFIER_DOWN, thresholds=None) == "inconclusive"


def test_likely_legitimate_with_no_match_url() -> None:
    assert run(classifier=ok(0.1), url_check=NO_MATCH) == "likely_legitimate"


def test_low_signals_do_not_block_likely_legitimate() -> None:
    assert run(classifier=ok(0.1), signals=[sig("a", "low")]) == "likely_legitimate"


def test_medium_signal_blocks_likely_legitimate() -> None:
    assert run(classifier=ok(0.1), signals=[sig("a")]) == "inconclusive"


@pytest.mark.parametrize("found", [11, 50])
def test_truncation_never_gives_likely_legitimate(found: int) -> None:
    padded = check(*[entry("no_match")] * 10, found=found, truncated=True)
    assert padded.status == "inconclusive"
    assert run(classifier=ok(0.0), url_check=padded) == "inconclusive"


def test_unknown_or_not_checked_url_is_inconclusive() -> None:
    assert run(classifier=ok(0.1), url_check=UNKNOWN) == "inconclusive"
    not_checked = check(entry("not_checked", "provider_not_configured"))
    assert run(classifier=ok(0.1), url_check=not_checked) == "inconclusive"


def test_url_endpoint_with_provider_none_is_inconclusive() -> None:
    not_checked = check(entry("not_checked", "provider_not_configured"))
    result = run(classifier=CLASSIFIER_NA, url_check=not_checked, input_type="url")
    assert result == "inconclusive"


def test_url_endpoint_no_match_is_likely_legitimate() -> None:
    result = run(classifier=CLASSIFIER_NA, url_check=NO_MATCH, input_type="url")
    assert result == "likely_legitimate"


def test_url_endpoint_rules_signals_count() -> None:
    signals = [sig("brand_lookalike_host", "high", "url_rules")]
    result = run(classifier=CLASSIFIER_NA, signals=signals, url_check=NO_MATCH, input_type="url")
    assert result == "suspicious"


def test_ok_classifier_without_thresholds_raises() -> None:
    with pytest.raises(ValueError, match="thresholds"):
        run(classifier=ok(0.3), thresholds=None)
    with pytest.raises(ValueError, match="thresholds"):
        classifier_signal(ok(0.3), None)


def test_thresholds_must_be_ordered() -> None:
    with pytest.raises(ValueError, match="thresholds"):
        Thresholds(suspicious=0.9, high_risk=0.5)


# Score.


def test_score_for_message_with_ok_classifier() -> None:
    result = risk_score(input_type="message", classifier=ok(0.944), classification="high_risk")
    assert result == (94, "heuristic", "text_classifier")


@pytest.mark.parametrize(
    ("input_type", "classifier", "classification"),
    [
        ("message", ok(0.5), "inconclusive"),
        ("message", CLASSIFIER_DOWN, "suspicious"),
        ("url", CLASSIFIER_NA, "high_risk"),
    ],
)
def test_score_is_hidden(
    input_type: str, classifier: ClassifierResult, classification: str
) -> None:
    kwargs: dict[str, Any] = {"input_type": input_type, "classification": classification}
    assert risk_score(classifier=classifier, **kwargs) == (None, "none", None)


# Signals.


def test_reputation_signal_only_when_flagged() -> None:
    assert url_reputation_signal("message", NO_MATCH) is None
    assert url_reputation_signal("message", NO_URLS) is None
    flagged = url_reputation_signal("message", FLAGGED)
    assert flagged is not None
    assert (flagged.id, flagged.source, flagged.severity) == (
        "url_reputation_flagged",
        "url_reputation",
        "high",
    )
    assert flagged.evidence_excerpt is None
    url_flagged = url_reputation_signal("url", FLAGGED)
    assert url_flagged is not None
    assert url_flagged.description != flagged.description


def test_classifier_signal_thresholds() -> None:
    assert classifier_signal(ok(0.49), TH) is None
    assert classifier_signal(CLASSIFIER_DOWN, TH) is None
    medium = classifier_signal(ok(0.6), TH)
    high = classifier_signal(ok(0.9), TH)
    assert medium is not None
    assert medium.severity == "medium"
    assert high is not None
    assert high.severity == "high"
    assert (high.id, high.source) == ("classifier_scam_like", "classifier")


def test_merge_signals_dedupes_by_highest_severity_then_first() -> None:
    first = sig("x", "medium", "rules")
    second = sig("x", "medium", "url_rules")
    higher = sig("x", "high", "url_rules")
    assert merge_signals([first, second]) == (first,)
    assert merge_signals([first, higher]) == (higher,)
    assert merge_signals([higher, first]) == (higher,)


def test_merge_signals_order() -> None:
    signals = [
        sig("b_low", "low", "rules"),
        sig("z_med_url", "medium", "url_rules"),
        sig("a_med_rules", "medium", "rules"),
        sig("rep", "high", "url_reputation"),
        sig("b_high_rules", "high", "rules"),
        sig("a_high_rules", "high", "rules"),
        sig("m_med_rules", "medium", "rules"),
    ]
    assert [s.id for s in merge_signals(signals)] == [
        "a_high_rules",
        "b_high_rules",
        "rep",
        "a_med_rules",
        "m_med_rules",
        "z_med_url",
        "b_low",
    ]
