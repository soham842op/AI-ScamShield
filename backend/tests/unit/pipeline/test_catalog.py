import re
from typing import Any

import pytest

from app.pipeline.catalog import (
    LIMIT_NEW_SITES,
    NOT_A_GUARANTEE,
    build_limitations,
    build_recommendations,
)
from app.pipeline.types import Classification, UrlCheck, UrlEntry

from .helpers import entry

NO_URLS = UrlCheck("not_applicable", None, None, 0, False, ())
ALL_CLASSIFICATIONS: tuple[Classification, ...] = (
    "likely_legitimate",
    "suspicious",
    "high_risk",
    "inconclusive",
)


def url_check(
    *entries: UrlEntry,
    found: int | None = None,
    truncated: bool = False,
    status: str = "inconclusive",
) -> UrlCheck:
    kwargs: dict[str, Any] = {"status": status}
    return UrlCheck(
        provider="none",
        checked_at=None,
        urls_found=len(entries) if found is None else found,
        urls_truncated=truncated,
        urls=tuple(entries),
        **kwargs,
    )


def test_not_a_guarantee_string_is_exact_and_first() -> None:
    assert NOT_A_GUARANTEE == (
        "A risk assessment is not a guarantee. "
        "A low rating is not proof that content is legitimate."
    )
    result = build_limitations(
        input_type="message",
        classification="inconclusive",
        classifier_status="unavailable",
        url_check=NO_URLS,
    )
    assert result[0] == NOT_A_GUARANTEE


def test_message_without_model_says_rules_only() -> None:
    result = build_limitations(
        input_type="message",
        classification="inconclusive",
        classifier_status="unavailable",
        url_check=NO_URLS,
    )
    assert result == (
        NOT_A_GUARANTEE,
        "The text model is not available, so this result is based on rules only.",
    )


def test_url_input_has_no_model_limitation() -> None:
    result = build_limitations(
        input_type="url",
        classification="inconclusive",
        classifier_status="not_applicable",
        url_check=url_check(entry("not_checked", "provider_not_configured")),
    )
    assert result == (NOT_A_GUARANTEE, "Links were not checked against a reputation service.")


@pytest.mark.parametrize("reason", ["provider_timeout", "provider_error"])
def test_provider_failure_limitation(reason: str) -> None:
    result = build_limitations(
        input_type="url",
        classification="inconclusive",
        classifier_status="not_applicable",
        url_check=url_check(entry("unknown", reason)),
    )
    assert result == (
        NOT_A_GUARANTEE,
        "The URL could not be checked because the reputation provider did not respond.",
    )


def test_quota_and_truncation_limitations() -> None:
    result = build_limitations(
        input_type="message",
        classification="inconclusive",
        classifier_status="ok",
        url_check=url_check(entry("not_checked", "quota_exhausted"), found=12, truncated=True),
    )
    assert any("limit was reached" in item for item in result)
    assert "Only the first 10 links were analyzed." in result


def test_new_sites_limitation_only_for_likely_legitimate_with_no_match() -> None:
    no_match = url_check(entry("no_match"), status="no_match")

    def limits(classification: Classification, check: UrlCheck) -> tuple[str, ...]:
        return build_limitations(
            input_type="message",
            classification=classification,
            classifier_status="ok",
            url_check=check,
        )

    assert LIMIT_NEW_SITES == "New scam sites are often not yet on reputation lists."
    assert LIMIT_NEW_SITES in limits("likely_legitimate", no_match)
    assert LIMIT_NEW_SITES not in limits("suspicious", no_match)
    assert LIMIT_NEW_SITES not in limits("likely_legitimate", NO_URLS)


@pytest.mark.parametrize("classification", ALL_CLASSIFICATIONS)
def test_recommendations_always_at_least_one(classification: Classification) -> None:
    assert len(build_recommendations(classification, ())) >= 1


def test_recommendations_by_signal() -> None:
    result = build_recommendations(
        "high_risk", ["credential_request", "url_reputation_flagged", "urgency"]
    )
    assert result[0] == "Do not click the link."
    assert "Do not share passwords, PINs or one-time codes." in result
    assert any("official website" in item for item in result)


def test_recommendations_are_deduped_and_stable() -> None:
    ids = ["brand_lookalike_host", "url_userinfo", "punycode_host", "credential_request"]
    first = build_recommendations("high_risk", ids)
    second = build_recommendations("high_risk", reversed(ids))
    assert first == second
    assert len(first) == len(set(first))
    assert first.count("Do not click the link.") == 1


def test_inconclusive_recommendation() -> None:
    assert build_recommendations("inconclusive", ()) == (
        "Do not rely on this result. Verify the sender through an official channel.",
    )


def test_no_catalog_text_calls_anything_safe() -> None:
    every_signal = [
        "url_reputation_flagged",
        "credential_request",
        "payment_request",
        "prize_or_lottery",
        "too_good_to_be_true",
        "obfuscation_chars",
        "urgency",
        "brand_impersonation",
    ]
    texts: list[str] = [LIMIT_NEW_SITES]
    for classification in ALL_CLASSIFICATIONS:
        texts += build_recommendations(classification, every_signal)
    for text in texts:
        assert not re.search(r"\b(safe|secure|clean|verified)\b", text, re.I), text
