import asyncio
import re
from dataclasses import replace
from typing import Any

import pytest

from app.pipeline.explain import TEMPLATE_VERSION, explain, template_explanation
from app.pipeline.explain.template import (
    _LEAD,
    _MODEL_UNAVAILABLE,
    _SIGNALS_PREFIX,
    _URL_PHRASE,
    _URL_PHRASE_SINGLE,
)
from app.pipeline.types import EvidenceSignal, EvidenceUrl, ExplanationEvidence


def _evidence(**overrides: Any) -> ExplanationEvidence:
    base = ExplanationEvidence(
        input_type="message",
        classification="inconclusive",
        classifier_status="ok",
        signals=(),
        url_check_status="not_applicable",
        urls=(),
        urls_truncated=False,
    )
    return replace(base, **overrides)


def _sig(id_: str, severity: Any, desc: str, source: Any = "rules") -> EvidenceSignal:
    return EvidenceSignal(id_, source, severity, desc)


def test_template_version_format() -> None:
    assert TEMPLATE_VERSION == "tpl-1.1"


@pytest.mark.parametrize("classification", list(_LEAD))
def test_lead_sentence_per_classification(classification: Any) -> None:
    text = template_explanation(_evidence(classification=classification))
    assert text.startswith(_LEAD[classification])


@pytest.mark.parametrize(("status", "phrase"), list(_URL_PHRASE.items()))
def test_url_status_phrase(status: Any, phrase: str | None) -> None:
    text = template_explanation(_evidence(url_check_status=status))
    if phrase is None:
        assert text == _LEAD["inconclusive"]
    else:
        assert phrase in text


@pytest.mark.parametrize(("status", "phrase"), list(_URL_PHRASE_SINGLE.items()))
def test_url_status_phrase_singular_for_url_input(status: Any, phrase: str | None) -> None:
    text = template_explanation(
        _evidence(input_type="url", classifier_status="not_applicable", url_check_status=status)
    )
    if phrase is None:
        assert text == _LEAD["inconclusive"]
    else:
        assert phrase in text
        assert "links" not in text


def test_exact_phrases() -> None:
    assert _LEAD["high_risk"] == "This looks like a scam."
    assert _LEAD["suspicious"] == "This has warning signs of a scam."
    assert _LEAD["inconclusive"] == "There is not enough information to rate this."
    assert _URL_PHRASE["not_checked"] == "The links were not checked against a reputation service."
    assert _URL_PHRASE["inconclusive"] == "Some links could not be checked."
    assert _URL_PHRASE["flagged"] == "A link was flagged by the URL reputation provider."


def test_top_signals_by_severity_then_order() -> None:
    signals = (
        _sig("a_low", "low", "Low one."),
        _sig("b_med", "medium", "Medium one."),
        _sig("c_high", "high", "High one."),
        _sig("d_med", "medium", "Medium two."),
    )
    text = template_explanation(_evidence(classification="suspicious", signals=signals))
    assert "Main warning signs: High one; Medium one." in text
    assert "Low one" not in text
    assert "Medium two" not in text


def test_url_reputation_signal_not_repeated() -> None:
    signals = (_sig("url_reputation_flagged", "high", "A link was bad.", "url_reputation"),)
    text = template_explanation(
        _evidence(classification="high_risk", signals=signals, url_check_status="flagged")
    )
    assert "A link was bad" not in text
    assert _SIGNALS_PREFIX not in text
    assert "flagged by the URL reputation provider" in text


def test_inconclusive_model_unavailable_note() -> None:
    text = template_explanation(_evidence(classifier_status="unavailable"))
    assert _MODEL_UNAVAILABLE in text
    url_text = template_explanation(_evidence(input_type="url", classifier_status="not_applicable"))
    assert _MODEL_UNAVAILABLE not in url_text


def test_at_most_three_sentences() -> None:
    signals = (_sig("x", "high", "Sign x."), _sig("y", "high", "Sign y."))
    text = template_explanation(
        _evidence(
            classification="inconclusive",
            classifier_status="unavailable",
            signals=signals,
            url_check_status="inconclusive",
        )
    )
    # lead, signals, url status; the model note is dropped by the cap.
    assert text.count(". ") + 1 == 3
    assert _MODEL_UNAVAILABLE not in text


def test_deterministic() -> None:
    ev = _evidence(
        classification="suspicious",
        signals=(_sig("u", "medium", "Pressure."),),
        url_check_status="no_match",
    )
    assert template_explanation(ev) == template_explanation(ev)


def test_output_only_from_vocabulary_and_descriptions() -> None:
    # The evidence type cannot carry excerpts, URLs or hosts. Check that the
    # output is built purely from fixed phrases plus the given descriptions.
    vocab = {
        *_LEAD.values(),
        *(p for p in _URL_PHRASE.values() if p),
        *(p for p in _URL_PHRASE_SINGLE.values() if p),
        _MODEL_UNAVAILABLE,
        _SIGNALS_PREFIX,
    }
    desc = "The message pressures you to act now."
    ev = _evidence(
        classification="high_risk",
        signals=(_sig("urgency", "medium", desc),),
        url_check_status="flagged",
        urls=(EvidenceUrl("flagged", None, ("SOCIAL_ENGINEERING",)),),
    )
    text = template_explanation(ev)
    remaining = text
    for piece in [*sorted(vocab, key=len, reverse=True), desc.rstrip(".")]:
        remaining = remaining.replace(piece, "")
    assert re.sub(r"[\s.;]", "", remaining) == ""
    assert "SOCIAL_ENGINEERING" not in text
    assert "http" not in text


def test_never_claims_safe() -> None:
    for classification in _LEAD:
        for status in _URL_PHRASE:
            text = template_explanation(
                _evidence(classification=classification, url_check_status=status)
            ).lower()
            stripped = text.replace("does not mean they are safe", "")
            stripped = stripped.replace("does not mean it is safe", "")
            assert not re.search(r"\b(safe|clean|verified|secure)\b", stripped)


def test_explain_returns_template() -> None:
    ev = _evidence(classification="suspicious")
    result = asyncio.run(explain(ev))
    assert result.source == "template"
    assert result.prompt_version is None
    assert result.text == template_explanation(ev)
