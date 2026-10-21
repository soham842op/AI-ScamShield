from collections.abc import Sequence
from datetime import UTC, datetime

import pytest

from app.pipeline import orchestrator
from app.pipeline.types import (
    Explanation,
    ExplanationEvidence,
    LookupBatch,
    ParsedUrl,
    SubmittedUrl,
    UrlExtraction,
    UrlLookup,
)

from .helpers import parsed, sig

pytestmark = pytest.mark.anyio

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
SECRET_URL = "http://secret-host.example/private?token=abc"  # noqa: S105


class FakeProvider:
    provider_id = "fake"

    def __init__(self, results: Sequence[UrlLookup] | None = None, error: Exception | None = None):
        self.results = results
        self.error = error
        self.calls: list[list[ParsedUrl]] = []

    async def lookup(self, urls: Sequence[ParsedUrl]) -> LookupBatch:
        self.calls.append(list(urls))
        if self.error is not None:
            raise self.error
        results = self.results or tuple(UrlLookup(status="no_match") for _ in urls)
        return LookupBatch(provider=self.provider_id, results=tuple(results), checked_at=NOW)


@pytest.fixture(autouse=True)
def fakes(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[ExplanationEvidence]]:
    seen: dict[str, list[ExplanationEvidence]] = {"evidence": []}

    async def fake_explain(evidence: ExplanationEvidence) -> Explanation:
        seen["evidence"].append(evidence)
        return Explanation(text="fake explanation", source="template")

    monkeypatch.setattr(orchestrator, "explain", fake_explain)
    monkeypatch.setattr(orchestrator, "TEMPLATE_VERSION", "tpl-test")
    monkeypatch.setattr(orchestrator, "URL_RULES_VERSION", "url-test")
    monkeypatch.setattr(orchestrator, "extract_urls", lambda text: _no_urls())
    return seen


def _no_urls() -> UrlExtraction:
    return UrlExtraction(urls=(), urls_found=0, truncated=False, signals=())


def use_urls(
    monkeypatch: pytest.MonkeyPatch,
    urls: Sequence[ParsedUrl],
    *,
    found: int | None = None,
    signals: Sequence = (),
) -> None:
    extraction = UrlExtraction(
        urls=tuple(urls),
        urls_found=len(urls) if found is None else found,
        truncated=(len(urls) if found is None else found) > 10,
        signals=tuple(signals),
    )
    monkeypatch.setattr(orchestrator, "extract_urls", lambda text: extraction)


async def test_message_without_urls_or_signals() -> None:
    provider = FakeProvider()
    result = await orchestrator.analyze_message("Lunch at noon?", "sms", provider=provider)
    assert result.input_type == "message"
    assert result.channel == "sms"
    assert result.char_count == len("Lunch at noon?")
    assert result.classification == "inconclusive"  # no text model yet
    assert result.risk_score is None
    assert (result.score_type, result.score_basis) == ("none", None)
    assert result.classifier.status == "unavailable"
    assert result.url_check.status == "not_applicable"
    assert result.url_check.provider is None
    assert provider.calls == []
    assert result.limitations[0].startswith("A risk assessment is not a guarantee.")
    assert any("rules only" in item for item in result.limitations)
    assert result.versions.model is None
    assert result.versions.prompt is None
    assert set(result.timings_ms) >= {"rules", "urls", "explain"}
    assert all(isinstance(v, int) for v in result.timings_ms.values())


async def test_versions_are_composed() -> None:
    result = await orchestrator.analyze_message("hi", "chat", provider=FakeProvider())
    assert result.versions.pipeline == f"{orchestrator.PIPELINE_VERSION}+tpl-test"
    assert result.versions.rules == f"{orchestrator.RULES_VERSION}+url-test"


async def test_char_count_is_code_points_after_nfc() -> None:
    result = await orchestrator.analyze_message("Café \U0001f600", "chat", provider=FakeProvider())
    assert result.char_count == 6


async def test_rule_signals_drive_classification() -> None:
    text = "Verify your password now. Pay with Western Union."
    result = await orchestrator.analyze_message(text, "email", provider=FakeProvider())
    assert result.classification == "high_risk"
    assert [s.id for s in result.signals][:2] == ["credential_request", "payment_request"]
    assert result.signals[0].evidence_excerpt is not None
    assert "Do not share passwords, PINs or one-time codes." in result.recommendations


async def test_flagged_url_adds_reputation_signal_and_high_risk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_urls(monkeypatch, [parsed("bad.example")])
    provider = FakeProvider([UrlLookup(status="flagged", threat_types=("SOCIAL_ENGINEERING",))])
    result = await orchestrator.analyze_message("see bad.example", "sms", provider=provider)
    assert result.classification == "high_risk"
    assert result.url_check.status == "flagged"
    assert result.url_check.provider == "fake"
    assert result.url_check.checked_at == NOW
    assert "url_reputation_flagged" in [s.id for s in result.signals]
    assert result.recommendations[0] == "Do not click the link."
    assert "intel" in result.timings_ms


async def test_provider_failure_gives_unknown_not_error(monkeypatch: pytest.MonkeyPatch) -> None:
    use_urls(monkeypatch, [parsed("a.example"), parsed("b.example")])
    provider = FakeProvider(error=RuntimeError(SECRET_URL))
    result = await orchestrator.analyze_message("a.example b.example", "sms", provider=provider)
    assert [e.lookup.status for e in result.url_check.urls] == ["unknown", "unknown"]
    assert {e.lookup.reason for e in result.url_check.urls} == {"provider_error"}
    assert result.url_check.status == "inconclusive"
    assert result.url_check.checked_at is None
    assert result.classification == "inconclusive"
    assert any("did not respond" in item for item in result.limitations)


async def test_provider_timeout_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    use_urls(monkeypatch, [parsed()])
    provider = FakeProvider(error=TimeoutError())
    result = await orchestrator.analyze_message("example.com", "sms", provider=provider)
    assert result.url_check.urls[0].lookup.reason == "provider_timeout"


async def test_provider_result_count_mismatch_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    use_urls(monkeypatch, [parsed("a.example"), parsed("b.example")])
    provider = FakeProvider([UrlLookup(status="no_match")])
    result = await orchestrator.analyze_message("x", "sms", provider=provider)
    assert {e.lookup.reason for e in result.url_check.urls} == {"provider_error"}


async def test_provider_failure_is_not_logged_with_message(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    use_urls(monkeypatch, [parsed()])
    provider = FakeProvider(error=RuntimeError(SECRET_URL))
    with caplog.at_level("DEBUG"):
        await orchestrator.analyze_message("example.com", "sms", provider=provider)
    assert "secret-host" not in caplog.text
    assert "RuntimeError" in caplog.text


async def test_odd_provider_output_is_cleaned(monkeypatch: pytest.MonkeyPatch) -> None:
    use_urls(monkeypatch, [parsed("a.example"), parsed("b.example"), parsed("c.example")])
    provider = FakeProvider(
        [
            UrlLookup(status="flagged"),
            UrlLookup(status="unknown", reason="quota_exhausted"),
            UrlLookup(status="not_checked", reason=None),
        ]
    )
    result = await orchestrator.analyze_message("x", "sms", provider=provider)
    flagged, unknown, not_checked = (e.lookup for e in result.url_check.urls)
    assert flagged.threat_types
    assert unknown.reason == "provider_error"
    assert not_checked.reason == "provider_not_configured"


async def test_truncation_never_likely_legitimate(monkeypatch: pytest.MonkeyPatch) -> None:
    use_urls(monkeypatch, [parsed(f"h{i}.example") for i in range(10)], found=25)
    result = await orchestrator.analyze_message("x", "sms", provider=FakeProvider())
    assert result.url_check.urls_found == 25
    assert result.url_check.urls_truncated is True
    assert len(result.url_check.urls) == 10
    assert result.classification != "likely_legitimate"
    assert "Only the first 10 links were analyzed." in result.limitations


async def test_signals_are_unique_and_ordered(monkeypatch: pytest.MonkeyPatch) -> None:
    url_signals = [
        sig("obfuscation_chars", "medium", "url_rules"),
        sig("url_shortener", "low", "url_rules"),
        sig("brand_lookalike_host", "high", "url_rules"),
    ]
    use_urls(monkeypatch, [parsed()], signals=url_signals)
    result = await orchestrator.analyze_message(
        "hel\u200blo act now", "sms", provider=FakeProvider()
    )
    ids = [s.id for s in result.signals]
    assert len(ids) == len(set(ids))
    assert ids == ["brand_lookalike_host", "obfuscation_chars", "urgency", "url_shortener"]
    obfuscation = next(s for s in result.signals if s.id == "obfuscation_chars")
    assert obfuscation.source == "rules"  # first one wins on a tie


async def test_explanation_evidence_has_no_submitted_content(
    monkeypatch: pytest.MonkeyPatch, fakes: dict[str, list[ExplanationEvidence]]
) -> None:
    secret = ParsedUrl(
        display=SECRET_URL,
        lookup=SECRET_URL,
        host_unicode="secret-host.example",
        punycode=None,
        scheme_assumed=False,
    )
    use_urls(monkeypatch, [secret])
    text = "Act now at secret-host.example, verify your password. Ref ZX-7731"
    await orchestrator.analyze_message(text, "sms", provider=FakeProvider())
    (evidence,) = fakes["evidence"]
    dumped = repr(evidence)
    for needle in ("secret-host", "ZX-7731", "token=abc", "Act now at", "verify your password"):
        assert needle not in dumped
    assert evidence.input_type == "message"
    assert {s.id for s in evidence.signals} >= {"urgency", "credential_request"}


async def test_explain_failure_falls_back_to_template(monkeypatch: pytest.MonkeyPatch) -> None:
    async def broken(evidence: ExplanationEvidence) -> Explanation:
        raise RuntimeError("boom")

    monkeypatch.setattr(orchestrator, "explain", broken)
    monkeypatch.setattr(orchestrator, "template_explanation", lambda evidence: "template text")
    result = await orchestrator.analyze_message("hi", "sms", provider=FakeProvider())
    assert result.explanation == Explanation(text="template text", source="template")


async def test_explain_and_template_failure_use_fixed_sentence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def broken(evidence: ExplanationEvidence) -> Explanation:
        raise RuntimeError("boom")

    def broken_template(evidence: ExplanationEvidence) -> str:
        raise RuntimeError("boom")

    monkeypatch.setattr(orchestrator, "explain", broken)
    monkeypatch.setattr(orchestrator, "template_explanation", broken_template)
    result = await orchestrator.analyze_message("hi", "sms", provider=FakeProvider())
    assert result.explanation.source == "template"
    assert (
        result.explanation.text == "This result is based on automated checks and may be incomplete."
    )


async def test_llm_prompt_version_flows_to_versions(monkeypatch: pytest.MonkeyPatch) -> None:
    async def llm(evidence: ExplanationEvidence) -> Explanation:
        return Explanation(text="x", source="llm", prompt_version="p-1")

    monkeypatch.setattr(orchestrator, "explain", llm)
    result = await orchestrator.analyze_message("hi", "sms", provider=FakeProvider())
    assert result.versions.prompt == "p-1"


# URL endpoint.


def submitted(*signals) -> SubmittedUrl:
    return SubmittedUrl(url=parsed("example.com"), signals=tuple(signals))


async def test_analyze_url_no_match() -> None:
    result = await orchestrator.analyze_url(submitted(), 11, provider=FakeProvider())
    assert result.input_type == "url"
    assert result.channel is None
    assert result.char_count == 11
    assert result.classifier.status == "not_applicable"
    assert result.risk_score is None
    assert result.url_check.urls_found == 1
    assert result.url_check.status == "no_match"
    assert result.classification == "likely_legitimate"
    assert "New scam sites are often not yet on reputation lists." in result.limitations
    assert not any("text model" in item for item in result.limitations)


async def test_analyze_url_provider_error_is_inconclusive() -> None:
    provider = FakeProvider(error=RuntimeError("x"))
    result = await orchestrator.analyze_url(submitted(), 5, provider=provider)
    assert result.classification == "inconclusive"
    assert result.url_check.urls[0].lookup.reason == "provider_error"
    assert result.url_check.provider == "fake"


async def test_analyze_url_flagged() -> None:
    provider = FakeProvider([UrlLookup(status="flagged", threat_types=("MALWARE",))])
    result = await orchestrator.analyze_url(submitted(), 5, provider=provider)
    assert result.classification == "high_risk"
    assert [s.id for s in result.signals] == ["url_reputation_flagged"]
    assert result.risk_score is None


async def test_analyze_url_rule_signal_makes_suspicious() -> None:
    lookalike = sig("brand_lookalike_host", "high", "url_rules")
    result = await orchestrator.analyze_url(submitted(lookalike), 5, provider=FakeProvider())
    assert result.classification == "suspicious"
    assert result.recommendations[0] == "Do not click the link."


async def test_real_none_provider_and_real_packages() -> None:
    intel = pytest.importorskip("app.pipeline.intel")
    provider = intel.NoneProvider()
    result = await orchestrator.analyze_url(submitted(), 11, provider=provider)
    assert result.url_check.provider == "none"
    assert result.url_check.status == "not_checked"
    assert result.url_check.urls[0].lookup.reason == "provider_not_configured"
    assert result.classification == "inconclusive"
    assert result.url_check.checked_at is None
    assert "Links were not checked against a reputation service." in result.limitations
