"""Data types shared by the analysis pipeline modules.

Field names and values follow the v1 API contract. Changing any of them is a
contract change.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

InputType = Literal["message", "url"]
Channel = Literal["sms", "email", "chat", "social", "other"]
Classification = Literal["likely_legitimate", "suspicious", "high_risk", "inconclusive"]
ScoreType = Literal["heuristic", "calibrated_probability", "none"]
ScoreBasis = Literal["text_classifier"]
Severity = Literal["low", "medium", "high"]
SignalSource = Literal["rules", "classifier", "url_rules", "url_reputation"]
ClassifierStatus = Literal["ok", "unavailable", "not_applicable"]
ClassifierLabel = Literal["scam_like", "not_scam_like"]
UrlStatus = Literal["flagged", "no_match", "unknown", "not_checked"]
UrlReason = Literal[
    "provider_timeout", "provider_error", "provider_not_configured", "quota_exhausted"
]
UrlCheckStatus = Literal["flagged", "no_match", "inconclusive", "not_checked", "not_applicable"]
ExplanationSource = Literal["llm", "template"]

MAX_EXCERPT_CODE_POINTS = 120
MAX_URLS_ANALYZED = 10


@dataclass(frozen=True, slots=True)
class Signal:
    id: str
    source: SignalSource
    severity: Severity
    description: str
    # Shown to the user only. Never persisted, logged or sent to the LLM.
    evidence_excerpt: str | None = None


@dataclass(frozen=True, slots=True)
class ParsedUrl:
    # Normalized display string (the response's `url` field).
    display: str
    # Normalized form sent to the reputation provider: no userinfo, no fragment.
    lookup: str
    host_unicode: str
    punycode: str | None
    scheme_assumed: bool


@dataclass(frozen=True, slots=True)
class SubmittedUrl:
    """Result of parsing the single URL sent to the URL endpoint."""

    url: ParsedUrl
    # url_rules signals for this URL, including obfuscation_chars when format
    # characters were removed.
    signals: tuple[Signal, ...]


@dataclass(frozen=True, slots=True)
class UrlExtraction:
    """URLs found in message text."""

    # The first MAX_URLS_ANALYZED distinct URLs, in order of first appearance.
    urls: tuple[ParsedUrl, ...]
    # Distinct http(s) URLs found before truncation.
    urls_found: int
    truncated: bool
    # url_rules signals for the analyzed URLs, plus dangerous_scheme.
    signals: tuple[Signal, ...]


@dataclass(frozen=True, slots=True)
class UrlLookup:
    status: UrlStatus
    reason: UrlReason | None = None
    threat_types: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LookupBatch:
    # Provider id: "none", "google_safe_browsing" or "web_risk".
    provider: str
    # Same order and length as the URLs passed to the provider.
    results: tuple[UrlLookup, ...]
    # When the provider response was received; None if nothing was checked.
    checked_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class UrlEntry:
    url: ParsedUrl
    lookup: UrlLookup


@dataclass(frozen=True, slots=True)
class UrlCheck:
    status: UrlCheckStatus
    provider: str | None
    checked_at: datetime | None
    urls_found: int
    urls_truncated: bool
    urls: tuple[UrlEntry, ...]

    @property
    def urls_checked(self) -> int:
        return sum(1 for entry in self.urls if entry.lookup.status in ("flagged", "no_match"))


@dataclass(frozen=True, slots=True)
class ClassifierResult:
    status: ClassifierStatus
    label: ClassifierLabel | None = None
    raw_score: float | None = None


@dataclass(frozen=True, slots=True)
class EvidenceSignal:
    """A signal as the explanation service sees it: no excerpt."""

    id: str
    source: SignalSource
    severity: Severity
    description: str


@dataclass(frozen=True, slots=True)
class EvidenceUrl:
    """A URL result as the explanation service sees it: no URL or host."""

    status: UrlStatus
    reason: UrlReason | None
    threat_types: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExplanationEvidence:
    """Everything the explanation service may use. Holds no submitted content."""

    input_type: InputType
    classification: Classification
    classifier_status: ClassifierStatus
    signals: tuple[EvidenceSignal, ...]
    url_check_status: UrlCheckStatus
    urls: tuple[EvidenceUrl, ...]
    urls_truncated: bool


@dataclass(frozen=True, slots=True)
class Explanation:
    text: str
    source: ExplanationSource
    # Set only when source == "llm".
    prompt_version: str | None = None


@dataclass(frozen=True, slots=True)
class Versions:
    pipeline: str
    rules: str
    model: str | None = None
    prompt: str | None = None


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Pipeline output. The API layer maps it to the response and the stored record."""

    input_type: InputType
    channel: Channel | None
    # Code points of the analyzed input (after NFC for messages, after trimming for URLs).
    char_count: int
    classification: Classification
    risk_score: int | None
    score_type: ScoreType
    score_basis: ScoreBasis | None
    classifier: ClassifierResult
    signals: tuple[Signal, ...]
    url_check: UrlCheck
    explanation: Explanation
    recommendations: tuple[str, ...]
    limitations: tuple[str, ...]
    versions: Versions
    timings_ms: dict[str, int] = field(default_factory=dict)
