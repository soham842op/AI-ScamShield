"""Builders shared by the pipeline unit tests."""

from typing import Any

from app.pipeline.types import (
    ClassifierResult,
    ParsedUrl,
    Severity,
    Signal,
    SignalSource,
    UrlEntry,
    UrlLookup,
)

CLASSIFIER_NA = ClassifierResult(status="not_applicable")
CLASSIFIER_DOWN = ClassifierResult(status="unavailable")


def parsed(host: str = "example.com") -> ParsedUrl:
    return ParsedUrl(
        display=f"http://{host}/",
        lookup=f"http://{host}/",
        host_unicode=host,
        punycode=None,
        scheme_assumed=False,
    )


def entry(status: str, reason: str | None = None, host: str = "example.com") -> UrlEntry:
    threats = ("SOCIAL_ENGINEERING",) if status == "flagged" else ()
    kwargs: dict[str, Any] = {"status": status, "reason": reason, "threat_types": threats}
    return UrlEntry(url=parsed(host), lookup=UrlLookup(**kwargs))


def sig(signal_id: str, severity: Severity = "medium", source: SignalSource = "rules") -> Signal:
    return Signal(id=signal_id, source=source, severity=severity, description=f"d {signal_id}")
