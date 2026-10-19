"""Fixed recommendation and limitation strings.

Nothing here is generated from submitted content. Wording never says that
something is safe.
"""

from collections.abc import Iterable

from app.pipeline.types import (
    MAX_URLS_ANALYZED,
    Classification,
    ClassifierStatus,
    InputType,
    UrlCheck,
)

NOT_A_GUARANTEE = (
    "A risk assessment is not a guarantee. A low rating is not proof that content is legitimate."
)
LIMIT_NOT_CONFIGURED = "Links were not checked against a reputation service."
LIMIT_PROVIDER_FAILED = (
    "The URL could not be checked because the reputation provider did not respond."
)
LIMIT_QUOTA = "Some links were not checked because the reputation service limit was reached."
LIMIT_TRUNCATED = f"Only the first {MAX_URLS_ANALYZED} links were analyzed."
LIMIT_NO_MODEL = "The text model is not available, so this result is based on rules only."
LIMIT_NEW_SITES = "New scam sites are often not yet on reputation lists."

REC_DO_NOT_CLICK = "Do not click the link."
REC_CREDENTIALS = "Do not share passwords, PINs or one-time codes."
REC_PAYMENT = (
    "Do not send money, gift cards or cryptocurrency to someone who contacted you unexpectedly."
)
REC_PRIZE = "Do not pay a fee to claim a prize or winnings."
REC_TOO_GOOD = "Be wary of offers that promise guaranteed returns or easy money."
REC_OBFUSCATION = (
    "Hidden or look-alike characters can disguise words and links, so treat this with extra care."
)
REC_PRESSURE = "Be wary of pressure to act immediately."
REC_OFFICIAL = (
    "Contact the organization through its official website or a known, trusted phone number."
)

_CLASSIFICATION_REC: dict[Classification, str] = {
    "high_risk": "Do not reply to this or act on it.",
    "suspicious": "Verify the sender through an official channel before acting.",
    "inconclusive": "Do not rely on this result. Verify the sender through an official channel.",
    "likely_legitimate": (
        "Still verify the sender through an official channel before sharing information or money."
    ),
}

# Ordered: this is the order recommendations appear in.
_SIGNAL_RECS: tuple[tuple[frozenset[str], str], ...] = (
    (
        frozenset(
            {
                "url_reputation_flagged",
                "brand_lookalike_host",
                "url_userinfo",
                "dangerous_scheme",
                "punycode_host",
            }
        ),
        REC_DO_NOT_CLICK,
    ),
    (frozenset({"credential_request"}), REC_CREDENTIALS),
    (frozenset({"payment_request"}), REC_PAYMENT),
    (frozenset({"prize_or_lottery"}), REC_PRIZE),
    (frozenset({"too_good_to_be_true"}), REC_TOO_GOOD),
    (frozenset({"obfuscation_chars"}), REC_OBFUSCATION),
    (frozenset({"urgency", "threat_or_penalty"}), REC_PRESSURE),
    (
        frozenset(
            {"brand_impersonation", "brand_lookalike_host", "credential_request", "payment_request"}
        ),
        REC_OFFICIAL,
    ),
)


def build_recommendations(
    classification: Classification, signal_ids: Iterable[str]
) -> tuple[str, ...]:
    ids = set(signal_ids)
    result: list[str] = []
    for trigger, text in _SIGNAL_RECS:
        if ids & trigger and text not in result:
            result.append(text)
    result.append(_CLASSIFICATION_REC[classification])
    return tuple(result)


def build_limitations(
    *,
    input_type: InputType,
    classification: Classification,
    classifier_status: ClassifierStatus,
    url_check: UrlCheck,
) -> tuple[str, ...]:
    reasons = {entry.lookup.reason for entry in url_check.urls}
    result = [NOT_A_GUARANTEE]
    if "provider_not_configured" in reasons:
        result.append(LIMIT_NOT_CONFIGURED)
    if reasons & {"provider_timeout", "provider_error"}:
        result.append(LIMIT_PROVIDER_FAILED)
    if "quota_exhausted" in reasons:
        result.append(LIMIT_QUOTA)
    if url_check.urls_truncated:
        result.append(LIMIT_TRUNCATED)
    if input_type == "message" and classifier_status == "unavailable":
        result.append(LIMIT_NO_MODEL)
    if classification == "likely_legitimate" and any(
        entry.lookup.status == "no_match" for entry in url_check.urls
    ):
        result.append(LIMIT_NEW_SITES)
    return tuple(result)
