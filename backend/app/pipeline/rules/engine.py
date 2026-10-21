"""Pattern rules over normalized message text.

Patterns are deliberately narrow: a phrase that legitimate mail also uses on its
own is paired with a second cue. Each signal appears at most once per message.
"""

import re

from app.pipeline.normalize import NormalizedText
from app.pipeline.types import MAX_EXCERPT_CODE_POINTS, Severity, Signal

# Bump when a pattern, description or severity changes.
RULES_VERSION = "rules-1.1"

_FLAGS = re.IGNORECASE
_MAX_CONTEXT = 25
_CLAUSE_LOOKBACK = 60
_CLAUSE_END = ".!?;\n"
_NEGATION = re.compile(
    r"\b(?:never|not|don'?t|doesn'?t|won'?t|cannot|can'?t|no one|nobody)\b|\bwill not\b|\bdo not\b",
    re.IGNORECASE,
)

_BRANDS = (
    r"paypal|amazon|apple|microsoft|google|netflix|facebook|instagram|whatsapp|dhl|fedex|ups"
    r"|usps|irs|hmrc|fbi|chase|wells ?fargo|bank of america|hsbc|coinbase|binance|linkedin"
)
_SECRETS = (
    r"password|passcode|pin|otp|one[- ]time (?:code|password|passcode)|verification code"
    r"|security code|cvv|card number|social security(?: number)?|ssn|bank details"
    r"|account number|login details|login credentials"
)


class _Rule:
    __slots__ = ("description", "id", "patterns", "severity", "skip_negated")

    def __init__(
        self,
        signal_id: str,
        severity: Severity,
        description: str,
        patterns: tuple[str, ...],
        *,
        skip_negated: bool = False,
    ) -> None:
        self.skip_negated = skip_negated
        self.id = signal_id
        self.severity = severity
        self.description = description
        self.patterns = tuple(re.compile(p, _FLAGS) for p in patterns)


_RULES = (
    _Rule(
        "credential_request",
        "high",
        "The message asks for a password, PIN, one-time code or similar private details.",
        (
            r"\b(?:enter|confirm|verify|provide|send|share|give|submit|"
            r"reply with|read out)\b[^.!?\n]{0,40}?\b(?:" + _SECRETS + r")\b",
            r"\byour (?:" + _SECRETS + r")\b[^.!?\n]{0,30}\b(?:is required|is needed|to continue"
            r"|to verify)\b",
        ),
        skip_negated=True,
    ),
    _Rule(
        "payment_request",
        "high",
        "The message asks for payment by gift card, cryptocurrency or wire transfer.",
        (
            # A request verb must come first, so a receipt for a wire transfer does not match.
            r"\b(?:send|pay|make|transfer|wire|buy|purchase|deposit)\b[^.!?\n]{0,40}?"
            r"\b(?:gift ?cards?|itunes cards?|google play cards?|steam cards?"
            r"|bitcoin|btc|ethereum|usdt|crypto(?:currency)?"
            r"|wire transfer|western union|moneygram)\b",
            r"\bwire (?:transfer )?(?:the |me |us )?(?:money|funds|fee|payment)\b",
            r"\bwire transfer (?:the|a|your|me|us)\b",
        ),
        skip_negated=True,
    ),
    _Rule(
        "urgency",
        "medium",
        "The message pressures you to act immediately.",
        (
            r"\b(?:act now|act immediately|immediate action|urgent(?:ly)?|final notice"
            r"|final warning|last chance|today only|respond immediately|verify immediately"
            r"|within \d{1,4} (?:hours?|minutes?|mins?)|expires? (?:today|tonight|soon)"
            r"|before it'?s too late|don'?t delay)\b",
        ),
    ),
    _Rule(
        "threat_or_penalty",
        "medium",
        "The message threatens a penalty, such as a locked account or legal action.",
        (
            r"\b(?:account|card|access|service)\b[^.!?\n]{0,30}\b(?:will be|has been|have been"
            r"|is|was)\s+(?:suspended|closed|locked|blocked|disabled|terminated|deactivated"
            r"|frozen|limited)\b",
            r"\b(?:legal action|arrest warrant|will be arrested|be prosecuted|criminal charges"
            r"|permanently (?:closed|deleted|banned))\b",
        ),
    ),
    _Rule(
        "prize_or_lottery",
        "medium",
        "The message says you won a prize or lottery.",
        (
            r"\byou(?:'ve| have)? (?:won|been selected)\b",
            r"\bcongratulations\b[^.!?\n]{0,40}\b(?:won|winner|prize|selected)\b",
            r"\b(?:lottery|sweepstakes?)\b",
            r"\bclaim your (?:prize|reward|winnings|gift)\b",
        ),
    ),
    _Rule(
        "brand_impersonation",
        "medium",
        "The message claims to come from a well-known company or agency.",
        (
            r"\b(?:this is|we are|from the|message from|calling from)\s+(?:the\s+)?(?:"
            + _BRANDS
            + r"|your bank)\b",
            r"\b(?:" + _BRANDS + r")\s+(?:security|support|customer (?:service|support)|billing"
            r"|fraud (?:team|department)|account team|team)\b",
        ),
    ),
    _Rule(
        "too_good_to_be_true",
        "medium",
        "The message promises easy money or guaranteed returns.",
        (
            r"\bguaranteed (?:returns?|income|profit)\b",
            # Every quantifier is bounded so a long digit or space run cannot backtrack badly.
            r"\b(?:earn|make)\s{1,5}\$?\d[\d,]{0,15}\s{0,3}(?:\w{1,15}\s{1,3}){0,2}"
            r"(?:per|a|every)\s{1,3}(?:day|week|hour)\b",
            r"\b(?:risk[- ]free|double your (?:money|investment)|get rich)\b",
            r"\b100% (?:free|guaranteed)\b",
        ),
    ),
)

_OBFUSCATION = Signal(
    id="obfuscation_chars",
    source="rules",
    severity="medium",
    description=(
        "The message contains hidden or look-alike characters that can disguise words or links."
    ),
    evidence_excerpt=None,
)


_ELLIPSIS = "..."


def _excerpt(features: str, start: int, end: int) -> str:
    """The match with a little context, cut only at whitespace and marked with "..." where cut."""
    cap = MAX_EXCERPT_CODE_POINTS
    matched = " ".join(features[start:end].split())
    more_before = bool(features[:start].strip())
    if len(matched) > cap - 2 * len(_ELLIPSIS):
        limit = cap - len(_ELLIPSIS) * (1 + more_before)
        piece = matched[:limit]
        if len(matched) > limit and matched[limit] != " " and " " in piece:
            piece = piece[: piece.rindex(" ")]
        left = _ELLIPSIS if more_before else ""
        return left + piece.rstrip() + _ELLIPSIS
    room = cap - 2 * len(_ELLIPSIS) - len(matched)
    after = min(len(features) - end, _MAX_CONTEXT, room // 2)
    before = min(start, _MAX_CONTEXT, room - after)
    after = min(len(features) - end, _MAX_CONTEXT, room - before)
    lo, hi = start - before, end + after
    if lo > 0 and not features[lo - 1].isspace() and not features[lo].isspace():
        gap = next((i for i in range(lo, start) if features[i].isspace()), None)
        lo = gap + 1 if gap is not None else start
    if hi < len(features) and not features[hi].isspace() and not features[hi - 1].isspace():
        gap = next((i for i in range(hi - 1, end - 1, -1) if features[i].isspace()), None)
        hi = gap if gap is not None else end
    text = " ".join(features[lo:hi].split())
    left = _ELLIPSIS if lo > 0 and features[:lo].strip() else ""
    right = _ELLIPSIS if hi < len(features) and features[hi:].strip() else ""
    return left + text + right


def _is_negated(features: str, start: int) -> bool:
    """True if a negation sits earlier in the same clause, as in "we never ask you to share"."""
    prefix = features[max(0, start - _CLAUSE_LOOKBACK) : start]
    cut = max(prefix.rfind(ch) for ch in _CLAUSE_END)
    return _NEGATION.search(prefix[cut + 1 :]) is not None


def _first_match(rule: _Rule, features: str) -> re.Match[str] | None:
    first: re.Match[str] | None = None
    for pattern in rule.patterns:
        for found in pattern.finditer(features):
            if rule.skip_negated and _is_negated(features, found.start()):
                continue
            if first is None or found.start() < first.start():
                first = found
            break
    return first


def evaluate(text: NormalizedText) -> tuple[Signal, ...]:
    signals: list[Signal] = []
    for rule in _RULES:
        first = _first_match(rule, text.features)
        if first is not None:
            signals.append(
                Signal(
                    id=rule.id,
                    source="rules",
                    severity=rule.severity,
                    description=rule.description,
                    evidence_excerpt=_excerpt(text.features, first.start(), first.end()),
                )
            )
    if text.obfuscated:
        signals.append(_OBFUSCATION)
    return tuple(signals)
