import re
import time

import pytest

from app.pipeline.normalize import normalize
from app.pipeline.rules import RULES_VERSION, evaluate
from app.pipeline.rules.engine import _RULES
from app.pipeline.types import MAX_EXCERPT_CODE_POINTS


def ids(text: str) -> set[str]:
    return {s.id for s in evaluate(normalize(text))}


POSITIVE = [
    ("credential_request", "Please verify your password at the link below."),
    ("credential_request", "Reply with the one-time code we sent you."),
    ("credential_request", "Enter your card number and CVV to continue."),
    ("payment_request", "Buy gift cards and send me the codes."),
    ("payment_request", "Please send bitcoin to this wallet."),
    ("payment_request", "Pay with Western Union today."),
    ("payment_request", "You must wire transfer the fee."),
    ("urgency", "Act now or lose the offer."),
    ("urgency", "Reply within 24 hours."),
    ("urgency", "FINAL NOTICE for your invoice."),
    ("threat_or_penalty", "Your account has been suspended."),
    ("threat_or_penalty", "We will take legal action against you."),
    ("prize_or_lottery", "Congratulations, you have won a new phone!"),
    ("prize_or_lottery", "Claim your prize today."),
    ("prize_or_lottery", "You were picked in the lottery draw."),
    ("brand_impersonation", "This is PayPal, we noticed a problem."),
    ("brand_impersonation", "Microsoft support needs remote access."),
    ("too_good_to_be_true", "Guaranteed returns on every deposit."),
    ("too_good_to_be_true", "Earn $500 a day from home."),
    ("too_good_to_be_true", "A risk-free investment."),
]


@pytest.mark.parametrize(("signal_id", "text"), POSITIVE)
def test_positive(signal_id: str, text: str) -> None:
    assert signal_id in ids(text)


NEGATIVE = [
    "We will never ask you to share your password or PIN.",
    "Do not share your one-time code with anyone.",
    "To reset your password, open the app and tap Settings.",
    "Your wire transfer of $120 has been received.",
    "Do not pay with gift cards; we never accept them.",
    "Lunch at noon tomorrow?",
    "Your package was delivered to the front desk.",
    "The password policy changed; see the handbook.",
    "I bought a gift for my sister.",
    "Meeting moved to 3pm, see you there.",
    "My bitcoin podcast is out tomorrow.",
    "We won the match yesterday!",
    "Thanks for your payment, receipt attached.",
]


@pytest.mark.parametrize("text", NEGATIVE)
def test_benign_text_raises_nothing(text: str) -> None:
    assert evaluate(normalize(text)) == ()


def test_severities_and_source() -> None:
    text = (
        "This is PayPal. Verify your password. Pay with Western Union. Act now! "
        "Your account is locked. You won the lottery. Guaranteed returns."
    )
    by_id = {s.id: s for s in evaluate(normalize(text))}
    assert by_id["credential_request"].severity == "high"
    assert by_id["payment_request"].severity == "high"
    for sid in ("urgency", "threat_or_penalty", "prize_or_lottery"):
        assert by_id[sid].severity == "medium"
    assert all(s.source == "rules" for s in by_id.values())
    assert all(s.description for s in by_id.values())


def test_one_signal_per_id() -> None:
    result = evaluate(normalize("Act now. Urgent. Final notice. Last chance."))
    assert [s.id for s in result].count("urgency") == 1


def test_excerpt_contains_match_with_original_case() -> None:
    result = evaluate(normalize("Hello. ACT NOW or lose it."))
    (signal,) = result
    assert signal.evidence_excerpt is not None
    assert "ACT NOW" in signal.evidence_excerpt


def test_excerpt_is_capped() -> None:
    text = "x" * 500 + " act now " + "y" * 500
    (signal,) = evaluate(normalize(text))
    assert signal.evidence_excerpt is not None
    assert len(signal.evidence_excerpt) <= MAX_EXCERPT_CODE_POINTS
    assert "act now" in signal.evidence_excerpt


def test_long_match_is_capped() -> None:
    text = "verify " + "a " * 20 + "password"
    for signal in evaluate(normalize(text)):
        assert signal.evidence_excerpt is None or len(signal.evidence_excerpt) <= 120


def test_obfuscation_signal_has_no_excerpt() -> None:
    (signal,) = evaluate(normalize("hel\u200blo"))
    assert signal.id == "obfuscation_chars"
    assert signal.evidence_excerpt is None
    assert signal.severity == "medium"


def test_zero_width_padding_does_not_hide_phrase() -> None:
    result = ids("a\u200bct n\u200bow please")
    assert {"urgency", "obfuscation_chars"} <= result


def test_fullwidth_text_is_folded() -> None:
    assert "urgency" in ids("ＡＣＴ ＮＯＷ")


def test_negation_only_covers_its_own_clause() -> None:
    text = "We never ask for codes. Now verify your password here."
    assert "credential_request" in ids(text)


def test_version_string() -> None:
    assert RULES_VERSION == "rules-1.1"


# Inputs built to make a careless pattern backtrack. Each is about 10,000 characters.
_ADVERSARIAL = {
    "digits": "earn " + "9" * 10_000,
    "dollar_digits": "make $" + "1" * 10_000 + " a",
    "comma_digits": "earn " + "9," * 5_000,
    "spaces": "earn" + " " * 10_000,
    "repeated_earn": "earn " * 2_000,
    "repeated_words": "a " * 5_000,
    "repeated_verify": "verify " * 1_400,
    "repeated_send": "send " * 2_000,
    "send_long_gap": "send " + "x" * 10_000 + " gift card",
    "your_secret": "your password " * 700,
    "account_chain": "account will be " * 600,
    "within_digits": "within " + "7" * 10_000,
    "congrats_gap": "congratulations " + "a " * 4_000,
    "newlines": "act now\n" * 1_200,
    "brand_prefix": "this is " * 1_200,
    "plain": "x" * 10_000,
}
_LIMIT_SECONDS = 0.05
# All rules together. Shared CI runners are several times slower than a laptop; a
# backtracking pattern still takes over a second on these inputs.
_EVALUATE_LIMIT_SECONDS = 0.25


def _timed(pattern: "re.Pattern[str]", features: str) -> float:
    start = time.perf_counter()
    list(pattern.finditer(features))
    return time.perf_counter() - start


@pytest.mark.parametrize("name", sorted(_ADVERSARIAL))
def test_no_pattern_backtracks_badly(name: str) -> None:
    features = normalize(_ADVERSARIAL[name]).features
    for rule in _RULES:
        for pattern in rule.patterns:
            elapsed = min(_timed(pattern, features) for _ in range(3))
            assert elapsed < _LIMIT_SECONDS, (name, rule.id, pattern.pattern[:40], elapsed)


@pytest.mark.parametrize("name", sorted(_ADVERSARIAL))
def test_evaluate_is_fast_on_adversarial_text(name: str) -> None:
    normalized = normalize(_ADVERSARIAL[name])
    # Best of three, so a busy machine does not fail the test.
    runs = []
    for _ in range(3):
        start = time.perf_counter()
        evaluate(normalized)
        runs.append(time.perf_counter() - start)
    assert min(runs) < _EVALUATE_LIMIT_SECONDS


def excerpt_of(text: str) -> str:
    signals = evaluate(normalize(text))
    excerpt = signals[0].evidence_excerpt
    assert excerpt is not None
    return excerpt


def test_excerpt_never_cuts_inside_a_word() -> None:
    text = (
        "URGENT: your account will be suspended today. Reply with the verification code "
        "and pay the release fee with a gift card at paypa1-secure.example/login now."
    )
    for signal in evaluate(normalize(text)):
        assert signal.evidence_excerpt is not None
        body = signal.evidence_excerpt.removeprefix("...").removesuffix("...")
        words = set(text.replace("-", " - ").split()) | set(text.split())
        assert all(word in words for word in body.split()), signal.evidence_excerpt
        assert len(signal.evidence_excerpt) <= MAX_EXCERPT_CODE_POINTS


def test_excerpt_marks_cuts_with_dots() -> None:
    text = "start " + "word " * 40 + "act now " + "word " * 40 + "end"
    excerpt = excerpt_of(text)
    assert excerpt.startswith("...")
    assert excerpt.endswith("...")
    assert "act now" in excerpt
    assert len(excerpt) <= MAX_EXCERPT_CODE_POINTS


def test_excerpt_has_no_dots_when_nothing_was_cut() -> None:
    assert excerpt_of("Act now or lose it.") == "Act now or lose it."


def test_excerpt_dots_only_on_cut_side() -> None:
    excerpt = excerpt_of("Act now " + "word " * 60)
    assert excerpt.startswith("Act now")
    assert excerpt.endswith("...")


def test_overlong_match_is_cut_at_a_word_with_dots() -> None:
    text = "verify " + "alpha " * 30 + "password"
    for signal in evaluate(normalize(text)):
        excerpt = signal.evidence_excerpt
        assert excerpt is not None
        assert len(excerpt) <= MAX_EXCERPT_CODE_POINTS
        assert excerpt.endswith("alpha...") or excerpt.endswith("password")


def test_single_huge_word_is_hard_cut() -> None:
    text = "verify " + "x" * 300 + " password"
    for signal in evaluate(normalize(text)):
        assert signal.evidence_excerpt is not None
        assert len(signal.evidence_excerpt) <= MAX_EXCERPT_CODE_POINTS


def test_match_stays_whole_in_excerpt() -> None:
    text = "q " * 30 + "Reply with the verification code" + " z" * 30
    assert "Reply with the verification code" in excerpt_of(text)
