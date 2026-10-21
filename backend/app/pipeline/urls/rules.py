"""URL rule signals. These look at the string only; the URL is never fetched."""

from collections.abc import Iterable

from publicsuffixlist import PublicSuffixList

from app.pipeline.types import Severity, Signal
from app.pipeline.urls.brands import (
    BRANDS,
    MIN_SUBDOMAIN_BRAND_LENGTH,
    MIN_TOKEN_BRAND_LENGTH,
    REAL_DOMAINS,
    has_phishing_keyword,
    is_tld_like,
    label_matches_brand,
    token_matches_brand,
)
from app.pipeline.urls.parser import UrlParts

# Bundled list, read once at import. It is never downloaded.
_PSL = PublicSuffixList(only_icann=True)

SHORTENER_DOMAINS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "bit.do",
        "tinyurl.com",
        "tiny.cc",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "v.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
        "rb.gy",
        "t.ly",
        "lnkd.in",
        "s.id",
        "adf.ly",
        "trib.al",
        "qr.net",
    }
)

SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {"zip", "mov", "top", "xyz", "click", "country", "kim", "work", "gq", "tk", "ml", "cf", "ga"}
)

_MIN_EXCESSIVE_SUBDOMAIN_LABELS = 4

_OBFUSCATION = Signal(
    id="obfuscation_chars",
    source="url_rules",
    severity="medium",
    description="The link contains hidden or invisible characters.",
)
_USERINFO = Signal(
    id="url_userinfo",
    source="url_rules",
    severity="high",
    description="The link has a user name or password before the host, which can disguise "
    "where it really goes.",
)
_BRAND_LOOKALIKE = Signal(
    id="brand_lookalike_host",
    source="url_rules",
    severity="high",
    description="The link's domain looks like a well-known brand's but is not one of the "
    "brand's known domains.",
)
_IP_HOST = Signal(
    id="ip_literal_host",
    source="url_rules",
    severity="medium",
    description="The link points to a numeric IP address instead of a domain name.",
)
_PUNYCODE = Signal(
    id="punycode_host",
    source="url_rules",
    severity="medium",
    description="The link's domain uses non-Latin or look-alike characters that can imitate "
    "another domain.",
)
_SHORTENER = Signal(
    id="url_shortener",
    source="url_rules",
    severity="low",
    description="The link uses a URL shortener, which hides the real destination.",
)
_PORT = Signal(
    id="unusual_port",
    source="url_rules",
    severity="low",
    description="The link uses an unusual network port.",
)
_TLD = Signal(
    id="suspicious_tld",
    source="url_rules",
    severity="low",
    description="The link ends in a domain suffix that is often used for throwaway sites.",
)
_SUBDOMAINS = Signal(
    id="excessive_subdomains",
    source="url_rules",
    severity="low",
    description="The link's domain has an unusually long chain of subdomains.",
)
DANGEROUS_SCHEME = Signal(
    id="dangerous_scheme",
    source="url_rules",
    severity="high",
    description="The text contains a link that runs code or embeds data instead of opening "
    "a web page.",
)

_SEVERITY_RANK: dict[Severity, int] = {"low": 0, "medium": 1, "high": 2}


def url_signals(parts: UrlParts) -> tuple[Signal, ...]:
    """Signals for one parsed URL, in registry order."""
    found: list[Signal] = []
    if parts.format_chars_removed:
        found.append(_OBFUSCATION)
    if parts.has_userinfo:
        found.append(_USERINFO)

    host = parts.host
    registrable: str | None = None
    if not host.is_ip:
        registrable = _registrable(host.unicode)
        if registrable is not None and _is_brand_lookalike(host.unicode, registrable):
            found.append(_BRAND_LOOKALIKE)
    if host.is_ip:
        found.append(_IP_HOST)
    if not host.is_ip and _is_punycode_host(host.ascii, host.unicode):
        found.append(_PUNYCODE)
    if registrable is not None and registrable in SHORTENER_DOMAINS:
        found.append(_SHORTENER)
    if parts.port is not None:
        found.append(_PORT)
    if not host.is_ip and host.unicode.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        found.append(_TLD)
    if registrable is not None and _subdomain_count(host.unicode, registrable) >= (
        _MIN_EXCESSIVE_SUBDOMAIN_LABELS
    ):
        found.append(_SUBDOMAINS)
    return tuple(found)


def merge_signals(groups: Iterable[Iterable[Signal]]) -> tuple[Signal, ...]:
    """One signal per id: keep the highest severity, the first on a tie.

    Order follows first appearance, which is registry order within one URL.
    """
    merged: dict[str, Signal] = {}
    for group in groups:
        for signal in group:
            current = merged.get(signal.id)
            if (
                current is None
                or _SEVERITY_RANK[signal.severity] > _SEVERITY_RANK[current.severity]
            ):
                merged[signal.id] = signal
    return tuple(merged.values())


def is_known_public_suffix_host(host: str) -> bool:
    """True if the last label of `host` is a known ICANN public suffix."""
    return _PSL.publicsuffix(host, accept_unknown=False) is not None


def _registrable(host: str) -> str | None:
    # An unknown last label (".example", ".test") is treated as the suffix, so
    # reserved test names still get the rules. None for a single-label host.
    return _PSL.privatesuffix(host)


def _subdomain_count(host: str, registrable: str) -> int:
    if host == registrable:
        return 0
    return len(host.removesuffix("." + registrable).split("."))


def _is_punycode_host(ascii_host: str, unicode_host: str) -> bool:
    if not unicode_host.isascii():
        return True
    return any(label.startswith("xn--") for label in ascii_host.split("."))


def _is_brand_lookalike(host: str, registrable: str) -> bool:
    if registrable in REAL_DOMAINS:
        return False
    suffix = _PSL.publicsuffix(host) or ""
    label = registrable.removesuffix("." + suffix) if suffix else registrable
    subdomain_labels = [item for item in host.removesuffix(registrable).split(".") if item]
    tokens = [token for token in label.split("-") if token]
    keyword = has_phishing_keyword(host)
    for brand in BRANDS:
        if label_matches_brand(label, brand):
            return True
        long_enough = len(brand.label) >= MIN_TOKEN_BRAND_LENGTH
        if (long_enough or keyword) and any(token_matches_brand(t, brand) for t in tokens):
            return True
        sub_long_enough = len(brand.label) >= MIN_SUBDOMAIN_BRAND_LENGTH
        for index, item in enumerate(subdomain_labels):
            if not token_matches_brand(item, brand):
                continue
            # "paypal.com.evil.example": the brand is followed by a suffix-like label.
            followed_by_suffix = index + 1 < len(subdomain_labels) and is_tld_like(
                subdomain_labels[index + 1]
            )
            if sub_long_enough or keyword or followed_by_suffix:
                return True
    return False
