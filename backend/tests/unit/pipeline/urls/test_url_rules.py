import pytest

from app.pipeline.urls import parse_submitted_url
from app.pipeline.urls.brands import BRANDS, REAL_DOMAINS, damerau_levenshtein, skeleton


def ids(value: str) -> set[str]:
    return {s.id for s in parse_submitted_url(value).signals}


def severity(value: str, signal_id: str) -> str:
    return next(s.severity for s in parse_submitted_url(value).signals if s.id == signal_id)


@pytest.mark.parametrize(
    ("value", "signal_id", "level"),
    [
        ("http://u@example.com/", "url_userinfo", "high"),
        ("http://paypa1.example/", "brand_lookalike_host", "high"),
        ("http://1.2.3.4/", "ip_literal_host", "medium"),
        ("http://xn--bcher-kva.example/", "punycode_host", "medium"),
        ("http://bit.ly/x", "url_shortener", "low"),
        ("http://example.com:8080/", "unusual_port", "low"),
        ("http://example.top/", "suspicious_tld", "low"),
        ("http://a.b.c.d.example.com/", "excessive_subdomains", "low"),
    ],
)
def test_signal_positive_and_severity(value: str, signal_id: str, level: str) -> None:
    assert signal_id in ids(value)
    assert severity(value, signal_id) == level


@pytest.mark.parametrize(
    ("value", "signal_id"),
    [
        ("http://example.com/", "url_userinfo"),
        ("http://example.com/", "ip_literal_host"),
        ("http://example.com/", "punycode_host"),
        ("http://example.com/", "url_shortener"),
        ("http://example.com:80/", "unusual_port"),
        ("https://example.com:443/", "unusual_port"),
        ("http://example.com/", "suspicious_tld"),
        ("http://a.b.c.example.com/", "excessive_subdomains"),
        ("http://example.com/top", "suspicious_tld"),
        ("http://mybit.ly.example.com/", "url_shortener"),
        ("http://notbit.ly/", "url_shortener"),
    ],
)
def test_signal_negative(value: str, signal_id: str) -> None:
    assert signal_id not in ids(value)


def test_unusual_port_for_other_scheme_default() -> None:
    assert "unusual_port" in ids("https://example.com:80/")
    assert "unusual_port" in ids("http://example.com:443/")


@pytest.mark.parametrize("tld", ["zip", "mov", "top", "xyz", "click", "country", "kim", "work"])
def test_suspicious_tld_list(tld: str) -> None:
    assert "suspicious_tld" in ids(f"http://example.{tld}/")


def test_suspicious_tld_ignores_ip_hosts() -> None:
    assert "suspicious_tld" not in ids("http://1.2.3.4/")


def test_shortener_subdomain_matches_registrable_domain() -> None:
    assert "url_shortener" in ids("http://www.bit.ly/x")
    assert "url_shortener" in ids("https://tinyurl.com/abc")


def test_excessive_subdomains_counts_labels_before_registrable_domain() -> None:
    assert "excessive_subdomains" not in ids("http://a.b.c.example.co.uk/")
    assert "excessive_subdomains" in ids("http://a.b.c.d.example.co.uk/")


@pytest.mark.parametrize(
    "host",
    [
        "paypa1.example",
        "paypai.example",
        "paypall.example",
        "paypal.example",
        "paypa.example",
        "pyapal.example",
        "paypal.top",
        "arnazon.example",
        "amaz0n.example",
        "rnicrosoft.example",
        "micr0soft.example",
        "g00gle.example",
        "faceb00k.example",
        "netfl1x.example",
        "app1e.example",
        "wellsfarg0.example",
        "bankofamerlca.example",
        "binanse.example",
        "paypal-secure.example",
        "secure-paypal-login.example",
        "apple-id-support.example",
        "paypa1-secure.example",
        "paypal.com.account-verify.example",
        "paypal.evil.example",
        "login.microsoft.com.evil.example",
        "www.amazon.co.uk.evil.example",
        "dhl-login.example",
        "ups-login.example",
        "apple-verify.example",
        "xn--pypal-4ve.example",
    ],
)
def test_brand_lookalike_positive(host: str) -> None:
    assert "brand_lookalike_host" in ids(f"http://{host}/")


def test_brand_lookalike_cyrillic_skeleton() -> None:
    # Cyrillic a and p letters in "paypal".
    assert "brand_lookalike_host" in ids("http://pаypаl.example/")
    assert "brand_lookalike_host" in ids("http://рaypal.example/")


@pytest.mark.parametrize(
    "host",
    [
        "paypal.com",
        "www.paypal.com",
        "www.paypal.co.uk",
        "history.paypal.com",
        "apple.com",
        "support.apple.com",
        "www.icloud.com",
        "amazon.com",
        "smile.amazon.com",
        "www.amazon.co.uk",
        "amazon.de",
        "microsoft.com",
        "outlook.com",
        "login.live.com",
        "www.office.com",
        "google.com",
        "accounts.google.com",
        "mail.google.co.uk",
        "netflix.com",
        "facebook.com",
        "m.facebook.com",
        "instagram.com",
        "web.whatsapp.com",
        "dhl.com",
        "fedex.com",
        "ups.com",
        "usps.com",
        "chase.com",
        "wellsfargo.com",
        "bankofamerica.com",
        "hsbc.co.uk",
        "coinbase.com",
        "binance.com",
        "linkedin.com",
        "www.linkedin.com",
    ],
)
def test_real_brand_domains_are_not_flagged(host: str) -> None:
    assert "brand_lookalike_host" not in ids(f"https://{host}/")


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "www.example.com",
        "wikipedia.org",
        "github.com",
        "apply.example",
        "ample.example",
        "phase.example",
        "example.co.uk",
        "chasing.example",
        "support.example.com",
    ],
)
def test_unrelated_hosts_are_not_flagged(host: str) -> None:
    assert "brand_lookalike_host" not in ids(f"http://{host}/")


def test_every_listed_real_domain_is_clean() -> None:
    for domain in sorted(REAL_DOMAINS):
        assert "brand_lookalike_host" not in ids(f"https://www.{domain}/"), domain


def test_brand_list_shape() -> None:
    assert len(BRANDS) == 20
    assert len({b.label for b in BRANDS}) == 20
    for brand in BRANDS:
        assert brand.label == brand.label.lower()
        assert brand.domains


def test_brand_check_skips_ip_hosts() -> None:
    assert "brand_lookalike_host" not in ids("http://192.168.0.1/paypal")


def test_distance_and_skeleton_helpers() -> None:
    assert damerau_levenshtein("paypal", "paypal") == 0
    assert damerau_levenshtein("paypal", "paypa1") == 1
    assert damerau_levenshtein("paypal", "pyapal") == 1
    assert damerau_levenshtein("paypal", "payal") == 1
    assert damerau_levenshtein("kitten", "sitting") == 3
    assert skeleton("paypa1") == skeleton("paypal")
    assert skeleton("rnicrosoft") == skeleton("microsoft")
    assert skeleton("vvhatsapp") == skeleton("whatsapp")
    assert skeleton("g00gle") == skeleton("google")


def test_distance_threshold_depends_on_label_length() -> None:
    # "paypal" (6): one edit matches, two do not.
    assert "brand_lookalike_host" in ids("http://paypa.example/")
    assert "brand_lookalike_host" not in ids("http://payp.example/")
    # "linkedin" (8): two edits match.
    assert "brand_lookalike_host" in ids("http://linkdin.example/")
    assert "brand_lookalike_host" in ids("http://linkdinn.example/")
    # "apple" (5): only the skeleton, so ordinary words nearby stay clean.
    assert "brand_lookalike_host" not in ids("http://apply.example/")
    assert "brand_lookalike_host" in ids("http://app1e.example/")


@pytest.mark.parametrize(
    "host",
    [
        "pop-ups.example",
        "start-ups.example",
        "ups.example.com",
        "chase-law.example",
        "big-apple-pizza.example",
        "amazon-rainforest.example",
        "finance.example",
        "goggle.example",
        "whatsup.example",
    ],
)
def test_common_words_near_brands_are_not_flagged(host: str) -> None:
    assert "brand_lookalike_host" not in ids(f"http://{host}/")


@pytest.mark.parametrize(
    "host",
    [
        "google.ie",
        "google.pl",
        "google.nl",
        "google.es",
        "google.it",
        "google.com.au",
        "google.co.in",
        "google.com.br",
        "amazon.co.za",
        "amazon.com.au",
        "amazon.nl",
        "amazon.pl",
        "amazon.se",
        "amazon.com.br",
        "amazon.in",
        "amazon.sg",
        "apple.news",
    ],
)
def test_more_country_domains_are_not_flagged(host: str) -> None:
    assert "brand_lookalike_host" not in ids(f"https://{host}/")


def test_description_does_not_claim_a_real_domain() -> None:
    signal = next(
        s
        for s in parse_submitted_url("http://paypa1.example/").signals
        if s.id == "brand_lookalike_host"
    )
    assert "known domains" in signal.description
    assert "real domain" not in signal.description


def test_cyrillic_apple_lookalike() -> None:
    host = "аррӏе.com"
    assert "brand_lookalike_host" in ids(f"http://{host}/")
    assert "punycode_host" in ids(f"http://{host}/")
