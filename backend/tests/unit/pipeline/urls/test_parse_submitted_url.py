import pytest

from app.pipeline.urls import InvalidUrlError, UnsupportedSchemeError, parse_submitted_url


def ids(value: str) -> set[str]:
    return {s.id for s in parse_submitted_url(value).signals}


@pytest.mark.parametrize(
    ("value", "display"),
    [
        ("http://example.com", "http://example.com/"),
        ("https://example.com/a/b?x=1&y=2", "https://example.com/a/b?x=1&y=2"),
        ("HTTPS://EXAMPLE.COM/Path", "https://example.com/Path"),
        ("http://example.com:80/x", "http://example.com/x"),
        ("https://example.com:443", "https://example.com/"),
        ("https://example.com:80/", "https://example.com:80/"),
        ("http://example.com/a#frag", "http://example.com/a"),
        ("http://example.com/a?q=1#frag", "http://example.com/a?q=1"),
        ("http://example.com?q=1", "http://example.com/?q=1"),
        ("http://user:pw@example.com/a", "http://example.com/a"),
        ("http://example.com/a%20b%2Fc", "http://example.com/a%20b%2Fc"),
        ("http://example.com.", "http://example.com/"),
        ("http:///example.com", "http://example.com/"),
        ("http://example.com\\path", "http://example.com/path"),
    ],
)
def test_normalized_display(value: str, display: str) -> None:
    result = parse_submitted_url(value)
    assert result.url.display == display
    assert result.url.lookup == display
    assert result.url.scheme_assumed is False


@pytest.mark.parametrize(
    ("value", "display", "host"),
    [
        ("paypa1.example/login", "http://paypa1.example/login", "paypa1.example"),
        ("www.example.com", "http://www.example.com/", "www.example.com"),
        ("example.com:8080/x", "http://example.com:8080/x", "example.com"),
        ("localhost:8080", "http://localhost:8080/", "localhost"),
        ("//example.com/x", "http://example.com/x", "example.com"),
        ("user:pw@example.com", "http://example.com/", "example.com"),
    ],
)
def test_scheme_assumed(value: str, display: str, host: str) -> None:
    result = parse_submitted_url(value)
    assert result.url.scheme_assumed is True
    assert result.url.display == display
    assert result.url.host_unicode == host


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com",
        "javascript:alert(1)",
        "JavaScript:alert(1)",
        "data:text/html,hello",
        "mailto:a@example.com",
        "file:///etc/passwd",
        "tel:123456",
        "sms:123456",
        "vbscript:x",
        "gopher://example.com",
    ],
)
def test_unsupported_scheme(value: str) -> None:
    with pytest.raises(UnsupportedSchemeError):
        parse_submitted_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "http://exa mple.com",
        "http://example.com/a b",
        "http://example.com/a\tb",
        "http://example.com/a\nb",
        "http://example.com/\x00",
        "http://example.com/\x01",
        "http://example.com/\x7f",
        "http://example.com/\x85",
        "http://example.com/\u00a0x",
        "http://example.com/　x",
        "http://",
        "http:///",
        "http://:80/",
        "http://@/",
        "http://example.com:abc/",
        "http://example.com:99999/",
        "http://example.com:0/",
        "http://example.com:-1/",
        "http://exa<mple.com",
        "http://a..b.com",
        "http://xn--/",
        "http://[::1/",
        "http://[::1]x/",
        "http://[::g]/",
        "http://[fe80::1%25eth0]/",
        "http://1.2.3.4.5/",
        "http://256.1.1.1/",
        "http://1.2.3.256/",
        "http://example.123/",
        "http://" + "a" * 64 + ".com/",
        "/just/a/path",
        "?q=1",
        "#frag",
        "",
        "   ",
        "\u200b",
    ],
)
def test_invalid(value: str) -> None:
    with pytest.raises(InvalidUrlError):
        parse_submitted_url(value)


@pytest.mark.parametrize(
    ("value", "host"),
    [
        ("http://0x7f.1/", "127.0.0.1"),
        ("http://0177.0.0.1/", "127.0.0.1"),
        ("http://2130706433/", "127.0.0.1"),
        ("http://127.1/", "127.0.0.1"),
        ("http://0x7f000001/", "127.0.0.1"),
        ("http://192.168.0.1/", "192.168.0.1"),
        ("http://169.254.169.254/latest", "169.254.169.254"),
        ("http://10.0.0.1./", "10.0.0.1"),
        ("http://１２７.0.0.1/", "127.0.0.1"),
    ],
)
def test_ipv4_forms_are_normalized(value: str, host: str) -> None:
    result = parse_submitted_url(value)
    assert result.url.host_unicode == host
    assert result.url.display.startswith(f"http://{host}")
    assert result.url.punycode is None
    assert "ip_literal_host" in {s.id for s in result.signals}


@pytest.mark.parametrize(
    ("value", "display"),
    [
        ("http://[::1]/", "http://[::1]/"),
        ("http://[0:0:0:0:0:0:0:1]:8080/x", "http://[::1]:8080/x"),
        ("https://[2001:DB8::1]:443/", "https://[2001:db8::1]/"),
        ("http://[::ffff:192.168.0.1]/", "http://[::ffff:192.168.0.1]/"),
        # The hex spelling of the same address gives the same dotted display.
        ("http://[::ffff:c0a8:1]/", "http://[::ffff:192.168.0.1]/"),
    ],
)
def test_ipv6_literals(value: str, display: str) -> None:
    result = parse_submitted_url(value)
    assert result.url.display == display
    assert "ip_literal_host" in {s.id for s in result.signals}


def test_idn_host_shows_punycode_in_display() -> None:
    result = parse_submitted_url("https://Bücher.example/x")
    assert result.url.display == "https://xn--bcher-kva.example/x"
    assert result.url.host_unicode == "bücher.example"
    assert result.url.punycode == "xn--bcher-kva.example"
    assert "punycode_host" in {s.id for s in result.signals}


def test_punycode_input_decodes_for_host_unicode() -> None:
    result = parse_submitted_url("http://xn--bcher-kva.example/")
    assert result.url.host_unicode == "bücher.example"
    assert result.url.punycode == "xn--bcher-kva.example"


def test_fullwidth_and_ideographic_dot_are_mapped() -> None:
    result = parse_submitted_url("http://ｅxample。com/")
    assert result.url.display == "http://example.com/"


def test_ascii_host_has_no_punycode() -> None:
    assert parse_submitted_url("http://example.com").url.punycode is None


def test_mixed_script_host_flags_punycode_host() -> None:
    # Cyrillic a in the first label.
    result = parse_submitted_url("http://exаmple.com/")
    assert "punycode_host" in {s.id for s in result.signals}
    assert result.url.display.startswith("http://xn--")
    assert result.url.punycode is not None


def test_underscore_host_is_allowed() -> None:
    assert parse_submitted_url("http://my_host.example/").url.host_unicode == "my_host.example"


def test_userinfo_is_removed_and_flagged() -> None:
    result = parse_submitted_url("https://paypal.com@evil.example/login")
    assert "@" not in result.url.display
    assert "@" not in result.url.lookup
    assert result.url.host_unicode == "evil.example"
    assert "url_userinfo" in {s.id for s in result.signals}


def test_empty_userinfo_is_still_flagged() -> None:
    assert "url_userinfo" in ids("http://@example.com/")


def test_last_at_sign_ends_userinfo() -> None:
    result = parse_submitted_url("http://a@b@example.com/")
    assert result.url.host_unicode == "example.com"


def test_backslash_does_not_hide_the_host() -> None:
    result = parse_submitted_url("http://evil.example\\@good.example/")
    assert result.url.host_unicode == "evil.example"
    assert "url_userinfo" not in ids("http://evil.example\\@good.example/")


def test_format_characters_are_removed_and_flagged() -> None:
    result = parse_submitted_url("http://pay\u200bpal.example/lo\u202egin")
    assert result.url.display == "http://paypal.example/login"
    obfuscation = next(s for s in result.signals if s.id == "obfuscation_chars")
    assert obfuscation.source == "url_rules"
    assert obfuscation.severity == "medium"
    assert obfuscation.evidence_excerpt is None


def test_no_obfuscation_signal_without_format_characters() -> None:
    assert "obfuscation_chars" not in ids("http://example.com/")


def test_plain_url_has_no_signals() -> None:
    assert parse_submitted_url("https://www.example.com/page?x=1").signals == ()


def test_signals_never_carry_excerpts_and_ids_are_unique() -> None:
    result = parse_submitted_url("http://user@bit.ly:8080/\u200bx")
    found = [s.id for s in result.signals]
    assert len(found) == len(set(found))
    assert all(s.evidence_excerpt is None and s.source == "url_rules" for s in result.signals)


def test_very_long_url_is_handled() -> None:
    result = parse_submitted_url("http://example.com/" + "a" * 2000)
    assert len(result.url.display) > 2000


@pytest.mark.parametrize(
    "value",
    ["http://\ud800.example/", "\ud800", "http://example.com/\udfff"],
)
def test_lone_surrogates_are_invalid_not_a_crash(value: str) -> None:
    with pytest.raises(InvalidUrlError):
        parse_submitted_url(value)
