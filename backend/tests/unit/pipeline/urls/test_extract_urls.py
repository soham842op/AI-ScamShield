import time

import pytest

from app.pipeline.urls import extract_urls


def displays(text: str) -> list[str]:
    return [u.display for u in extract_urls(text).urls]


def signal_ids(text: str) -> set[str]:
    return {s.id for s in extract_urls(text).signals}


def test_no_urls() -> None:
    result = extract_urls("Hello, your parcel is on the way.")
    assert result.urls == ()
    assert result.urls_found == 0
    assert result.truncated is False
    assert result.signals == ()


def test_empty_text() -> None:
    assert extract_urls("").urls_found == 0


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("see http://example.com/a for info", ["http://example.com/a"]),
        ("see HTTPS://Example.com/A", ["https://example.com/A"]),
        ("go to www.example.com now", ["http://www.example.com/"]),
        ("go to example.com now", ["http://example.com/"]),
        ("go to example.com/login now", ["http://example.com/login"]),
        ("go to example.co.uk/x", ["http://example.co.uk/x"]),
        ("visit sub.example.org:8080/p", ["http://sub.example.org:8080/p"]),
        ("bit.ly/3abc", ["http://bit.ly/3abc"]),
        ("tabs\tand\nnewlines http://a.example/x\nhttp://b.example/y", None),
    ],
)
def test_finds_urls(text: str, expected: list[str] | None) -> None:
    found = displays(text)
    if expected is None:
        assert found == ["http://a.example/x", "http://b.example/y"]
    else:
        assert found == expected


def test_scheme_assumed_flag() -> None:
    result = extract_urls("http://a.example and b.com and www.c.example")
    assert [u.scheme_assumed for u in result.urls] == [False, True, True]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Visit http://example.com.", "http://example.com/"),
        ("Visit http://example.com/a, then", "http://example.com/a"),
        ("Visit (http://example.com/a).", "http://example.com/a"),
        ("Visit <http://example.com/a>", "http://example.com/a"),
        ("Visit http://example.com/a!?", "http://example.com/a"),
        ('Say "http://example.com/a"', "http://example.com/a"),
        ("[click](http://example.com/a)", "http://example.com/a"),
        ("http://example.com/a;", "http://example.com/a"),
        ("http://example.com/a…", "http://example.com/a"),
        ("http://example.com/wiki/Foo_(bar)", "http://example.com/wiki/Foo_(bar)"),
        ("(http://example.com/wiki/Foo_(bar))", "http://example.com/wiki/Foo_(bar)"),
        ("http://example.com/a?x=1&y=2.", "http://example.com/a?x=1&y=2"),
    ],
)
def test_trailing_punctuation(text: str, expected: str) -> None:
    assert displays(text) == [expected]


def test_adjacent_urls_without_space() -> None:
    assert displays("http://a.example/x,http://b.example/y") == [
        "http://a.example/x",
        "http://b.example/y",
    ]


@pytest.mark.parametrize(
    "text",
    [
        "mail john@example.com please",
        "john.doe@mail.example.com",
        "file.txt and notes.docx and a.b",
        "version 1.2.3 and 10.0",
        "e.g. this and i.e. that",
        "see Mr.Smith",
        "mailto:john@example.com",
        "tel:+15551234567",
        "call 555.123.4567",
        "price is 3.50",
        "ftp://example.com/x",
    ],
)
def test_non_urls_are_ignored(text: str) -> None:
    result = extract_urls(text)
    assert result.urls == ()
    assert result.urls_found == 0


def test_mailto_and_tel_do_not_add_signals() -> None:
    assert extract_urls("mailto:a@example.com tel:+15550001111").signals == ()


def test_unknown_suffix_bare_token_is_rejected_but_www_is_kept() -> None:
    assert displays("config.zzzz") == []
    assert displays("www.config.zzzz") == ["http://www.config.zzzz/"]


@pytest.mark.parametrize(
    "text", ["click javascript:alert(1)", "JAVASCRIPT:void(0)", "(javascript:x)"]
)
def test_javascript_scheme_adds_signal_only(text: str) -> None:
    result = extract_urls(text)
    assert "dangerous_scheme" in {s.id for s in result.signals}
    assert result.urls_found == 0


def test_data_scheme_adds_signal_once() -> None:
    result = extract_urls("data:text/html;base64,AAAA and data:text/plain,hi")
    found = [s.id for s in result.signals]
    assert found.count("dangerous_scheme") == 1
    assert result.urls_found == 0


@pytest.mark.parametrize("text", ["Metadata: abc", "data: 5 items", "the data:", "xjavascript:"])
def test_dangerous_scheme_has_no_false_positive_on_prose(text: str) -> None:
    assert "dangerous_scheme" not in signal_ids(text)


def test_dangerous_scheme_severity() -> None:
    signal = extract_urls("javascript:alert(1)").signals[0]
    assert (signal.id, signal.source, signal.severity) == ("dangerous_scheme", "url_rules", "high")
    assert signal.evidence_excerpt is None


def test_dedupe_by_normalized_lookup() -> None:
    result = extract_urls(
        "http://Example.com/a http://example.com/a http://example.com:80/a#frag "
        "http://user@example.com/a http://example.com/b"
    )
    assert [u.display for u in result.urls] == ["http://example.com/a", "http://example.com/b"]
    assert result.urls_found == 2


def test_order_of_first_appearance() -> None:
    assert displays("http://c.example/ http://a.example/ http://b.example/ http://c.example/") == [
        "http://c.example/",
        "http://a.example/",
        "http://b.example/",
    ]


def test_ten_urls_not_truncated() -> None:
    text = " ".join(f"http://h{i}.example/" for i in range(10))
    result = extract_urls(text)
    assert len(result.urls) == 10
    assert result.urls_found == 10
    assert result.truncated is False


def test_eleven_urls_truncated() -> None:
    text = " ".join(f"http://h{i}.example/" for i in range(11))
    result = extract_urls(text)
    assert len(result.urls) == 10
    assert result.urls_found == 11
    assert result.truncated is True
    assert result.urls[0].display == "http://h0.example/"
    assert result.urls[-1].display == "http://h9.example/"


def test_signals_come_only_from_analyzed_urls() -> None:
    text = " ".join(f"http://h{i}.example/" for i in range(10)) + " http://u@x.example/"
    result = extract_urls(text)
    assert result.truncated is True
    assert "url_userinfo" not in {s.id for s in result.signals}


def test_signals_are_merged_one_per_id() -> None:
    result = extract_urls("bit.ly/a tinyurl.com/b http://paypa1.example/ http://paypal.top/")
    found = [s.id for s in result.signals]
    assert len(found) == len(set(found))
    assert {"url_shortener", "brand_lookalike_host", "suspicious_tld"} <= set(found)


def test_urls_in_message_get_url_rules() -> None:
    assert "brand_lookalike_host" in signal_ids("Log in at paypal-secure.com/login now")
    assert "ip_literal_host" in signal_ids("go to http://192.168.0.1/admin")
    assert "url_userinfo" in signal_ids("go to http://paypal.com@evil.example/")


def test_invalid_candidates_are_skipped_without_error() -> None:
    result = extract_urls("http:// http://[bad http://a..b/ http://ok.example/")
    assert [u.display for u in result.urls] == ["http://ok.example/"]


def test_format_characters_inside_url_are_flagged() -> None:
    result = extract_urls("open http://pay\u200bpal.example/x")
    assert [u.display for u in result.urls] == ["http://paypal.example/x"]
    assert "obfuscation_chars" in {s.id for s in result.signals}


def test_odd_input_never_raises() -> None:
    odd = [
        "\x00",
        "\ud800 http://example.com",
        "http://\ud800.example/",
        "\u202e" * 50,
        "http://" * 100,
        "www." * 100,
        "[" * 500 + "http://a.example/" + ")" * 500,
        ":" * 1000,
        "@" * 1000,
        "a.b.c.d.e.f" * 100,
        "http://" + "а" * 3000 + ".example",
    ]
    for text in odd:
        result = extract_urls(text)
        assert result.urls_found >= 0


def test_very_long_input_is_fast() -> None:
    started = time.perf_counter()
    for text in [
        "a" * 100_000,
        "a." * 50_000,
        "http://" + "a" * 100_000,
        ("word " * 20_000) + "http://example.com",
        "(" * 100_000,
        "http://a.example/ " * 20_000,
        "x.com " * 50_000,
    ]:
        extract_urls(text)
    assert time.perf_counter() - started < 5


def test_candidate_cap_stops_scanning() -> None:
    text = " ".join(f"h{i}.com" for i in range(5000))
    result = extract_urls(text)
    assert result.urls_found <= 1000
    assert result.truncated is True


def test_overlong_candidate_is_ignored() -> None:
    assert displays("http://example.com/" + "a" * 3000) == []
    assert displays("http://example.com/" + "a" * 2000) != []


@pytest.mark.parametrize(
    "text",
    [
        "JavaScript: closures are useful",
        "Topics today: JavaScript: closures, promises.",
        "Learn javascript: the basics",
        "myjavascript:alert",
        "Metadata:x",
    ],
)
def test_dangerous_scheme_ignores_prose(text: str) -> None:
    assert "dangerous_scheme" not in signal_ids(text)


def test_dangerous_scheme_requires_code_right_after() -> None:
    assert "dangerous_scheme" in signal_ids("click JavaScript:alert(1)")


@pytest.mark.parametrize(
    "text",
    [
        "Attached is invoice.zip",
        "see main.py",
        "run setup.sh now",
        "read notes.md",
        "video.mov",
        "See you today.Click the button",
        "the work.Live long",
    ],
)
def test_file_names_and_typos_are_not_links(text: str) -> None:
    assert extract_urls(text).urls_found == 0


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("example.com/path", "http://example.com/path"),
        ("paypa1-secure.com", "http://paypa1-secure.com/"),
        ("https://x.zip", "https://x.zip/"),
        ("www.x.zip", "http://www.x.zip/"),
        ("get invoice.zip/download", "http://invoice.zip/download"),
        ("EXAMPLE.COM", "http://example.com/"),
        ("paypal-login.app", "http://paypal-login.app/"),
        ("shop.pl", "http://shop.pl/"),
        ("promo.cc", "http://promo.cc/"),
    ],
)
def test_real_links_are_still_found(text: str, expected: str) -> None:
    assert expected in displays(text)
