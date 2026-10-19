import time

import pytest

from app.pipeline.urls import extract_urls, parse_submitted_url

SIZE = 64 * 1024
INPUTS = {
    "dots": "." * SIZE,
    "www": "www." * (SIZE // 4),
    "a_dot": "a." * (SIZE // 2),
    "scheme": "http://" * (SIZE // 7),
    "at": "@" * SIZE,
    "hyphens": "a" + "-" * SIZE,
    "hyphen_pairs": "a-" * (SIZE // 2) + "com",
    "digits": "1" * SIZE,
    "digit_dots": "1." * (SIZE // 2),
    "parens": "(" * SIZE,
    "host_digits": "http://" + "9" * SIZE,
    "label_run": "http://" + "a" * SIZE + ".com",
    "long_bare": "a" * 100 + ("." + "b" * 100) * 600 + ".com",
}
LIMIT_SECONDS = 0.1


@pytest.mark.parametrize("name", sorted(INPUTS))
def test_extract_urls_is_fast(name: str) -> None:
    started = time.perf_counter()
    extract_urls(INPUTS[name])
    assert time.perf_counter() - started < LIMIT_SECONDS


@pytest.mark.parametrize("name", sorted(INPUTS))
def test_parse_submitted_url_is_fast(name: str) -> None:
    started = time.perf_counter()
    try:
        parse_submitted_url(INPUTS[name])
    except ValueError:
        pass
    assert time.perf_counter() - started < LIMIT_SECONDS
