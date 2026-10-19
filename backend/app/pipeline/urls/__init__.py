"""URL parsing, normalization and rule signals.

Nothing in this package resolves a host name, opens a socket or fetches a URL.
"""

from app.pipeline.types import Signal, SubmittedUrl
from app.pipeline.urls.errors import InvalidUrlError, UnsupportedSchemeError
from app.pipeline.urls.extract import extract_urls
from app.pipeline.urls.parser import parse_parts, to_parsed_url
from app.pipeline.urls.rules import merge_signals, url_signals

# Bump when the brand list, distance limits, confusable map, shortener list, suffix
# list or any signal wording or severity changes.
URL_RULES_VERSION = "url-1.1"

__all__ = [
    "URL_RULES_VERSION",
    "InvalidUrlError",
    "UnsupportedSchemeError",
    "extract_urls",
    "parse_submitted_url",
]


def parse_submitted_url(value: str) -> SubmittedUrl:
    """Parse and normalize the single URL sent to the URL endpoint.

    `value` is already trimmed and length-checked by the caller.
    """
    parts = parse_parts(value)
    signals: tuple[Signal, ...] = merge_signals([url_signals(parts)])
    return SubmittedUrl(url=to_parsed_url(parts), signals=signals)
