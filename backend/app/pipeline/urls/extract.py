"""Find URLs in message text. String scanning only; nothing is resolved or fetched."""

import re

from app.pipeline.types import MAX_URLS_ANALYZED, ParsedUrl, Signal, UrlExtraction
from app.pipeline.urls.errors import InvalidUrlError, UnsupportedSchemeError
from app.pipeline.urls.parser import UrlParts, parse_parts, strip_format_chars, to_parsed_url
from app.pipeline.urls.rules import (
    DANGEROUS_SCHEME,
    is_known_public_suffix_host,
    merge_signals,
    url_signals,
)

MAX_CANDIDATE_LENGTH = 2048
MAX_CANDIDATES = 1000

# Whitespace and the characters that usually wrap a link end a token.
_TOKEN = re.compile(r'[^\s<>"]+')
_SCHEME_START = re.compile(r"https?://", re.IGNORECASE)
# "javascript:" counts only when code follows directly ("javascript:alert(1)"), not
# in prose such as "JavaScript: closures".
_DANGEROUS = re.compile(
    r"(?<![\w+.\-])(?:javascript:(?=\S)|data:(?:[a-z]+/[a-z0-9.+\-]+|[;,]))", re.IGNORECASE
)
# Common file extensions that are also real top-level domains.
_FILE_EXTENSION_TLDS = frozenset(
    {
        "zip",
        "mov",
        "py",
        "sh",
        "md",
        "exe",
        "bat",
        "jar",
        "rb",
        "cs",
        "js",
        "ts",
        "cpp",
        "tar",
        "gz",
        "txt",
        "doc",
        "docx",
        "xls",
        "pdf",
    }
)
_LEADING_PUNCTUATION = "([{<'\"`*_"
_TRAILING_PUNCTUATION = ".,;:!?)]}>'\"`*_\u2026\u201d\u2019\u00bb"
_PAIRS = {")": "(", "]": "[", "}": "{"}
_BARE_AUTHORITY = re.compile(r"[^/?#\\]+")
_BARE_HOST_PORT = re.compile(r"(?P<host>[^:@\[\]]+)(?::[0-9]{1,5})?")


def extract_urls(text: str) -> UrlExtraction:
    """Find http(s) URLs, `www.` tokens and bare domains in `text`.

    Never raises. Candidates that do not parse are skipped.
    """
    seen: dict[str, tuple[ParsedUrl, UrlParts]] = {}
    count = 0
    for token_match in _TOKEN.finditer(text):
        for candidate in _candidates(token_match.group()):
            count += 1
            if count > MAX_CANDIDATES:
                break
            try:
                parts = parse_parts(candidate)
            except (InvalidUrlError, UnsupportedSchemeError):
                continue
            parsed = to_parsed_url(parts)
            seen.setdefault(parsed.lookup, (parsed, parts))
        if count > MAX_CANDIDATES:
            break

    entries = list(seen.values())
    analyzed = entries[:MAX_URLS_ANALYZED]
    groups: list[tuple[Signal, ...]] = []
    if _DANGEROUS.search(text):
        groups.append((DANGEROUS_SCHEME,))
    groups.extend(url_signals(parts) for _, parts in analyzed)
    return UrlExtraction(
        urls=tuple(parsed for parsed, _ in analyzed),
        urls_found=len(entries),
        truncated=len(entries) > MAX_URLS_ANALYZED,
        signals=merge_signals(groups),
    )


def _candidates(token: str) -> list[str]:
    """Candidate URL strings found in one whitespace-delimited token."""
    starts = [m.start() for m in _SCHEME_START.finditer(token)]
    if not starts:
        return _bare_candidate(token)
    found: list[str] = []
    # Text before the first scheme ("(see:" or "www.a.com,") may hold a bare link.
    found.extend(_bare_candidate(token[: starts[0]]))
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(token)
        candidate = _trim(token[start:end])
        if 0 < len(candidate) <= MAX_CANDIDATE_LENGTH:
            found.append(candidate)
    return found


def _bare_candidate(piece: str) -> list[str]:
    candidate = _trim(piece.lstrip(_LEADING_PUNCTUATION))
    if not candidate or len(candidate) > MAX_CANDIDATE_LENGTH:
        return []
    cleaned = strip_format_chars(candidate)
    authority_match = _BARE_AUTHORITY.match(cleaned)
    if authority_match is None:
        return []
    host_match = _BARE_HOST_PORT.fullmatch(authority_match.group())
    # An "@" or a stray ":" in the authority means an email address or another scheme.
    if host_match is None:
        return []
    host = host_match.group("host").lower()
    if "." not in host or host.startswith(".") or host.endswith("."):
        return []
    if host.startswith("www."):
        return [candidate]
    if not is_known_public_suffix_host(host):
        return []
    last_label = host_match.group("host").rsplit(".", 1)[-1]
    # "today.Click": a sentence break with a missing space, not a domain.
    if last_label != last_label.lower() and last_label != last_label.upper():
        return []
    # "invoice.zip", "main.py": a file name, unless a path follows.
    if last_label.lower() in _FILE_EXTENSION_TLDS and not cleaned[authority_match.end() :]:
        return []
    return [candidate]


def _trim(value: str) -> str:
    """Drop trailing punctuation, keeping a closing bracket that has its opener."""
    end = len(value)
    # Skip the common case of a long run without slicing or re-counting.
    while end > 0 and value[end - 1] in _TRAILING_PUNCTUATION:
        last = value[end - 1]
        opener = _PAIRS.get(last)
        if opener is not None and value.count(opener, 0, end) >= value.count(last, 0, end):
            break
        end -= 1
    return value[:end]
