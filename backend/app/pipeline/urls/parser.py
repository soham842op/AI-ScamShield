"""Parse and normalize one URL string. Pure string handling, no network access."""

import re
import unicodedata
from dataclasses import dataclass

from app.pipeline.types import ParsedUrl
from app.pipeline.urls.errors import InvalidUrlError, UnsupportedSchemeError
from app.pipeline.urls.host import NormalizedHost, normalize_host

_DEFAULT_PORTS = {"http": 80, "https": 443}
_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*):")
_PORT_REST = re.compile(r"[0-9]+(?:[/\\?#]|$)")
_PORT = re.compile(r"[0-9]{1,5}")
_AUTHORITY_END = re.compile(r"[/\\?#]")
_OTHER_SCHEMES = frozenset(
    {"javascript", "data", "mailto", "tel", "sms", "file", "ftp", "vbscript", "blob", "about"}
)


@dataclass(frozen=True, slots=True)
class UrlParts:
    """Normalized pieces of a URL, used by the rules and the extractor."""

    scheme: str
    host: NormalizedHost
    # Explicit port that differs from the scheme default; None otherwise.
    port: int | None
    has_userinfo: bool
    path: str
    query: str
    scheme_assumed: bool
    # True when format characters (category Cf) were removed from the input.
    format_chars_removed: bool


def strip_format_chars(value: str) -> str:
    return "".join(ch for ch in value if unicodedata.category(ch) != "Cf")


def parse_parts(value: str) -> UrlParts:
    """Parse `value` into normalized parts.

    Raises InvalidUrlError or UnsupportedSchemeError, never anything else.
    """
    try:
        return _parse_parts(value)
    except (InvalidUrlError, UnsupportedSchemeError):
        raise
    except (UnicodeError, ValueError, IndexError) as exc:
        raise InvalidUrlError("unparseable URL") from exc


def _parse_parts(value: str) -> UrlParts:
    cleaned = strip_format_chars(value)
    removed = cleaned != value
    if removed:
        cleaned = cleaned.strip()
    if not cleaned:
        raise InvalidUrlError("empty URL")
    for ch in cleaned:
        category = unicodedata.category(ch)
        if category in ("Cc", "Zs", "Zl", "Zp") or ch.isspace():
            raise InvalidUrlError("whitespace or control character")
        if category == "Cs":
            raise InvalidUrlError("invalid unicode")

    scheme, rest, assumed = _split_scheme(cleaned)
    if assumed:
        # "//host/path" without a scheme is still a host.
        rest = rest[2:] if rest.startswith("//") else rest
    else:
        rest = rest.lstrip("/\\")

    end = _AUTHORITY_END.search(rest)
    authority = rest[: end.start()] if end else rest
    tail = rest[end.start() :] if end else ""

    fragment_at = tail.find("#")
    if fragment_at >= 0:
        tail = tail[:fragment_at]
    query = ""
    query_at = tail.find("?")
    if query_at >= 0:
        query = tail[query_at + 1 :]
        tail = tail[:query_at]
    path = tail.replace("\\", "/") or "/"

    # The last "@" ends the userinfo, as browsers read it.
    has_userinfo = "@" in authority
    hostport = authority.rsplit("@", 1)[-1]
    host_text, port = _split_port(hostport)
    if not host_text:
        raise InvalidUrlError("missing host")
    host = normalize_host(host_text)

    explicit_port = None if port is None or port == _DEFAULT_PORTS[scheme] else port
    return UrlParts(
        scheme=scheme,
        host=host,
        port=explicit_port,
        has_userinfo=has_userinfo,
        path=path,
        query=query,
        scheme_assumed=assumed,
        format_chars_removed=removed,
    )


def _split_scheme(value: str) -> tuple[str, str, bool]:
    """Return (scheme, remainder, scheme_assumed)."""
    match = _SCHEME.match(value)
    if match is not None:
        name = match.group(1)
        lowered = name.lower()
        rest = value[match.end() :]
        if rest.startswith(("//", "\\\\")):
            return _check_scheme(name), rest, False
        # "example.com:8080/x", "localhost:8080" and "user:pw@host" are host forms,
        # not schemes. Well-known non-web schemes are never read that way.
        if lowered not in _OTHER_SCHEMES and (
            _PORT_REST.match(rest) or "." in name or "@" in _AUTHORITY_END.split(rest, 1)[0]
        ):
            return "http", value, True
        return _check_scheme(name), rest, False
    return "http", value, True


def _check_scheme(name: str) -> str:
    lowered = name.lower()
    if lowered not in _DEFAULT_PORTS:
        raise UnsupportedSchemeError("unsupported scheme")
    return lowered


def _split_port(hostport: str) -> tuple[str, int | None]:
    if hostport.startswith("["):
        close = hostport.find("]")
        if close < 0:
            raise InvalidUrlError("invalid host")
        host_text = hostport[: close + 1]
        after = hostport[close + 1 :]
        if after and not after.startswith(":"):
            raise InvalidUrlError("invalid host")
        port_text = after[1:]
    else:
        host_text, sep, port_text = hostport.rpartition(":")
        if not sep:
            host_text, port_text = hostport, ""
        elif ":" in host_text:
            raise InvalidUrlError("invalid host")
    if not port_text:
        return host_text, None
    if not _PORT.fullmatch(port_text):
        raise InvalidUrlError("invalid port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise InvalidUrlError("invalid port")
    return host_text, port


def to_parsed_url(parts: UrlParts) -> ParsedUrl:
    host = parts.host.ascii
    port = f":{parts.port}" if parts.port is not None else ""
    query = f"?{parts.query}" if parts.query else ""
    normalized = f"{parts.scheme}://{host}{port}{parts.path}{query}"
    punycode = parts.host.ascii if parts.host.ascii != parts.host.unicode else None
    return ParsedUrl(
        display=normalized,
        lookup=normalized,
        host_unicode=parts.host.unicode,
        punycode=punycode,
        scheme_assumed=parts.scheme_assumed,
    )
