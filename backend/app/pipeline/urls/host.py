"""Host normalization: IDNA (UTS-46), IPv4 in all browser forms, bracketed IPv6.

Pure string handling. Nothing here resolves a name or opens a socket.
"""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote

import idna

from app.pipeline.urls.errors import InvalidUrlError

_MAX_HOST_LENGTH = 253
_MAX_LABEL_LENGTH = 63
# Code points that may not appear in a host (after percent-decoding).
_FORBIDDEN_HOST_CHARS = frozenset("\x00\t\n\r #/:<>?@[\\]^|%")
_ASCII_LABEL = re.compile(r"[a-z0-9_-]+")
_HEX = re.compile(r"0[xX][0-9a-fA-F]*")
_OCTAL = re.compile(r"0[0-7]+")
_DECIMAL = re.compile(r"[0-9]+")


@dataclass(frozen=True, slots=True)
class NormalizedHost:
    # ASCII form, as sent to the provider and shown in the display string.
    ascii: str
    # Unicode form. Equal to `ascii` for plain ASCII hosts.
    unicode: str
    is_ip: bool


def normalize_host(raw: str) -> NormalizedHost:
    """Normalize the host part of a URL (no brackets for IPv6 here, no port)."""
    if raw.startswith("[") and raw.endswith("]"):
        return _normalize_ipv6(raw[1:-1])
    if "%" in raw:
        raw = unquote(raw)
    if not raw or any(ch in _FORBIDDEN_HOST_CHARS for ch in raw):
        raise InvalidUrlError("invalid host")
    try:
        mapped = idna.uts46_remap(raw, std3_rules=False, transitional=False).lower()
    except (idna.IDNAError, UnicodeError) as exc:
        raise InvalidUrlError("invalid host") from exc
    mapped = mapped.removesuffix(".")
    if not mapped:
        raise InvalidUrlError("invalid host")
    if any(ch in _FORBIDDEN_HOST_CHARS for ch in mapped):
        raise InvalidUrlError("invalid host")

    if _ends_in_number(mapped):
        ip = _parse_ipv4(mapped)
        return NormalizedHost(ascii=ip, unicode=ip, is_ip=True)
    return _normalize_domain(mapped)


def _normalize_ipv6(inner: str) -> NormalizedHost:
    # A zone id ("%eth0") is accepted by ipaddress but is not valid in a URL host.
    if "%" in inner or not inner:
        raise InvalidUrlError("invalid host")
    try:
        address = ipaddress.IPv6Address(inner)
    except ValueError as exc:
        raise InvalidUrlError("invalid host") from exc
    text = f"[{address.compressed}]"
    return NormalizedHost(ascii=text, unicode=text, is_ip=True)


def _normalize_domain(host: str) -> NormalizedHost:
    labels = host.split(".")
    if any(not label for label in labels):
        raise InvalidUrlError("invalid host")
    if host.isascii() and not any(label.startswith("xn--") for label in labels):
        # The idna package rejects "_" and a few other characters that browsers
        # accept in host names; check plain ASCII labels directly.
        for label in labels:
            if len(label) > _MAX_LABEL_LENGTH or not _ASCII_LABEL.fullmatch(label):
                raise InvalidUrlError("invalid host")
        if len(host) > _MAX_HOST_LENGTH:
            raise InvalidUrlError("invalid host")
        return NormalizedHost(ascii=host, unicode=host, is_ip=False)
    try:
        ascii_host = idna.encode(host, uts46=True, transitional=False).decode("ascii")
        unicode_host = idna.decode(ascii_host)
    except (idna.IDNAError, UnicodeError) as exc:
        raise InvalidUrlError("invalid host") from exc
    if len(ascii_host) > _MAX_HOST_LENGTH:
        raise InvalidUrlError("invalid host")
    return NormalizedHost(ascii=ascii_host, unicode=unicode_host.lower(), is_ip=False)


def _parse_number(part: str) -> int | None:
    if not part:
        return None
    if _HEX.fullmatch(part):
        return int(part[2:], 16) if len(part) > 2 else 0
    if _OCTAL.fullmatch(part):
        return int(part, 8)
    if _DECIMAL.fullmatch(part):
        return int(part, 10)
    return None


def _ends_in_number(host: str) -> bool:
    last = host.rsplit(".", 1)[-1]
    return _parse_number(last) is not None


def _parse_ipv4(host: str) -> str:
    parts = host.split(".")
    if len(parts) > 4:
        raise InvalidUrlError("invalid host")
    numbers: list[int] = []
    for part in parts:
        value = _parse_number(part)
        if value is None:
            raise InvalidUrlError("invalid host")
        numbers.append(value)
    if any(n > 255 for n in numbers[:-1]):
        raise InvalidUrlError("invalid host")
    if numbers[-1] >= 256 ** (5 - len(numbers)):
        raise InvalidUrlError("invalid host")
    total = numbers[-1]
    for index, value in enumerate(numbers[:-1]):
        total += value * 256 ** (3 - index)
    return str(ipaddress.IPv4Address(total))
