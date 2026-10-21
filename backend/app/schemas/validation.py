"""Shared checks for request strings.

Each failure is a ``PydanticCustomError`` whose type is the issue name that appears in
``details[].issue``. Messages never contain the submitted value.
"""

import unicodedata
from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import PlainSerializer, WithJsonSchema
from pydantic_core import PydanticCustomError

MAX_TEXT_CODE_POINTS = 10000
MAX_URL_CODE_POINTS = 2048


def require_str(value: Any) -> str:
    """Accept only a real string without lone surrogates."""
    if not isinstance(value, str):
        raise PydanticCustomError("invalid_type", "Value must be a string.")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate, for example from the JSON escape "\ud800".
        raise PydanticCustomError("invalid_unicode", "Value is not valid Unicode.") from None
    return value


def check_length(value: str, limit: int) -> None:
    if len(value) > limit:
        raise PydanticCustomError("max_length", "Value is too long.", {"limit": limit})


def clean_text(value: Any) -> str:
    text = unicodedata.normalize("NFC", require_str(value))
    if not text:
        raise PydanticCustomError("min_length", "Value must not be empty.")
    if "\x00" in text:
        raise PydanticCustomError("nul_character", "Value contains a NUL character.")
    if not text.strip():
        raise PydanticCustomError("whitespace_only", "Value contains only whitespace.")
    check_length(text, MAX_TEXT_CODE_POINTS)
    return text


def clean_url(value: Any) -> str:
    url = require_str(value).strip()
    if not url:
        raise PydanticCustomError("min_length", "Value must not be empty.")
    check_length(url, MAX_URL_CODE_POINTS)
    return url


def _format_utc(value: datetime) -> str:
    """ISO-8601 UTC with milliseconds and a Z suffix. A naive value is taken to be UTC."""
    value = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return f"{value:%Y-%m-%dT%H:%M:%S}.{value.microsecond // 1000:03d}Z"


# Pydantic would otherwise write microseconds.
UtcTimestamp = Annotated[
    datetime,
    PlainSerializer(_format_utc, return_type=str, when_used="json"),
    WithJsonSchema({"type": "string", "format": "date-time"}),
]
