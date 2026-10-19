"""URL reputation providers.

A provider receives normalized lookup URLs (no userinfo, no fragment) and returns
one result per URL. It is the only code that may contact an outside service.
"""

from collections.abc import Sequence
from typing import Protocol

from app.pipeline.types import LookupBatch, ParsedUrl, UrlLookup

__all__ = ["NoneProvider", "UrlReputationProvider", "get_provider"]


class UrlReputationProvider(Protocol):
    provider_id: str

    async def lookup(self, urls: Sequence[ParsedUrl]) -> LookupBatch: ...


class NoneProvider:
    """Used when no reputation service is configured: nothing is checked."""

    provider_id = "none"

    async def lookup(self, urls: Sequence[ParsedUrl]) -> LookupBatch:
        results = tuple(
            UrlLookup(status="not_checked", reason="provider_not_configured") for _ in urls
        )
        return LookupBatch(provider=self.provider_id, results=results, checked_at=None)


def get_provider(name: str) -> UrlReputationProvider:
    if name == "none":
        return NoneProvider()
    raise ValueError("unknown URL reputation provider")
