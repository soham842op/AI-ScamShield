import asyncio

import pytest

from app.pipeline.intel import NoneProvider, UrlReputationProvider, get_provider
from app.pipeline.types import ParsedUrl


def make_url(host: str) -> ParsedUrl:
    return ParsedUrl(
        display=f"http://{host}/",
        lookup=f"http://{host}/",
        host_unicode=host,
        punycode=None,
        scheme_assumed=False,
    )


def test_none_provider_marks_every_url_not_checked() -> None:
    provider = NoneProvider()
    batch = asyncio.run(provider.lookup([make_url("a.example"), make_url("b.example")]))
    assert batch.provider == "none"
    assert batch.checked_at is None
    assert len(batch.results) == 2
    for result in batch.results:
        assert result.status == "not_checked"
        assert result.reason == "provider_not_configured"
        assert result.threat_types == ()


def test_none_provider_with_no_urls() -> None:
    batch = asyncio.run(NoneProvider().lookup([]))
    assert batch.results == ()
    assert batch.provider == "none"


def test_provider_id() -> None:
    assert NoneProvider.provider_id == "none"
    assert NoneProvider().provider_id == "none"


def test_get_provider_none() -> None:
    provider = get_provider("none")
    assert isinstance(provider, NoneProvider)
    checked: UrlReputationProvider = provider
    assert checked.provider_id == "none"


@pytest.mark.parametrize("name", ["", "None", "google_safe_browsing", "web_risk", "other"])
def test_get_provider_rejects_other_names(name: str) -> None:
    with pytest.raises(ValueError, match="unknown"):
        get_provider(name)


def test_error_message_does_not_echo_the_name() -> None:
    with pytest.raises(ValueError) as info:
        get_provider("secret-name")
    assert "secret-name" not in str(info.value)
