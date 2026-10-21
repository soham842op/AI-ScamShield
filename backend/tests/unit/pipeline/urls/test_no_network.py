import socket
from typing import Any, NoReturn

import pytest

from app.pipeline.urls import (
    InvalidUrlError,
    UnsupportedSchemeError,
    extract_urls,
    parse_submitted_url,
)

SAMPLES = [
    "http://example.com/",
    "http://169.254.169.254/latest/meta-data",
    "http://127.0.0.1:8080/",
    "http://[::1]/",
    "http://localhost/",
    "http://metadata.google.internal/",
    "http://user:pw@internal.example/",
    "http://bücher.example/",
    "http://xn--bcher-kva.example/",
    "paypa1.example/login",
    "http://2130706433/",
    "http://10.0.0.1:22/",
]


class NetworkUsed(AssertionError):
    pass


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> NoReturn:
        raise NetworkUsed("network access attempted")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "gethostbyname", boom)
    monkeypatch.setattr(socket, "gethostbyname_ex", boom)
    monkeypatch.setattr(socket, "gethostbyaddr", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket.socket, "connect_ex", boom)


def test_parse_submitted_url_never_touches_the_network(no_network: None) -> None:
    for sample in SAMPLES:
        try:
            parse_submitted_url(sample)
        except (InvalidUrlError, UnsupportedSchemeError):
            pass


def test_extract_urls_never_touches_the_network(no_network: None) -> None:
    text = " ".join(SAMPLES) + " www.example.com example.org/x bit.ly/y john@example.com"
    result = extract_urls(text)
    assert result.urls_found > 0


def test_url_packages_do_not_import_network_modules() -> None:
    import ast
    import pathlib

    import app.pipeline.intel as intel
    import app.pipeline.urls as urls

    banned = {"socket", "http", "httpx", "requests", "aiohttp", "ssl", "asyncio"}
    for package in (urls, intel):
        for path in pathlib.Path(package.__file__ or "").parent.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    assert name.split(".")[0] not in banned, (path.name, name)
                    assert name != "urllib.request", (path.name, name)
