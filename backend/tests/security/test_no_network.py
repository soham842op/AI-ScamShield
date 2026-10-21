"""Analysis never resolves or connects to a submitted host."""

import socket
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.security.conftest import MESSAGE, URL

LINKS = [
    "paypa1.example/login",
    "http://192.0.2.7/verify",
    "http://0x7f.1/x",
    "https://xn--pypal-4ve.example/",
    "https://user:pass@example.com/account",
    "http://bit.ly/abc123",
    "www.example.test/a?b=c",
]


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def blocked(name: str) -> Any:
        def raiser(*args: Any, **kwargs: Any) -> Any:
            calls.append(name)
            raise AssertionError(f"network call attempted: {name}")

        return raiser

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def is_loopback(address: Any) -> bool:
        # The event loop connects a loopback socket pair on Windows; that is not network use.
        return isinstance(address, tuple) and address[:1] in (("127.0.0.1",), ("::1",))

    def guarded(real: Any, name: str) -> Any:
        def wrapper(self: socket.socket, address: Any, *args: Any) -> Any:
            if is_loopback(address):
                return real(self, address, *args)
            calls.append(name)
            raise AssertionError(f"network call attempted: {name}")

        return wrapper

    monkeypatch.setattr(socket, "getaddrinfo", blocked("getaddrinfo"))
    monkeypatch.setattr(socket, "gethostbyname", blocked("gethostbyname"))
    monkeypatch.setattr(socket, "gethostbyname_ex", blocked("gethostbyname_ex"))
    monkeypatch.setattr(socket.socket, "connect", guarded(real_connect, "connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", guarded(real_connect_ex, "connect_ex"))
    return calls


def test_message_with_many_links(secure_client: TestClient, no_network: list[str]) -> None:
    text = "Please verify now: " + " and ".join(LINKS)
    response = secure_client.post(MESSAGE, json={"text": text, "channel": "sms"})
    assert response.status_code == 200
    assert response.json()["url_check"]["urls_found"] >= 5
    assert no_network == []


@pytest.mark.parametrize("link", LINKS)
def test_url_endpoint(secure_client: TestClient, no_network: list[str], link: str) -> None:
    response = secure_client.post(URL, json={"url": link})
    assert response.status_code == 200
    assert no_network == []
