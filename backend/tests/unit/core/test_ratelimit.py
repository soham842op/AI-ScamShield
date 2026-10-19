import asyncio
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.core import ratelimit
from app.core.ratelimit import (
    InMemoryRateLimiter,
    PostgresRateLimiter,
    RateLimitDecision,
    Window,
    WindowStatus,
    client_hash,
    normalize_ip,
    resolve_client_ip,
    window_bounds,
)

NOW = datetime(2026, 10, 19, 12, 0, 30, 250000, tzinfo=UTC)
WINDOWS = (Window("minute", 60, 3), Window("day", 86400, 5))


def test_window_bounds_minute_day_hour() -> None:
    start, reset = window_bounds(NOW, 60)
    assert start == datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
    assert reset == 30  # 29.75 seconds left, rounded up
    start, reset = window_bounds(NOW, 86400)
    assert start == datetime(2026, 10, 19, tzinfo=UTC)
    assert reset == 12 * 3600 - 30
    assert window_bounds(NOW, 3600)[0] == datetime(2026, 10, 19, 12, tzinfo=UTC)


def test_window_bounds_reset_at_least_one() -> None:
    almost = datetime(2026, 10, 19, 12, 0, 59, 999999, tzinfo=UTC)
    assert window_bounds(almost, 60)[1] == 1


def test_status_remaining_never_negative() -> None:
    status = WindowStatus("minute", 3, 9, 10)
    assert status.remaining == 0
    assert status.exceeded
    assert not WindowStatus("minute", 3, 3, 10).exceeded


def test_tightest_smallest_remaining_then_smaller_reset() -> None:
    decision = RateLimitDecision(
        (
            WindowStatus("a", 10, 2, 50),
            WindowStatus("b", 100, 98, 5000),
            WindowStatus("c", 4, 2, 20),
        )
    )
    # b and c both have 2 left; c resets sooner.
    assert decision.tightest.name == "c"
    assert decision.headers() == {
        "RateLimit-Limit": "4",
        "RateLimit-Remaining": "2",
        "RateLimit-Reset": "20",
    }


def test_retry_after_is_largest_reset_among_exceeded() -> None:
    decision = RateLimitDecision(
        (
            WindowStatus("minute", 10, 11, 40),
            WindowStatus("day", 100, 101, 7000),
            WindowStatus("x", 9, 1, 5),
        )
    )
    assert not decision.allowed
    assert decision.retry_after == 7000
    headers = decision.headers()
    assert headers["Retry-After"] == "7000"
    assert headers["RateLimit-Remaining"] == "0"
    # Tie on remaining 0: smaller reset is described.
    assert headers["RateLimit-Reset"] == "40"


def test_allowed_at_exact_limit() -> None:
    decision = RateLimitDecision((WindowStatus("minute", 3, 3, 10),))
    assert decision.allowed
    assert "Retry-After" not in decision.headers()
    assert decision.headers()["RateLimit-Remaining"] == "0"


def test_in_memory_counts_every_window_and_blocks() -> None:
    limiter = InMemoryRateLimiter(clock=lambda: NOW)

    async def run() -> list[RateLimitDecision]:
        return [await limiter.hit("analyze", "abc", WINDOWS) for _ in range(4)]

    decisions = asyncio.run(run())
    assert [d.allowed for d in decisions] == [True, True, True, False]
    assert [s.count for s in decisions[3].statuses] == [4, 4]


def test_in_memory_increments_all_windows_even_when_one_is_over() -> None:
    limiter = InMemoryRateLimiter(clock=lambda: NOW)
    windows = (Window("minute", 60, 1), Window("day", 86400, 100))

    async def run() -> RateLimitDecision:
        await limiter.hit("analyze", "abc", windows)
        return await limiter.hit("analyze", "abc", windows)

    decision = asyncio.run(run())
    assert [s.count for s in decision.statuses] == [2, 2]


def test_in_memory_new_window_resets() -> None:
    clock = {"now": NOW}
    limiter = InMemoryRateLimiter(clock=lambda: clock["now"])

    async def hit() -> RateLimitDecision:
        return await limiter.hit("analyze", "abc", WINDOWS)

    for _ in range(4):
        asyncio.run(hit())
    clock["now"] = NOW + timedelta(seconds=40)
    decision = asyncio.run(hit())
    assert decision.statuses[0].count == 1
    assert decision.statuses[1].count == 5


def test_in_memory_scopes_and_clients_are_separate() -> None:
    limiter = InMemoryRateLimiter(clock=lambda: NOW)

    async def run() -> list[int]:
        a = await limiter.hit("analyze", "c1", WINDOWS)
        b = await limiter.hit("feedback", "c1", WINDOWS)
        c = await limiter.hit("analyze", "c2", WINDOWS)
        return [a.statuses[0].count, b.statuses[0].count, c.statuses[0].count]

    assert asyncio.run(run()) == [1, 1, 1]


class _FakeConn:
    pass


class _FakeEngine:
    def __init__(self) -> None:
        self.began = 0
        self.committed = 0

    @contextmanager
    def begin(self) -> Iterator[_FakeConn]:
        self.began += 1
        yield _FakeConn()
        self.committed += 1


def test_postgres_limiter_uses_one_short_transaction(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = _FakeEngine()
    calls: list[tuple[str, datetime]] = []
    counts = {"n": 0}

    def fake_increment(conn: Any, key: str, window_start: datetime) -> int:
        assert isinstance(conn, _FakeConn)
        assert window_start.tzinfo is not None
        calls.append((key, window_start))
        counts["n"] += 1
        return counts["n"]

    monkeypatch.setattr(ratelimit, "increment_rate_limit", fake_increment)
    limiter = PostgresRateLimiter(lambda: engine, clock=lambda: NOW)  # type: ignore[arg-type,return-value]
    decision = asyncio.run(limiter.hit("analyze", "deadbeef", WINDOWS))
    assert engine.began == 1
    assert engine.committed == 1
    assert [k for k, _ in calls] == ["analyze:minute:deadbeef", "analyze:day:deadbeef"]
    assert calls[0][1] == datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
    assert calls[1][1] == datetime(2026, 10, 19, tzinfo=UTC)
    assert [s.count for s in decision.statuses] == [1, 2]


def test_postgres_limiter_error_propagates_and_does_not_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _FakeEngine()

    def boom(conn: Any, key: str, window_start: datetime) -> int:
        raise RuntimeError("down")

    monkeypatch.setattr(ratelimit, "increment_rate_limit", boom)
    limiter = PostgresRateLimiter(lambda: engine)  # type: ignore[arg-type,return-value]
    with pytest.raises(RuntimeError):
        asyncio.run(limiter.hit("analyze", "x", WINDOWS))
    assert engine.committed == 0


def test_postgres_limiter_resolves_engine_lazily() -> None:
    def no_engine() -> Any:
        raise AssertionError("must not be called at construction")

    PostgresRateLimiter(no_engine)


@pytest.mark.parametrize(
    ("peer", "xff", "hops", "expected"),
    [
        ("10.0.0.1", ["1.1.1.1"], 0, "10.0.0.1"),
        ("10.0.0.1", [], 1, "10.0.0.1"),
        ("10.0.0.1", ["1.1.1.1"], 1, "1.1.1.1"),
        ("10.0.0.1", ["9.9.9.9, 1.1.1.1"], 1, "1.1.1.1"),
        ("10.0.0.1", ["9.9.9.9, 1.1.1.1, 2.2.2.2"], 2, "1.1.1.1"),
        ("10.0.0.1", ["9.9.9.9", "1.1.1.1"], 2, "9.9.9.9"),
        ("10.0.0.1", ["1.1.1.1"], 2, "10.0.0.1"),
        ("10.0.0.1", ["not-an-ip"], 1, "10.0.0.1"),
        ("10.0.0.1", ["1.1.1.1, garbage"], 1, "10.0.0.1"),
        ("10.0.0.1", ["2001:db8::1"], 1, "2001:db8::1"),
        (None, [], 0, "unknown"),
    ],
)
def test_resolve_client_ip(peer: str | None, xff: Sequence[str], hops: int, expected: str) -> None:
    assert resolve_client_ip(peer, xff, hops) == expected


def test_normalize_ip() -> None:
    assert normalize_ip("203.0.113.7") == "203.0.113.7"
    assert normalize_ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd") == "2001:db8:1:2::"
    assert normalize_ip("2001:db8:1:2::1") == normalize_ip("2001:db8:1:2:ffff::9")
    assert normalize_ip("2001:db8:1:3::1") != normalize_ip("2001:db8:1:2::1")
    assert normalize_ip("::ffff:203.0.113.7") == "203.0.113.7"
    assert normalize_ip("testclient") == "testclient"


def test_client_hash() -> None:
    key = b"k" * 32
    digest = client_hash(key, "203.0.113.7", "analyze")
    assert len(digest) == 64
    assert "203.0.113.7" not in digest
    assert digest == client_hash(key, "203.0.113.7", "analyze")
    assert digest != client_hash(key, "203.0.113.7", "feedback")
    assert digest != client_hash(b"other" * 8, "203.0.113.7", "analyze")
    assert client_hash(key, "2001:db8:1:2::1", "analyze") == client_hash(
        key, "2001:db8:1:2::2", "analyze"
    )
