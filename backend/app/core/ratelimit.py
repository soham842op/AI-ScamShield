"""Fixed-window rate limiting.

The limiter never sees a raw IP: callers pass an HMAC of the client address (see
``client_hash``) and the keys stored in the database are built from that digest.
"""

import hashlib
import hmac
import ipaddress
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import Engine
from starlette.concurrency import run_in_threadpool

from app.db.repository import increment_rate_limit

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class Window:
    name: str
    seconds: int
    limit: int


@dataclass(frozen=True, slots=True)
class WindowStatus:
    name: str
    limit: int
    count: int
    # Seconds until the window resets, at least 1.
    reset: int

    @property
    def remaining(self) -> int:
        return max(self.limit - self.count, 0)

    @property
    def exceeded(self) -> bool:
        return self.count > self.limit


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    statuses: tuple[WindowStatus, ...]

    @property
    def allowed(self) -> bool:
        return not any(s.exceeded for s in self.statuses)

    @property
    def tightest(self) -> WindowStatus:
        # Smallest remaining; on a tie the smaller reset.
        return min(self.statuses, key=lambda s: (s.remaining, s.reset))

    @property
    def retry_after(self) -> int:
        exceeded = [s for s in self.statuses if s.exceeded]
        return max((s.reset for s in exceeded), default=0)

    def headers(self) -> dict[str, str]:
        tight = self.tightest
        headers = {
            "RateLimit-Limit": str(tight.limit),
            "RateLimit-Remaining": str(tight.remaining),
            "RateLimit-Reset": str(tight.reset),
        }
        if not self.allowed:
            headers["Retry-After"] = str(self.retry_after)
        return headers


class RateLimiter(Protocol):
    async def hit(self, scope: str, client: str, windows: Sequence[Window]) -> RateLimitDecision:
        """Count one request in every window, then report all of them.

        ``client`` is the hashed client id. Every window is incremented even when an
        earlier one is already over its limit.
        """
        ...


def window_bounds(now: datetime, seconds: int) -> tuple[datetime, int]:
    """Return (window start, seconds until the window ends) for a fixed window.

    Windows are aligned to the Unix epoch, so a day window starts at 00:00 UTC.
    """
    epoch = now.timestamp()
    start_epoch = math.floor(epoch / seconds) * seconds
    reset = max(math.ceil(start_epoch + seconds - epoch), 1)
    return datetime.fromtimestamp(start_epoch, UTC), reset


def limiter_key(scope: str, window: str, client: str) -> str:
    return f"{scope}:{window}:{client}"


class InMemoryRateLimiter:
    """For unit tests only. State is per process and is never shared or persisted."""

    def __init__(self, clock: Clock = utc_now) -> None:
        self._clock = clock
        self._counts: dict[tuple[str, datetime], int] = {}

    async def hit(self, scope: str, client: str, windows: Sequence[Window]) -> RateLimitDecision:
        now = self._clock()
        statuses: list[WindowStatus] = []
        for window in windows:
            start, reset = window_bounds(now, window.seconds)
            key = (limiter_key(scope, window.name, client), start)
            self._counts[key] = self._counts.get(key, 0) + 1
            statuses.append(WindowStatus(window.name, window.limit, self._counts[key], reset))
        return RateLimitDecision(tuple(statuses))


class PostgresRateLimiter:
    def __init__(self, get_engine: Callable[[], Engine], clock: Clock = utc_now) -> None:
        # The engine is resolved on use so the app can start without a database URL.
        self._get_engine = get_engine
        self._clock = clock

    def _hit_sync(self, scope: str, client: str, windows: Sequence[Window]) -> RateLimitDecision:
        now = self._clock()
        statuses: list[WindowStatus] = []
        # One short transaction, committed before the pipeline runs. It holds row locks
        # only for the duration of these upserts.
        with self._get_engine().begin() as conn:
            for window in windows:
                start, reset = window_bounds(now, window.seconds)
                count = increment_rate_limit(conn, limiter_key(scope, window.name, client), start)
                statuses.append(WindowStatus(window.name, window.limit, count, reset))
        return RateLimitDecision(tuple(statuses))

    async def hit(self, scope: str, client: str, windows: Sequence[Window]) -> RateLimitDecision:
        return await run_in_threadpool(self._hit_sync, scope, client, windows)


def resolve_client_ip(peer: str | None, forwarded_for: Sequence[str], hops: int) -> str:
    """Pick the client address.

    With ``hops == 0`` the socket peer is used and X-Forwarded-For is ignored, since
    anyone can send it. With N trusted proxies, the Nth entry from the right is the
    address the outermost trusted proxy saw. If the header is missing, has fewer than N
    entries, or that entry is not an IP address, the request did not come through the
    expected proxy chain, so the socket peer is the only value that can be trusted.
    """
    fallback = peer or "unknown"
    if hops <= 0:
        return fallback
    entries = [e.strip() for value in forwarded_for for e in value.split(",") if e.strip()]
    if len(entries) < hops:
        return fallback
    candidate = entries[-hops]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return fallback
    return candidate


def normalize_ip(value: str) -> str:
    """IPv4-mapped IPv6 becomes IPv4; IPv6 is reduced to its /64 network."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        # Not an address (for example a test client name). Hashed as given.
        return value
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address)
    return str(ip)


def client_hash(key: bytes, client_ip: str, scope: str) -> str:
    message = f"{normalize_ip(client_ip)}|{scope}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()
