"""Collaborators of the API layer, gathered in one object so tests can replace them."""

import logging
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

import psycopg
from sqlalchemy import Engine
from sqlalchemy.exc import InvalidRequestError, SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from app.core.errors import ApiError
from app.core.ratelimit import RateLimiter
from app.db.engine import get_engine
from app.db.repository import (
    AnalysisRecord,
    FeedbackResult,
    insert_analysis_record,
    insert_feedback,
)
from app.pipeline.intel import UrlReputationProvider
from app.pipeline.orchestrator import analyze_message, analyze_url
from app.pipeline.types import AnalysisResult

logger = logging.getLogger("scamshield")

RETRY_AFTER_SECONDS = "30"


def database_engine() -> Engine:
    """The shared engine. A missing database URL counts as a database failure (503)."""
    try:
        return get_engine()
    except RuntimeError:
        raise InvalidRequestError("database is not configured") from None


@contextmanager
def fail_closed() -> Iterator[None]:
    """Turn a database failure into 503. Only the exception type is logged."""
    try:
        yield
    except (SQLAlchemyError, psycopg.Error) as exc:
        logger.error("database unavailable type=%s", type(exc).__name__)
        raise ApiError(503, headers={"Retry-After": RETRY_AFTER_SECONDS}) from None


class Persistence(Protocol):
    async def save_analysis(self, record: AnalysisRecord) -> None: ...

    async def save_feedback(
        self, request_id: UUID, helpful: bool, verdict: str | None
    ) -> FeedbackResult: ...


class PostgresPersistence:
    def __init__(self, get_engine: Callable[[], Engine]) -> None:
        # Resolved on use so the app can start without a database URL.
        self._get_engine = get_engine

    def _save_analysis_sync(self, record: AnalysisRecord) -> None:
        with self._get_engine().begin() as conn:
            insert_analysis_record(conn, record)

    def _save_feedback_sync(
        self, request_id: UUID, helpful: bool, verdict: str | None
    ) -> FeedbackResult:
        with self._get_engine().begin() as conn:
            return insert_feedback(conn, request_id, helpful, verdict)

    async def save_analysis(self, record: AnalysisRecord) -> None:
        await run_in_threadpool(self._save_analysis_sync, record)

    async def save_feedback(
        self, request_id: UUID, helpful: bool, verdict: str | None
    ) -> FeedbackResult:
        return await run_in_threadpool(self._save_feedback_sync, request_id, helpful, verdict)


@dataclass(frozen=True, slots=True)
class Pipeline:
    """The analysis entry points. Replaceable in tests."""

    analyze_message: Callable[..., Awaitable[AnalysisResult]] = analyze_message
    analyze_url: Callable[..., Awaitable[AnalysisResult]] = analyze_url


@dataclass(frozen=True, slots=True)
class Services:
    limiter: RateLimiter
    persistence: Persistence
    provider: UrlReputationProvider
    pipeline: Pipeline
    # HMAC key for client ids.
    client_id_key: bytes
