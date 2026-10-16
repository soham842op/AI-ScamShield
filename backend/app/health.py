import asyncio

import psycopg
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.core.config import get_settings

router = APIRouter()

# libpq treats any connect timeout below 2 seconds as 2.
CONNECT_TIMEOUT_SECONDS = 2
QUERY_TIMEOUT_MS = 1000


def _check_database_sync() -> bool:
    url = get_settings().database_url.get_secret_value().replace("+psycopg", "", 1)
    if not url:
        return False
    try:
        with psycopg.connect(
            url,
            connect_timeout=CONNECT_TIMEOUT_SECONDS,
            options=f"-c statement_timeout={QUERY_TIMEOUT_MS}",
        ) as conn:
            conn.execute("SELECT 1")
    except Exception:
        return False
    return True


async def check_database() -> bool:
    return await asyncio.to_thread(_check_database_sync)


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz() -> JSONResponse:
    database_ok = await check_database()
    body = {
        "status": "ready" if database_ok else "not_ready",
        "checks": {
            "database": "ok" if database_ok else "unavailable",
            "model": "not_loaded",
        },
    }
    return JSONResponse(body, status_code=200 if database_ok else 503)
