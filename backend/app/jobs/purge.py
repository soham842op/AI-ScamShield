import logging
import sys
from datetime import UTC, datetime

from app.db.engine import get_engine
from app.db.repository import purge_expired

logger = logging.getLogger("app.jobs.purge")


def run() -> int:
    try:
        with get_engine().begin() as conn:
            counts = purge_expired(conn, datetime.now(UTC))
    except Exception as exc:
        # Type only: driver messages can embed connection details.
        logger.error("purge failed: %s", type(exc).__name__)
        return 1
    logger.info(
        "purge complete: analysis_records=%d feedback=%d rate_limit_counters=%d",
        counts.analysis_records,
        counts.feedback,
        counts.rate_limit_counters,
    )
    return 0


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    sys.exit(run())


if __name__ == "__main__":
    main()
