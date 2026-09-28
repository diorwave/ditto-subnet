"""widen the infrastructure-failed screening attempts index to every auto-retry code

Revision ID: 6b8e2f4c9a17
Revises: a2f4d9c51e60
Create Date: 2026-09-28

#2449 adds four fleet-owned failure codes to
``screening_infra_retry.INFRA_AUTO_RETRY_REASON_CODES``. The fleet breaker's
``status = 'failed' AND reason_code IN (...) AND finished_at >= :cutoff`` scan
runs under the global claim lock and must stay on the partial
``screening_attempts_infra_failed_idx`` (``3c9d5e7a1b42``), whose predicate named
only ``docker-build-infrastructure``. A query over more codes no longer implies
that predicate, so Postgres would fall back to a sequential scan.

The index is rebuilt under the same name with the widened predicate. The
predicate is duplicated in ``models.py`` and
``screening_infra_retry._infra_failure_filters``; keep all three in step.

Built ``CONCURRENTLY`` (an ``autocommit_block``) so it never holds a ``SHARE``
lock against attempt inserts and verdict updates, and re-runnable from any
point: an index that is ``INVALID`` or over any other set of codes is dropped
first, and one already over exactly the wanted codes is left alone.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Sequence

from sqlalchemy import exc, text

from alembic import op
from ditto.db.migration_lock import MAX_ATTEMPTS, backoff_delay, is_retryable, sqlstate

revision: str = "6b8e2f4c9a17"
down_revision: str | Sequence[str] | None = "a2f4d9c51e60"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

log = logging.getLogger("alembic.lock")

INDEX_NAME = "screening_attempts_infra_failed_idx"
# Frozen copies: a migration never imports the live tuple it mirrors.
REASON_CODES = (
    "docker-build-infrastructure",
    "worker-lease-orphaned",
    "worker-platform-request-failed",
    "l2-cache-lock-timeout",
    "source-review-retryable-infra",
)
PREVIOUS_REASON_CODES = ("docker-build-infrastructure",)
_INDEX_STATE_SQL = """
SELECT i.indisvalid, pg_get_expr(i.indpred, i.indrelid)
  FROM pg_index i
  JOIN pg_class c ON c.oid = i.indexrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = current_schema()
   AND c.relname = :name
"""


def _index_state(bind, codes: Sequence[str]) -> bool | None:  # noqa: ANN001
    """``True`` valid over exactly ``codes``, ``False`` otherwise, ``None`` absent."""
    row = bind.execute(text(_INDEX_STATE_SQL), {"name": INDEX_NAME}).first()
    if row is None:
        return None
    literals = set(re.findall(r"'([^']*)'", row[1] or ""))
    return bool(row[0]) and literals == {"failed", *codes}


def _run_concurrently(bind, statement: str, what: str) -> None:  # noqa: ANN001
    """Run one ``CONCURRENTLY`` statement, retrying lock contention.

    Only the initial ``SHARE UPDATE EXCLUSIVE`` acquisition is subject to
    ``lock_timeout``; the build itself is never cut short.
    """
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            bind.exec_driver_sql(statement)
            return
        except exc.DBAPIError as error:
            if not is_retryable(error) or attempt == MAX_ATTEMPTS:
                raise
            delay = backoff_delay(attempt)
            log.warning(
                "%s: %s on attempt %d/%d; retrying in %.1fs",
                what,
                sqlstate(error),
                attempt,
                MAX_ATTEMPTS,
                delay,
            )
            time.sleep(delay)


def _rebuild(codes: Sequence[str]) -> None:
    with op.get_context().autocommit_block():
        bind = op.get_bind()
        state = _index_state(bind, codes)
        if state is False:
            log.warning(
                "%s is INVALID or covers other reason codes; rebuilding", INDEX_NAME
            )
            _run_concurrently(
                bind,
                f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX_NAME}",
                f"drop stale {INDEX_NAME}",
            )
            state = None
        if state is None:
            in_list = ", ".join(f"'{code}'" for code in codes)
            _run_concurrently(
                bind,
                f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {INDEX_NAME} "
                "ON screening_attempts (finished_at) "
                f"WHERE status = 'failed' AND reason_code IN ({in_list})",
                f"create {INDEX_NAME}",
            )
        if _index_state(bind, codes) is not True:
            raise RuntimeError(
                f"{INDEX_NAME} did not come up valid; re-run the migration"
            )


def upgrade() -> None:
    _rebuild(REASON_CODES)


def downgrade() -> None:
    _rebuild(PREVIOUS_REASON_CODES)
