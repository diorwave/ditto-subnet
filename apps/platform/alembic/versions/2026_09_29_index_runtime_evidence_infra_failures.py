"""cover retryable runtime-evidence failures in the infra-failure index

Revision ID: 5e2a8c4f9d17
Revises: b6f3d0c7a915
Create Date: 2026-09-29

``INFRA_AUTO_RETRY_REASON_CODES`` now also retries a worker's
``l2-runtime-evidence-unavailable`` failure: Platform attached no signed V13
scorer-cohort lease to the claim, so the artifact was never judged (#2444). The
fleet breaker scan under the global claim lock filters on exactly that tuple, so
the partial ``screening_attempts_infra_failed_idx`` from ``3c9d5e7a1b42`` must
name both codes or the scan falls back to a sequential walk.

The predicate is duplicated in ``models.py`` and
``screening_infra_retry._infra_failure_filters``; keep all three in step.

Rebuilt ``CONCURRENTLY`` (an ``autocommit_block``) so it never holds a ``SHARE``
lock against attempt inserts and verdict updates. Re-runnable from any point: an
index that is ``INVALID`` or carries the other predicate is dropped first. The
index is briefly absent between the drop and the rebuild; the rows it covers are
a tiny fraction of the table, so that window costs one slower breaker scan.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence

from sqlalchemy import exc, text

from alembic import op
from ditto.db.migration_lock import MAX_ATTEMPTS, backoff_delay, is_retryable, sqlstate

revision: str = "5e2a8c4f9d17"
down_revision: str | Sequence[str] | None = "b6f3d0c7a915"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

log = logging.getLogger("alembic.lock")

INDEX_NAME = "screening_attempts_infra_failed_idx"
NEW_CODE = "l2-runtime-evidence-unavailable"
UPGRADED_PREDICATE = (
    "status = 'failed' AND reason_code IN "
    f"('docker-build-infrastructure', '{NEW_CODE}')"
)
PREVIOUS_PREDICATE = "status = 'failed' AND reason_code = 'docker-build-infrastructure'"
_INDEX_STATE_SQL = """
SELECT i.indisvalid, pg_get_expr(i.indpred, i.indrelid)
  FROM pg_index i
  JOIN pg_class c ON c.oid = i.indexrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = current_schema()
   AND c.relname = :name
"""


def _index_state(bind) -> tuple[bool, str] | None:  # noqa: ANN001 -- alembic bind
    """``(valid, predicate)`` for the index, or ``None`` when it is absent."""
    row = bind.execute(text(_INDEX_STATE_SQL), {"name": INDEX_NAME}).first()
    return None if row is None else (bool(row[0]), str(row[1] or ""))


def _run_concurrently(bind, statement: str, what: str) -> None:  # noqa: ANN001
    """Run one ``CONCURRENTLY`` statement, retrying lock contention."""
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


def _rebuild(predicate: str, *, covers_new_code: bool) -> None:
    with op.get_context().autocommit_block():
        bind = op.get_bind()

        def current() -> bool:
            state = _index_state(bind)
            return (
                state is not None
                and state[0]
                and (NEW_CODE in state[1]) is covers_new_code
            )

        if not current():
            if _index_state(bind) is not None:
                log.warning("%s is invalid or stale; rebuilding", INDEX_NAME)
                _run_concurrently(
                    bind,
                    f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX_NAME}",
                    f"drop {INDEX_NAME}",
                )
            _run_concurrently(
                bind,
                f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {INDEX_NAME} "
                f"ON screening_attempts (finished_at) WHERE {predicate}",
                f"create {INDEX_NAME}",
            )
        if not current():
            raise RuntimeError(
                f"{INDEX_NAME} did not come up valid; re-run the migration"
            )


def upgrade() -> None:
    _rebuild(UPGRADED_PREDICATE, covers_new_code=True)


def downgrade() -> None:
    _rebuild(PREVIOUS_PREDICATE, covers_new_code=False)
