"""Bounded grant-ledger reads behind the per-run cost ceiling (#3271).

Two operator questions, both answered from ``inference_grants`` alone:

* **Which wall did a run hit?** The grant row is the authoritative meter: it
  is what admission declines on and what the Platform bills a spent allowance
  from (:func:`~ditto.db.queries.inference.ticket_inference_grant_spent_allowance`).
  A scoring run that ends as ``inference_allowance_exhausted`` left a grant
  at its request, token or enforced cost wall. The scorer's own
  ``diagnostics.wall`` is not sent to the Platform, so the split is derived
  from the meters, in the order admission names the walls: the enforced cost
  ceiling first, then the chat token wall, then the chat request wall. A
  grant marked ``exhausted`` with no meter at a wall (a v1 grant whose token
  counters were reservation estimates, or a legacy row) lands in ``unknown``
  rather than being dropped. Embedding and decision walls never exhaust a
  grant, so they are not run walls.
* **How much does a run cost?** Ledger cost per grant, per bench version, so
  the operator can size the ceiling from data before ``shadow`` and before
  ``enforce``.

Both statements are bounded by ``expires_at`` -- the only indexed time column
on ``inference_grants`` (``inference_grants_expiry_idx``) -- project only the
columns they aggregate, and return one row per window or per bench version.
"""

# ruff: noqa: E501 -- SQL is kept vertically aligned with its result columns.

from __future__ import annotations

from datetime import datetime

from sqlalchemy import text
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncSession

from ditto.db.queries.inference import USAGE_ACCOUNTING_VERSION

ALLOWANCE_WALL_WINDOWS_SECONDS = (3600, 86400, 604800)
"""1 hour / 1 day / 7 days. A run lasts minutes to hours and walls are rare, so
the request-level 1/5/15/60-minute grain would read empty almost always."""

LEDGER_COST_DEFAULT_HOURS = 168
LEDGER_COST_MAX_HOURS = 744
"""The distribution reads a bounded slice of ended leases: 7 days by default,
31 at most, the same ceiling ``/admin/inference-grant-costs`` uses."""

# The CASE order is admission's (relay step 8): an enforced, spent cost
# ceiling answers 4110 before the token wall's 4104, and 4102 is the rest.
_WALL_SQL = """
    WITH windows AS (
        SELECT unnest(CAST(:windows AS int[])) AS window_seconds
    ), walled AS (
        SELECT g.expires_at,
               CASE
                 WHEN g.usage_accounting_version < :accounting_version THEN
                   CASE WHEN g.status = 'exhausted' THEN 'unknown' END
                 WHEN g.cost_ceiling_mode = 'enforce'
                  AND g.cost_ceiling_microusd IS NOT NULL
                  AND g.ledger_cost_microusd >= g.cost_ceiling_microusd THEN 'cost'
                 WHEN g.prompt_tokens + g.completion_tokens >= g.token_budget THEN 'token'
                 WHEN g.request_count >= g.request_budget THEN 'request'
                 WHEN g.status = 'exhausted' THEN 'unknown'
               END AS wall
          FROM inference_grants g
         WHERE g.expires_at > CAST(:now AS timestamptz) - make_interval(secs => CAST(:max_window AS int))
    )
    SELECT w.window_seconds                                      AS window_seconds,
           count(x.wall)                                         AS grants_at_wall,
           count(*) FILTER (WHERE x.wall = 'request')            AS request,
           count(*) FILTER (WHERE x.wall = 'token')              AS token,
           count(*) FILTER (WHERE x.wall = 'cost')               AS cost,
           count(*) FILTER (WHERE x.wall = 'unknown')            AS unknown
      FROM windows w
      LEFT JOIN walled x
        ON x.wall IS NOT NULL
       AND x.expires_at > CAST(:now AS timestamptz) - make_interval(secs => w.window_seconds)
     GROUP BY w.window_seconds
     ORDER BY w.window_seconds
"""

# ``unbooked`` is a grant that receipted usage but booked no ledger cost: one
# settled before the ledger column existed (it defaults to 0), or a chat grant
# with no list price whose provider bill was untrusted. Counting it as a zero
# would drag every percentile down, so it is excluded and reported apart. A
# grant that receipted nothing is a genuine zero-cost run and stays in.
_DISTRIBUTION_SQL = """
    WITH ended AS (
        SELECT g.bench_version,
               g.ledger_cost_microusd                            AS ledger,
               g.cost_ceiling_mode                               AS mode,
               g.cost_ceiling_microusd                           AS ceiling,
               g.cost_ceiling_would_decline                      AS would_decline,
               (g.ledger_cost_microusd = 0
                AND g.prompt_tokens + g.completion_tokens
                    + g.embedding_tokens + g.decision_tokens > 0) AS unbooked
          FROM inference_grants g
         WHERE g.expires_at > :window_start
           AND g.expires_at <= :window_end
           AND g.usage_accounting_version >= :accounting_version
    )
    SELECT bench_version,
           count(*)                                              AS grants,
           count(*) FILTER (WHERE unbooked)                      AS unbooked_grants,
           percentile_disc(0.5) WITHIN GROUP (ORDER BY ledger)
             FILTER (WHERE NOT unbooked)                         AS p50_microusd,
           percentile_disc(0.95) WITHIN GROUP (ORDER BY ledger)
             FILTER (WHERE NOT unbooked)                         AS p95_microusd,
           percentile_disc(0.99) WITHIN GROUP (ORDER BY ledger)
             FILTER (WHERE NOT unbooked)                         AS p99_microusd,
           max(ledger) FILTER (WHERE NOT unbooked)               AS max_microusd,
           COALESCE(sum(ledger) FILTER (WHERE NOT unbooked), 0)  AS total_microusd,
           count(*) FILTER (WHERE mode = 'shadow')               AS shadow_grants,
           count(*) FILTER (WHERE mode = 'enforce')              AS enforce_grants,
           COALESCE(sum(would_decline), 0)                       AS would_decline,
           count(*) FILTER (WHERE would_decline > 0)             AS grants_with_would_decline,
           count(*) FILTER (WHERE mode = 'enforce'
                              AND ceiling IS NOT NULL
                              AND ledger >= ceiling)             AS cost_wall_grants
      FROM ended
     GROUP BY bench_version
     ORDER BY bench_version DESC
"""


async def load_allowance_wall_rows(
    session: AsyncSession, *, now: datetime
) -> list[RowMapping]:
    """One row per window: grants that reached a run wall, split by wall."""
    rows = await session.execute(
        text(_WALL_SQL),
        {
            "windows": list(ALLOWANCE_WALL_WINDOWS_SECONDS),
            "max_window": max(ALLOWANCE_WALL_WINDOWS_SECONDS),
            "now": now,
            "accounting_version": USAGE_ACCOUNTING_VERSION,
        },
    )
    return list(rows.mappings())


async def load_ledger_cost_distribution(
    session: AsyncSession, *, window_start: datetime, window_end: datetime
) -> list[RowMapping]:
    """Per bench version: ledger cost of leases that ended in the window."""
    rows = await session.execute(
        text(_DISTRIBUTION_SQL),
        {
            "window_start": window_start,
            "window_end": window_end,
            "accounting_version": USAGE_ACCOUNTING_VERSION,
        },
    )
    return list(rows.mappings())


__all__ = [
    "ALLOWANCE_WALL_WINDOWS_SECONDS",
    "LEDGER_COST_DEFAULT_HOURS",
    "LEDGER_COST_MAX_HOURS",
    "load_allowance_wall_rows",
    "load_ledger_cost_distribution",
]
