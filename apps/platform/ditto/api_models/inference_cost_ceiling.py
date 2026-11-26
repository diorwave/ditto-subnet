"""Private operator reads for the per-run cost ceiling (#3271).

Counts and micro-USD sums from the grant ledger only: no prompt, response,
key, header or trace body.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from ditto.api_models.inference_concurrency_settings import CostCeilingMode


class InferenceAllowanceWallWindow(BaseModel):
    """Scoring grants that reached a run wall, by wall, over one window.

    A run that ends as ``inference_allowance_exhausted`` left its grant at one
    of these walls. ``request`` and ``token`` are the chat walls and ``cost``
    is an enforced ledger cost ceiling (#3271), named in admission's order
    (cost before token before request). ``unknown`` is a grant marked
    exhausted whose meters prove no wall: a v1 grant or a legacy row. It is
    reported so that a gap is visible, never folded into a named wall. The
    window counts grants whose lease ended inside it or is still live.
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    window_seconds: int
    grants_at_wall: int
    request: int
    token: int
    cost: int
    unknown: int


class InferenceLedgerCostBench(BaseModel):
    """Ledger cost per run for one bench version's ended leases."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    bench_version: int
    grants: int
    unbooked_grants: int
    """Grants that receipted usage but booked no ledger cost (settled before
    the ledger existed, or a chat grant with no list price and an untrusted
    bill). Left out of every figure below so they cannot drag it to zero."""
    p50_microusd: int | None
    p95_microusd: int | None
    p99_microusd: int | None
    max_microusd: int | None
    total_microusd: int
    shadow_grants: int
    enforce_grants: int
    would_decline: int
    """Shadow admissions that ``enforce`` would have declined, summed."""
    grants_with_would_decline: int
    cost_wall_grants: int
    """Enforced grants whose settled ledger cost reached their ceiling."""


class InferenceLedgerCostDistribution(BaseModel):
    """What one run costs, so the operator can size the ceiling from data."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    observed_at: datetime
    window_start: datetime
    window_end: datetime
    aggregation_basis: Literal["grant_expires_at_ended_leases"] = (
        "grant_expires_at_ended_leases"
    )
    run_cost_ceiling_microusd: int | None
    """The ceiling in force now, for comparison. Each grant ran under the one
    stamped at its own mint."""
    cost_ceiling_mode: CostCeilingMode
    case_cost_report_microusd: int | None
    benches: list[InferenceLedgerCostBench]
