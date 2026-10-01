"""Subnet liveness signals from durable Platform state (ditto-subnet#2600).

Invariant 1 of #2600: the conditions that stop the whole subnet must be
visible in minutes, not found by a miner days later. Each incident below went
undetected for hours or days while every component reported itself healthy:

* #2474 -- a leftover per-node settings revision held production screening
  admission at 0 for about 41 hours (``screening_admission``,
  ``oldest_claimable_upload``);
* #2490 -- a stale signed scorer-cohort pin declined every v13 lease
  (``v13_scorer_cohort_pin``, ``scoring_throughput``);
* #2231 -- a chain runtime upgrade halted the source-emission collector
  (``source_emission_collector``);
* holds and leases that never reach a terminal state (#2100, #1146)
  (``oldest_actionable_hold``, ``lease_overrun``).

This module is a **read model**: it pages nobody, gates nothing, and runs in a
``READ ONLY`` transaction with a statement timeout, so a wedged signal can
neither write nor hold the caller. Paging/alert delivery on top of these
statuses is an explicit follow-up.

Every query is bounded by a partial index or a ``LIMIT`` and none touches
``inference_requests``:

* screener nodes and their heartbeats/settings revisions (a handful of rows,
  revoked nodes collapsed into one aggregate);
* ``agents_status_uploaded_idx`` / ``agents_status_evaluating_idx``;
* the newest :data:`SCORE_AUDIT_SCAN_LIMIT` ``score_audit_log`` rows by
  primary key;
* ``screening_quarantines_one_active_agent_idx`` and
  ``ath_reviews_status_opened_idx``;
* ``validator_tickets_open_idx`` and ``screening_attempts_one_running_idx``;
* one ``source_emission_collector_cursors`` primary-key read.

Every value is "higher is worse" and compared against named default
thresholds below. They are liveness alarms, not policy deadlines: in
particular :data:`HOLD_AGE_BREACH_SECONDS` is NOT a published hold clock
(#2100 has none); it only says an operator should look.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ditto.api_models.screener_node_settings import ScreenerNodeChannelSettings
from ditto.api_models.subnet_liveness import (
    LivenessSignalName,
    LivenessStatus,
    LivenessUnit,
    SubnetLiveness,
    SubnetLivenessSignal,
    SubnetLivenessUnavailableSignal,
)
from ditto.api_server.screener_node_identity import (
    CONTROLLER_HEARTBEAT_READY_SECONDS,
    is_enrolled_node_heartbeat_instance,
    screener_heartbeat_ready,
)
from ditto.api_server.screener_policy_activation import (
    resolve_screener_policy_activation,
)
from ditto.api_server.v13_scorer_cohort import current_pin, packet_for_heartbeat
from ditto.db.models import (
    ScreenerHeartbeat,
    ScreenerNode,
    ScreenerNodeChannelSettingsRevision,
    SourceEmissionCollectorCursor,
    ValidatorHeartbeat,
)
from ditto.db.queries.benchmark_rollout import active_bench_version, open_rollout
from ditto.db.queries.scores import SCORING_QUORUM
from ditto.db.queries.screener_capacity import legacy_gcp_claim_authorized
from ditto.db.queries.screener_node_settings import (
    resolve_screener_node_channel_settings,
)
from ditto.db.queries.screening import claimable_screening_upload_backlog
from ditto.db.queries.terminal_quarantine_reconciliation import (
    TERMINAL_QUARANTINE_AGENT_STATUSES,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

# ─── Default thresholds (seconds unless noted) ──────────────────────────────

ADMISSION_ZERO_WARN_SECONDS = 5 * 60
ADMISSION_ZERO_BREACH_SECONDS = 15 * 60
"""Effective screening admission at 0 while a claimable upload waits."""

OLDEST_CLAIMABLE_UPLOAD_WARN_SECONDS = 60 * 60
OLDEST_CLAIMABLE_UPLOAD_BREACH_SECONDS = 4 * 60 * 60
"""Age of the oldest upload a production claim could take right now."""

SCORING_STALL_WARN_SECONDS = 60 * 60
SCORING_STALL_BREACH_SECONDS = 3 * 60 * 60
"""Time with no accepted validator score while scoring work is queued."""

SCORE_THROUGHPUT_WINDOW = timedelta(hours=1)
SCORE_AUDIT_SCAN_LIMIT = 5000
"""Newest ``score_audit_log`` rows examined; a backward primary-key scan."""

HOLD_AGE_WARN_SECONDS = 24 * 60 * 60
HOLD_AGE_BREACH_SECONDS = 72 * 60 * 60
"""Oldest actionable quarantine or ATH hold. A liveness alarm, not a policy
deadline: holds still have no published terminal clock (#2100)."""

LEASE_OVERRUN_WARN_SECONDS = 5 * 60
LEASE_OVERRUN_BREACH_SECONDS = 30 * 60
"""A lease still open past its deadline means no sweep has run: no validator
is polling (validator tickets) or no screener claim/controller heartbeat has
arrived (screening attempts)."""

COLLECTOR_CURSOR_WARN_SECONDS = 15 * 60
COLLECTOR_CURSOR_BREACH_SECONDS = 60 * 60
"""Age of the source-emission collector's finalized-block cursor."""

V13_SCORER_BENCH_VERSION = 13
V13_PIN_MEMBERS = 3
"""``v13_scorer_pin_three_hotkeys_check`` pins exactly three members."""
STATEMENT_TIMEOUT_MS = 5000
SETTINGS_REVISION_SCAN_LIMIT = 50

_EXCEPTION_CLASS = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,63}$")

UNAVAILABLE_SIGNALS = (
    SubnetLivenessUnavailableSignal(
        name="disk_and_db_headroom",
        reason=(
            "Host disk and Postgres volume headroom are host metrics, not "
            "durable Platform state (#1745). Use the release-ops "
            "platform-host-disk runbook."
        ),
    ),
    SubnetLivenessUnavailableSignal(
        name="v13_scorer_pin_declines",
        reason=(
            "Dispatch declines are only a Prometheus counter "
            "(validator_dispatch_declined, reason=v13_scorer_cohort_pin) and a "
            "log line. v13_scorer_cohort_pin derives pin staleness from member "
            "heartbeats instead."
        ),
    ),
)


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def _seconds(now: datetime, start: datetime | None) -> float:
    if start is None:
        return 0.0
    return max(0.0, (now - start).total_seconds())


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def classify(
    value: float | None, *, warn: float | None, breach: float
) -> LivenessStatus:
    """Map a higher-is-worse value onto ok / warn / breach."""
    if value is None:
        return "ok"
    if value >= breach:
        return "breach"
    if warn is not None and value >= warn:
        return "warn"
    return "ok"


def _signal(
    name: LivenessSignalName,
    *,
    value: float | None,
    unit: LivenessUnit,
    warn: float | None,
    breach: float,
    since: datetime | None,
    hint: str,
    detail: dict[str, int | float | str | bool | None],
) -> SubnetLivenessSignal:
    return SubnetLivenessSignal(
        name=name,
        status=classify(value, warn=warn, breach=breach),
        value=value,
        unit=unit,
        warn_threshold=warn,
        threshold=breach,
        since=since,
        hint=hint,
        detail=detail,
    )


# ─── Screening admission ────────────────────────────────────────────────────


@dataclass(frozen=True)
class AdmissionState:
    effective_slots: int
    enrolled_nodes: int
    ready_nodes: int
    open_nodes: int
    legacy_gcp_route_open: bool
    legacy_ready_workers: int
    zero_since: datetime | None


async def _concurrency_zero_since(
    session: AsyncSession, *, node: ScreenerNode
) -> datetime | None:
    """Start of the node's current ``screening_concurrency == 0`` streak.

    Settings revisions are append-only, so the streak starts at the first
    zero revision after the newest nonzero one. With no revision at all the
    node has run on the default (closed) settings since it enrolled.
    """
    rows = list(
        await session.scalars(
            select(ScreenerNodeChannelSettingsRevision)
            .where(ScreenerNodeChannelSettingsRevision.node_id == node.node_id)
            .order_by(ScreenerNodeChannelSettingsRevision.revision.desc())
            .limit(SETTINGS_REVISION_SCAN_LIMIT)
        )
    )
    if not rows:
        return _aware(node.registered_at)
    streak_start: datetime | None = None
    for row in rows:
        try:
            concurrency = ScreenerNodeChannelSettings.model_validate(
                row.settings
            ).screening_concurrency
        except ValueError:
            break
        if concurrency > 0:
            break
        streak_start = _aware(row.created_at)
    return streak_start


async def load_admission_state(
    session: AsyncSession,
    *,
    environment: str,
    now: datetime,
    required_policy: int,
) -> AdmissionState:
    """Effective screening admission, mirroring the controller's node view.

    A node contributes its ``screening_concurrency`` only while it is
    ``active`` and its newest worker heartbeat is ready
    (:func:`screener_heartbeat_ready`). Legacy unenrolled GCP fleet workers
    add one slot each while the legacy route is authorized
    (:func:`legacy_gcp_claim_authorized`, read without a row lock).

    ``zero_since`` is when admission last became zero, when every closed
    node's closure time is recorded: the latest of the per-node closure
    times. It is null while admission is open or any closure is unrecorded
    (a status change or a policy mismatch carries no timestamp).
    """
    nodes = list(
        await session.scalars(
            select(ScreenerNode)
            .where(
                ScreenerNode.environment == environment,
                ScreenerNode.status != "revoked",
            )
            .order_by(ScreenerNode.node_id)
        )
    )
    revoked_at = _aware(
        await session.scalar(
            text(
                "SELECT max(revoked_at) FROM screener_nodes "
                "WHERE environment = :environment AND status = 'revoked'"
            ),
            {"environment": environment},
        )
    )
    heartbeats: list[ScreenerHeartbeat] = (
        list(
            await session.scalars(
                select(ScreenerHeartbeat).where(
                    ScreenerHeartbeat.screener_hotkey.in_(
                        [node.screener_hotkey for node in nodes]
                    )
                )
            )
        )
        if nodes
        else []
    )
    effective = 0
    ready_nodes = 0
    open_nodes = 0
    closures: list[datetime | None] = []
    for node in nodes:
        latest = max(
            (
                row
                for row in heartbeats
                if row.screener_hotkey == node.screener_hotkey
                and is_enrolled_node_heartbeat_instance(
                    node_id=node.node_id, instance_id=row.instance_id
                )
            ),
            key=lambda row: _aware(row.seen_at) or now,
            default=None,
        )
        seen_at = _aware(latest.seen_at) if latest is not None else None
        ready = node.status == "active" and screener_heartbeat_ready(
            seen_at=seen_at,
            policy_version=latest.policy_version if latest is not None else None,
            now=now,
            required_policy=required_policy,
        )
        # The same resolver the claim path's per-node admission reads.
        _, channels = await resolve_screener_node_channel_settings(
            session, node_id=node.node_id
        )
        concurrency = channels.screening_concurrency
        ready_nodes += int(ready)
        open_nodes += int(concurrency > 0)
        if ready and concurrency > 0:
            effective += concurrency
            continue
        known: list[datetime] = []
        if concurrency == 0:
            streak_start = await _concurrency_zero_since(session, node=node)
            if streak_start is not None:
                known.append(streak_start)
        if seen_at is None:
            known.append(_aware(node.registered_at) or now)
        elif now - seen_at > timedelta(seconds=CONTROLLER_HEARTBEAT_READY_SECONDS):
            known.append(
                seen_at + timedelta(seconds=CONTROLLER_HEARTBEAT_READY_SECONDS)
            )
        closures.append(min(known) if known else None)
    if revoked_at is not None:
        closures.append(revoked_at)

    legacy_open = await legacy_gcp_claim_authorized(session, now=now, lock=False)
    legacy_ready = 0
    if legacy_open:
        enrolled_ids = {node.node_id for node in nodes}
        legacy_rows = await session.scalars(
            select(ScreenerHeartbeat).where(
                ScreenerHeartbeat.instance_id.like("ditto-screener-fleet-%"),
                ScreenerHeartbeat.seen_at
                >= now - timedelta(seconds=CONTROLLER_HEARTBEAT_READY_SECONDS),
            )
        )
        legacy_ready = sum(
            1
            for row in legacy_rows
            if row.instance_id not in enrolled_ids
            and screener_heartbeat_ready(
                seen_at=_aware(row.seen_at),
                policy_version=row.policy_version,
                now=now,
                required_policy=required_policy,
            )
        )
    effective += legacy_ready
    zero_since: datetime | None = None
    if effective == 0 and closures and all(c is not None for c in closures):
        zero_since = max(c for c in closures if c is not None)
    return AdmissionState(
        effective_slots=effective,
        enrolled_nodes=len(nodes),
        ready_nodes=ready_nodes,
        open_nodes=open_nodes,
        legacy_gcp_route_open=legacy_open,
        legacy_ready_workers=legacy_ready,
        zero_since=zero_since,
    )


def admission_signal(
    admission: AdmissionState,
    *,
    claimable_uploads: int,
    oldest_upload_at: datetime | None,
    now: datetime,
) -> SubnetLivenessSignal:
    """Seconds effective admission has been 0 while a claimable upload waits."""
    since: datetime | None = None
    value = 0.0
    if admission.effective_slots == 0 and claimable_uploads > 0:
        candidates = [t for t in (admission.zero_since, oldest_upload_at) if t]
        since = max(candidates) if candidates else None
        value = _seconds(now, since)
    return _signal(
        "screening_admission",
        value=value,
        unit="seconds",
        warn=ADMISSION_ZERO_WARN_SECONDS,
        breach=ADMISSION_ZERO_BREACH_SECONDS,
        since=since,
        hint=(
            "Effective admission is 0 while uploads wait. Check node_controls "
            "and heartbeats in get_screener_capacity; a leftover "
            "screening_concurrency=0 revision caused #2474."
            if value > 0
            else "Screening admission is open, or nothing is waiting for it."
        ),
        detail={
            "effective_slots": admission.effective_slots,
            "enrolled_nodes": admission.enrolled_nodes,
            "ready_nodes": admission.ready_nodes,
            "open_nodes": admission.open_nodes,
            "legacy_gcp_route_open": admission.legacy_gcp_route_open,
            "legacy_ready_workers": admission.legacy_ready_workers,
            "zero_since": _iso(admission.zero_since),
            "claimable_uploads": claimable_uploads,
        },
    )


def oldest_upload_signal(
    *, claimable_uploads: int, oldest_upload_at: datetime | None, now: datetime
) -> SubnetLivenessSignal:
    value = _seconds(now, oldest_upload_at) if claimable_uploads else 0.0
    return _signal(
        "oldest_claimable_upload",
        value=value,
        unit="seconds",
        warn=OLDEST_CLAIMABLE_UPLOAD_WARN_SECONDS,
        breach=OLDEST_CLAIMABLE_UPLOAD_BREACH_SECONDS,
        since=oldest_upload_at if claimable_uploads else None,
        hint=(
            "Uploads are claimable but not being claimed. Compare "
            "screening_admission and get_source_review_queue_slo capacity_wait."
        ),
        detail={"claimable_uploads": claimable_uploads},
    )


# ─── Scoring throughput ─────────────────────────────────────────────────────

_SCORE_EVENTS_SQL = text(
    """
    SELECT count(*) FILTER (WHERE recorded_at >= :window_start) AS last_window,
           max(recorded_at) AS last_score_at
      FROM (
        SELECT event, recorded_at
          FROM score_audit_log
         ORDER BY seq DESC
         LIMIT :scan_limit
      ) recent
     WHERE event = 'score'
    """
)

# GREATEST ignores NULLs: an evaluating agent entered the queue at its upload,
# its last screening finish, or its last quarantine release, whichever is last.
_SCORING_QUEUE_SQL = text(
    """
    SELECT count(*) AS queued, min(entered_at) AS queued_since
      FROM (
        SELECT GREATEST(
                 a.created_at,
                 (SELECT max(sa.finished_at) FROM screening_attempts sa
                   WHERE sa.agent_id = a.agent_id),
                 (SELECT max(q.resolved_at) FROM screening_quarantines q
                   WHERE q.agent_id = a.agent_id)
               ) AS entered_at
          FROM agents a
         WHERE a.status = 'evaluating'
      ) queue
    """
)

_OPEN_LEASES_SQL = text(
    "SELECT count(*) FROM validator_tickets WHERE status = 'issued' AND deadline > :now"
)


async def scoring_signal(
    session: AsyncSession, *, now: datetime
) -> SubnetLivenessSignal:
    """Seconds without an accepted validator score while work is queued."""
    events = (
        (
            await session.execute(
                _SCORE_EVENTS_SQL,
                {
                    "window_start": now - SCORE_THROUGHPUT_WINDOW,
                    "scan_limit": SCORE_AUDIT_SCAN_LIMIT,
                },
            )
        )
        .mappings()
        .one()
    )
    queue = (await session.execute(_SCORING_QUEUE_SQL)).mappings().one()
    open_leases = int(await session.scalar(_OPEN_LEASES_SQL, {"now": now}) or 0)
    queued = int(queue["queued"] or 0)
    last_score_at = _aware(events["last_score_at"])
    queued_since = _aware(queue["queued_since"])
    since: datetime | None = None
    if queued:
        candidates = [t for t in (last_score_at, queued_since) if t is not None]
        since = max(candidates) if candidates else None
    value = _seconds(now, since)
    return _signal(
        "scoring_throughput",
        value=value,
        unit="seconds",
        warn=SCORING_STALL_WARN_SECONDS,
        breach=SCORING_STALL_BREACH_SECONDS,
        since=since,
        hint=(
            "No accepted score while agents wait. Open leases with no scores is "
            "an execution fault; no leases is dispatch (check the v13 pin, "
            "get_validator_capacity, agent_scoring_readiness)."
        ),
        detail={
            "scores_last_hour": int(events["last_window"] or 0),
            "last_accepted_score_at": _iso(last_score_at),
            "evaluating_agents": queued,
            "open_validator_leases": open_leases,
        },
    )


# ─── V13 scorer cohort pin ──────────────────────────────────────────────────


async def scorer_pin_signal(
    session: AsyncSession, *, now: datetime
) -> SubnetLivenessSignal:
    """Pinned members whose live signed packet no longer matches the pin.

    The same comparison
    :func:`~ditto.api_server.v13_scorer_cohort.pinned_validator_allowed`
    makes on every v13 dispatch: a mismatched member is declined. A pin is as
    large as the scoring quorum, so one stale member stops v13 finalization.
    """
    rollout = await open_rollout(session)
    active = await active_bench_version(session, open_transition=rollout)
    targets = {active} | ({rollout.desired_version} if rollout is not None else set())
    pin = await current_pin(session)
    # Breach once fewer members match than a quorum needs. The pin table
    # enforces exactly three members, so with quorum 3 one stale member breaches.
    members = len(pin.hotkeys) if pin is not None else V13_PIN_MEMBERS
    breach = float(max(1, members - SCORING_QUORUM + 1))
    if V13_SCORER_BENCH_VERSION not in targets or pin is None:
        return _signal(
            "v13_scorer_cohort_pin",
            value=None,
            unit="members",
            warn=None,
            breach=breach,
            since=None,
            hint="No v13 scorer pin governs dispatch right now.",
            detail={"active_bench_version": active, "pin_active": pin is not None},
        )
    hotkeys: Sequence[str] = list(pin.hotkeys)
    matching = 0
    for hotkey in hotkeys:
        heartbeat = await session.get(ValidatorHeartbeat, hotkey)
        packet = packet_for_heartbeat(heartbeat, now=now)
        if packet is not None and packet.model_dump(mode="json") == pin.packet:
            matching += 1
    stale = len(hotkeys) - matching
    return _signal(
        "v13_scorer_cohort_pin",
        value=float(stale),
        unit="members",
        warn=None,
        breach=breach,
        since=None,
        hint=(
            "Pinned members report a different signed scorer packet and are "
            "declined v13 work (#2490). Compare get_v13_scorer_cohort_preflight "
            "and rotate the pin."
        ),
        detail={
            "pinned_members": len(hotkeys),
            "matching_members": matching,
            "pin_created_at": _iso(_aware(pin.created_at)),
            "active_bench_version": active,
        },
    )


# ─── Oldest actionable hold ─────────────────────────────────────────────────


def _terminal_status_list() -> str:
    # Closed enum values only, never user input.
    return ", ".join(
        f"'{status.value}'"
        for status in sorted(
            TERMINAL_QUARANTINE_AGENT_STATUSES, key=lambda status: status.value
        )
    )


_HOLDS_SQL = text(
    f"""
    WITH holds AS (
        SELECT 'screening_quarantine' AS kind, q.agent_id, q.created_at AS started_at
          FROM screening_quarantines q
          JOIN agents a ON a.agent_id = q.agent_id
         WHERE q.status = 'active'
           AND a.status NOT IN ({_terminal_status_list()})
        UNION ALL
        SELECT 'ath_review' AS kind, r.agent_id,
               COALESCE(r.reopened_at, r.opened_at) AS started_at
          FROM ath_reviews r
          JOIN agents a ON a.agent_id = r.agent_id
         WHERE r.status = 'pending'
           AND a.status NOT IN ({_terminal_status_list()})
    )
    SELECT (SELECT count(*) FROM holds WHERE kind = 'screening_quarantine')
               AS quarantines,
           (SELECT count(*) FROM holds WHERE kind = 'ath_review') AS ath_reviews,
           oldest.kind, oldest.agent_id, oldest.started_at
      FROM (SELECT 1) one
      LEFT JOIN LATERAL (
        SELECT kind, agent_id, started_at FROM holds
         ORDER BY started_at ASC LIMIT 1
      ) oldest ON true
    """
)


async def hold_signal(session: AsyncSession, *, now: datetime) -> SubnetLivenessSignal:
    """Age of the oldest actionable screening quarantine or ATH hold.

    Reuses the #2554 terminal-ghost exclusion: a hold whose exact agent is
    already banned or rejected is reconciliation work, never actionable age.
    """
    row = (await session.execute(_HOLDS_SQL)).mappings().one()
    started_at = _aware(row["started_at"])
    return _signal(
        "oldest_actionable_hold",
        value=_seconds(now, started_at),
        unit="seconds",
        warn=HOLD_AGE_WARN_SECONDS,
        breach=HOLD_AGE_BREACH_SECONDS,
        since=started_at,
        hint=(
            "A hold has waited long without a decision. Triage with "
            "get_screening_review_queue and list_screening_quarantines; holds "
            "have no published terminal clock yet (#2100)."
        ),
        detail={
            "active_quarantines": int(row["quarantines"] or 0),
            "pending_ath_reviews": int(row["ath_reviews"] or 0),
            "oldest_kind": row["kind"],
            "oldest_agent_id": str(row["agent_id"]) if row["agent_id"] else None,
        },
    )


# ─── Lease overrun ──────────────────────────────────────────────────────────

_TICKET_OVERDUE_SQL = text(
    """
    SELECT agent_id, validator_hotkey, issued_at, deadline
      FROM validator_tickets
     WHERE status = 'issued'
     ORDER BY deadline ASC
     LIMIT 1
    """
)
_TICKET_OLDEST_SQL = text(
    """
    SELECT issued_at, deadline, count(*) OVER () AS open_count
      FROM validator_tickets
     WHERE status = 'issued'
     ORDER BY issued_at ASC
     LIMIT 1
    """
)
_ATTEMPT_OVERDUE_SQL = text(
    """
    SELECT attempt_id, agent_id, started_at, deadline,
           count(*) OVER () AS running_count
      FROM screening_attempts
     WHERE status = 'running'
     ORDER BY deadline ASC
     LIMIT 1
    """
)


async def lease_signal(session: AsyncSession, *, now: datetime) -> SubnetLivenessSignal:
    """Worst overrun of an open validator lease or running screening attempt."""
    ticket = (await session.execute(_TICKET_OVERDUE_SQL)).mappings().first()
    oldest_ticket = (await session.execute(_TICKET_OLDEST_SQL)).mappings().first()
    attempt = (await session.execute(_ATTEMPT_OVERDUE_SQL)).mappings().first()
    candidates: list[tuple[float, str, datetime, Any]] = []
    if ticket is not None:
        deadline = _aware(ticket["deadline"])
        assert deadline is not None
        candidates.append(
            (_seconds(now, deadline), "validator_ticket", deadline, ticket["agent_id"])
        )
    if attempt is not None:
        deadline = _aware(attempt["deadline"])
        assert deadline is not None
        candidates.append(
            (
                _seconds(now, deadline),
                "screening_attempt",
                deadline,
                attempt["agent_id"],
            )
        )
    worst = max(candidates, key=lambda item: item[0], default=None)
    overrun = worst[0] if worst is not None else 0.0
    detail: dict[str, int | float | str | bool | None] = {
        "open_validator_leases": (
            int(oldest_ticket["open_count"]) if oldest_ticket is not None else 0
        ),
        "running_screening_attempts": (
            int(attempt["running_count"]) if attempt is not None else 0
        ),
        "worst_kind": worst[1] if worst is not None and overrun > 0 else None,
        "worst_agent_id": str(worst[3]) if worst is not None and overrun > 0 else None,
    }
    if oldest_ticket is not None:
        issued = _aware(oldest_ticket["issued_at"])
        deadline = _aware(oldest_ticket["deadline"])
        assert issued is not None and deadline is not None
        detail["oldest_validator_lease_age_seconds"] = round(_seconds(now, issued))
        detail["oldest_validator_lease_length_seconds"] = round(
            max(0.0, (deadline - issued).total_seconds())
        )
    if attempt is not None:
        started = _aware(attempt["started_at"])
        detail["running_attempt_age_seconds"] = round(_seconds(now, started))
    return _signal(
        "lease_overrun",
        value=overrun,
        unit="seconds",
        warn=LEASE_OVERRUN_WARN_SECONDS,
        breach=LEASE_OVERRUN_BREACH_SECONDS,
        since=worst[2] if worst is not None and overrun > 0 else None,
        hint=(
            "A lease is open past its deadline, so no expiry sweep ran: no "
            "validator is polling or no screener claim/controller heartbeat "
            "arrived. Check get_validator_capacity and get_screener_capacity."
        ),
        detail=detail,
    )


# ─── Source-emission collector ──────────────────────────────────────────────


def _blocked_reason_class(reason: str | None) -> str | None:
    """Only the exception class name: the message may carry endpoint URLs."""
    if not reason:
        return None
    head = reason.split(":", 1)[0].strip()
    return head if _EXCEPTION_CLASS.fullmatch(head) else "unclassified"


async def collector_signal(
    session: AsyncSession, *, now: datetime, netuid: int
) -> SubnetLivenessSignal:
    cursor = await session.get(SourceEmissionCollectorCursor, netuid)
    if cursor is None:
        return _signal(
            "source_emission_collector",
            value=None,
            unit="seconds",
            warn=COLLECTOR_CURSOR_WARN_SECONDS,
            breach=COLLECTOR_CURSOR_BREACH_SECONDS,
            since=None,
            hint="The collector has not initialized a cursor for this netuid.",
            detail={"netuid": netuid},
        )
    updated_at = _aware(cursor.updated_at)
    return _signal(
        "source_emission_collector",
        value=_seconds(now, updated_at),
        unit="seconds",
        warn=COLLECTOR_CURSOR_WARN_SECONDS,
        breach=COLLECTOR_CURSOR_BREACH_SECONDS,
        since=updated_at,
        hint=(
            "The finalized-block cursor stopped advancing (#2231). Read "
            "release_gate in get_source_release_policy and the "
            "Platform logs."
        ),
        detail={
            "netuid": netuid,
            "cursor_block": int(cursor.block),
            "blocked": cursor.last_blocked_reason is not None,
            "blocked_reason_class": _blocked_reason_class(cursor.last_blocked_reason),
        },
    )


# ─── Rollup ─────────────────────────────────────────────────────────────────

_SEVERITY: dict[LivenessStatus, int] = {"ok": 0, "warn": 1, "breach": 2}


def overall_status(signals: Sequence[SubnetLivenessSignal]) -> LivenessStatus:
    return max(
        (signal.status for signal in signals), key=_SEVERITY.__getitem__, default="ok"
    )


async def load_subnet_liveness(
    session: AsyncSession,
    *,
    environment: str,
    netuid: int,
    now: datetime | None = None,
) -> SubnetLiveness:
    """Compute every signal in one read-only, time-bounded transaction."""
    now = now or datetime.now(UTC)
    if session.in_transaction():
        # The read must own its transaction to make it READ ONLY.
        await session.rollback()
    async with session.begin():
        await session.execute(
            text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        )
        await session.execute(
            text(f"SET LOCAL statement_timeout = {int(STATEMENT_TIMEOUT_MS)}")
        )
        policy = await resolve_screener_policy_activation(session)
        admission = await load_admission_state(
            session,
            environment=environment,
            now=now,
            required_policy=policy.required_policy_version,
        )
        uploads, oldest_upload_at = await claimable_screening_upload_backlog(
            session, now=now, netuid=netuid
        )
        oldest_upload_at = _aware(oldest_upload_at)
        signals = [
            admission_signal(
                admission,
                claimable_uploads=uploads,
                oldest_upload_at=oldest_upload_at,
                now=now,
            ),
            oldest_upload_signal(
                claimable_uploads=uploads, oldest_upload_at=oldest_upload_at, now=now
            ),
            await scoring_signal(session, now=now),
            await scorer_pin_signal(session, now=now),
            await hold_signal(session, now=now),
            await lease_signal(session, now=now),
            await collector_signal(session, now=now, netuid=netuid),
        ]
    return SubnetLiveness(
        generated_at=now,
        environment=environment,
        status=overall_status(signals),
        signals=signals,
        unavailable=list(UNAVAILABLE_SIGNALS),
    )
