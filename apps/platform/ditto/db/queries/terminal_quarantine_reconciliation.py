"""Close screening quarantines left active behind a terminal agent ruling.

A screening quarantine is only actionable while its exact agent row is still
``quarantined``. A scored policy rescreen can record an active quarantine
while the agent keeps its board position, and an ATH ruling can then move that
same agent to ``banned``. Before ditto-subnet#2038 that left an active
quarantine that no guarded resolver could close: the screening court refuses
to rule on a terminal agent, and the ATH court does not own quarantine rows.
The orphan inflated active counts and made review age look worse than the
actionable queue.

These writers now close such a row, each inside the transaction that holds
the exact agent lock, and none ever changes the agent's terminal status or its
miner-visible reason:

* ``resolve_copy_review`` (and the batched ATH rulings built on it) closes the
  matching active quarantine in the same transaction as a terminal ATH reject;
* the owner-only ``resolve_review`` CLI exit does the same for its ban;
* the fenced screening batch resolver closes a pre-existing orphan when an
  operator previews and executes ``reject`` for the exact agent UUID and
  artifact SHA-256.

Each closure appends a ``screening_quarantine_resolutions`` row and a manual
``screening_review_events`` snapshot whose evidence names the terminal ruling,
so the terminal decision and the reconciled quarantine keep one audit trail.
No public moderation record is written: the agent's public status does not
change, and the terminal ruling remains the authoritative outcome.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ditto.api_models.agent_status import AgentStatus
from ditto.db.models import (
    Agent,
    AthReview,
    ScreeningQuarantine,
    ScreeningQuarantineResolution,
)
from ditto.db.queries.screening_review_events import append_manual_review_event

TERMINAL_QUARANTINE_AGENT_STATUSES = frozenset(
    {AgentStatus.BANNED, AgentStatus.REJECTED}
)
"""Agent statuses after which an active quarantine can no longer be ruled on."""

TERMINAL_RECONCILIATION_RESOLUTION = "reject"
"""The only quarantine resolution consistent with a terminal agent ruling."""

ReconciliationSource = Literal["ath_ruling", "operator_reconciliation"]


def is_terminal_quarantine_ghost(quarantine: ScreeningQuarantine, agent: Agent) -> bool:
    """True for an active quarantine whose exact agent is already terminal."""
    return (
        quarantine.status == "active"
        and quarantine.agent_id == agent.agent_id
        and agent.status in TERMINAL_QUARANTINE_AGENT_STATUSES
    )


async def lock_active_quarantines(
    session: AsyncSession, *, agent_id: UUID
) -> list[ScreeningQuarantine]:
    """Row-lock the exact agent's active quarantine, if any.

    The screening resolvers lock the quarantine before the agent. A writer
    that must also close the quarantine takes the same order, so an ATH ruling
    and a concurrent screening resolution serialize instead of deadlocking.
    """
    return list(
        (
            await session.scalars(
                select(ScreeningQuarantine)
                .where(
                    ScreeningQuarantine.agent_id == agent_id,
                    ScreeningQuarantine.status == "active",
                )
                .order_by(ScreeningQuarantine.quarantine_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).all()
    )


async def terminal_ath_ruling(
    session: AsyncSession, *, agent_id: UUID
) -> AthReview | None:
    """The exact agent's resolved ATH reject, when that is its terminal ruling."""
    return await session.scalar(
        select(AthReview).where(
            AthReview.agent_id == agent_id,
            AthReview.status == "resolved",
            AthReview.resolution == "reject",
        )
    )


async def reconcile_terminal_quarantine(
    session: AsyncSession,
    *,
    agent: Agent,
    quarantine: ScreeningQuarantine,
    actor: str,
    reason: str,
    now: datetime,
    source: ReconciliationSource,
    ath_review: AthReview | None,
) -> UUID:
    """Resolve one terminal ghost without touching the agent's ruling.

    The caller holds both row locks. Returns the appended resolution id.
    """
    if not is_terminal_quarantine_ghost(quarantine, agent):
        raise ValueError("quarantine is not an active row behind a terminal agent")
    quarantine.status = "resolved"
    quarantine.resolved_at = now
    quarantine.resolved_by = actor
    quarantine.resolution = TERMINAL_RECONCILIATION_RESOLUTION
    quarantine.resolution_reason = reason
    resolution_id = uuid4()
    session.add(
        ScreeningQuarantineResolution(
            resolution_id=resolution_id,
            quarantine_id=quarantine.quarantine_id,
            resolution=TERMINAL_RECONCILIATION_RESOLUTION,
            reason=reason,
            actor=actor,
            created_at=now,
        )
    )
    await append_manual_review_event(
        session,
        agent=agent,
        quarantine=quarantine,
        resolution_id=resolution_id,
        resolution=TERMINAL_RECONCILIATION_RESOLUTION,
        reason=reason,
        actor=actor,
        prior_agent_status=agent.status,
        next_agent_status=agent.status,
        created_at=now,
        terminal_reconciliation={
            "source": source,
            "agent_status": agent.status.value,
            "artifact_sha256": agent.sha256,
            "ath_review_id": (
                str(ath_review.review_id) if ath_review is not None else None
            ),
            "ath_resolution": ath_review.resolution if ath_review else None,
            "ath_resolved_at": (
                ath_review.resolved_at.isoformat()
                if ath_review is not None and ath_review.resolved_at is not None
                else None
            ),
        },
    )
    return resolution_id


async def close_quarantines_for_terminal_ruling(
    session: AsyncSession,
    *,
    agent: Agent,
    ath_review: AthReview | None,
    actor: str,
    reason: str,
    now: datetime,
) -> list[UUID]:
    """Close every active quarantine behind a just-recorded terminal ATH ruling.

    ``ath_review`` is the durable review row the ruling resolved; it is
    ``None`` only for the legacy CLI ban, which predates ``ath_reviews``.

    Runs in the ruling's transaction after the agent row is locked and moved to
    its terminal status. Re-reading under that lock also catches a quarantine a
    screener committed before the agent lock was granted.
    """
    closed: list[UUID] = []
    for quarantine in await lock_active_quarantines(session, agent_id=agent.agent_id):
        await reconcile_terminal_quarantine(
            session,
            agent=agent,
            quarantine=quarantine,
            actor=actor,
            reason=reason,
            now=now,
            source="ath_ruling",
            ath_review=ath_review,
        )
        closed.append(quarantine.quarantine_id)
    return closed
