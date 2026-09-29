"""Ownership-gated builder for miner-private screening diagnostics."""

from __future__ import annotations

from typing import get_args
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ditto.api_models.miner_screening_feedback import (
    MinerAdjudicationRefusal,
    MinerScreeningAdjudication,
    MinerScreeningCitation,
    MinerScreeningFailure,
    MinerScreeningFeedbackResponse,
    MinerScreeningReviewNote,
)
from ditto.api_server.deferred_source_review import verified_review_notes
from ditto.db.models import (
    Agent,
    ScreeningAttempt,
    ScreeningQuarantine,
    ScreeningReviewEvent,
)
from ditto_screening_protocol.models import (
    SourceReviewAdjudication,
    SourceReviewNote,
    source_review_notes_digest,
)

_KNOWN_REFUSALS: frozenset[str] = frozenset(get_args(MinerAdjudicationRefusal))
_EMPTY_LEDGER_DIGEST = source_review_notes_digest([])


def _owner_notes(raw_notes: object, digest: object) -> list[SourceReviewNote] | None:
    """The recorded ledger only if it verifies against its signed digest.

    The automated review event stores an empty ledger as ``None`` beside the
    digest of ``[]``; that is a verified empty ledger, not a missing one.
    """
    if raw_notes is None and digest == _EMPTY_LEDGER_DIGEST:
        return []
    return verified_review_notes(raw_notes, digest)


def _project_notes(notes: list[SourceReviewNote]) -> list[MinerScreeningReviewNote]:
    return [
        MinerScreeningReviewNote(
            kind=note.kind,
            category=note.category,
            path=note.path,
            line=note.line,
            summary=note.summary,
        )
        for note in notes
    ]


def _project_adjudication(
    evidence: dict, *, policy_version: int
) -> MinerScreeningAdjudication | None:
    """The court decision only if it verifies against its signed digest.

    Operator metadata on the record (model, prompt revision, notes count, run
    diagnostic, completion receipt) is dropped by construction.
    """
    raw = evidence.get("adjudication")
    if not isinstance(raw, dict):
        return None
    try:
        adjudication = SourceReviewAdjudication.model_validate(raw)
    except ValidationError:
        return None
    if (
        adjudication.canonical_digest() != evidence.get("adjudication_digest")
        or adjudication.policy_version != policy_version
    ):
        return None
    refusal = (
        adjudication.escalation_code
        if adjudication.decision == "escalate"
        and adjudication.escalation_code in _KNOWN_REFUSALS
        else None
    )
    return MinerScreeningAdjudication(
        decision=adjudication.decision,
        reason=adjudication.reason,
        reject_invariant=(
            str(adjudication.reject_invariant)
            if adjudication.reject_invariant is not None
            else None
        ),
        clear_clause=(
            str(adjudication.clear_clause)
            if adjudication.clear_clause is not None
            else None
        ),
        citations=[
            MinerScreeningCitation(path=citation.path, line=citation.line)
            for citation in adjudication.citations
        ],
        refusal=refusal,  # type: ignore[arg-type]
    )


async def load_owned_screening_feedback(
    session: AsyncSession,
    *,
    hotkey: str,
    agent_id: UUID,
) -> MinerScreeningFeedbackResponse | None:
    """Every screening attempt's private feedback for one of ``hotkey``'s agents.

    ``None`` when the agent does not exist or belongs to another hotkey; the
    caller maps both to the same 404. Review notes and the court decision come
    from the attempt's signed automated review event, falling back to its
    quarantine record for the notes; anything that does not verify against its
    recorded digest is omitted rather than shown.
    """
    agent = await session.scalar(
        select(Agent).where(
            Agent.agent_id == agent_id,
            Agent.miner_hotkey == hotkey,
        )
    )
    if agent is None:
        return None
    attempts = (
        await session.scalars(
            select(ScreeningAttempt)
            .where(ScreeningAttempt.agent_id == agent_id)
            .order_by(ScreeningAttempt.started_at.desc())
        )
    ).all()
    events = {
        event.attempt_id: event
        for event in (
            await session.scalars(
                select(ScreeningReviewEvent).where(
                    ScreeningReviewEvent.agent_id == agent_id,
                    ScreeningReviewEvent.event_kind == "automated",
                )
            )
        ).all()
    }
    quarantines = {
        quarantine.attempt_id: quarantine
        for quarantine in (
            await session.scalars(
                select(ScreeningQuarantine).where(
                    ScreeningQuarantine.agent_id == agent_id
                )
            )
        ).all()
    }

    def review_for(
        attempt: ScreeningAttempt,
    ) -> tuple[list[MinerScreeningReviewNote], MinerScreeningAdjudication | None]:
        event = events.get(attempt.attempt_id)
        evidence = (
            event.evidence
            if event is not None and isinstance(event.evidence, dict)
            else {}
        )
        notes = _owner_notes(
            evidence.get("review_notes"), evidence.get("review_notes_digest")
        )
        quarantine = quarantines.get(attempt.attempt_id)
        if notes is None and quarantine is not None:
            notes = _owner_notes(
                quarantine.review_notes, quarantine.review_notes_digest
            )
        return (
            _project_notes(notes or []),
            _project_adjudication(evidence, policy_version=attempt.policy_version),
        )

    items: list[MinerScreeningFailure] = []
    for item in attempts:
        review_notes, adjudication = review_for(item)
        items.append(
            MinerScreeningFailure(
                attempt_id=item.attempt_id,
                status=item.status,
                policy_version=item.policy_version,
                started_at=item.started_at,
                finished_at=item.finished_at,
                reason_code=item.reason_code,
                public_reason=item.public_reason,
                provider=item.failure_provider,
                lane=item.failure_lane,
                detail=item.private_failure_detail,
                log_tail=item.private_failure_log_tail,
                captured_at=item.failure_captured_at,
                review_notes=review_notes,
                adjudication=adjudication,
            )
        )
    return MinerScreeningFeedbackResponse(
        agent_id=agent.agent_id,
        miner_hotkey=agent.miner_hotkey,
        agent_status=str(agent.status),
        attempts=items,
    )
