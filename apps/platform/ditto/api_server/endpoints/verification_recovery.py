"""Policy-v13 verification readiness ledger and bounded recovery replay.

Four v13 holds are blocked by automated court failures that establish neither
misconduct nor completed verification. Before this module an operator could only
release the hold, reject it, or order a full guarded rescreen that repeats the
expensive source work and can hit the same court failure. Nothing could answer
"which mandatory check is still missing", and nothing could resume only that
check against the committed artifact.

Surfaces:

``GET  /admin/screening-submissions/{agent_id}/verification-readiness``
    A read. Pinned identities, per-check and per-rule evidence state, the last
    sanitized court failure, worker identities, published retry defaults, the
    finalizer read, and any recovery grant with its audit. Unknown evidence is
    ``not_recorded``; nothing is inferred from L1 review notes.

``POST /admin/screening-submissions/{agent_id}/verification-recovery``
    One append-only operator grant authorizing exactly one replay of the
    outstanding mandatory verification on the unchanged committed artifact.

``POST /screener/verification-recovery/claim`` and ``.../{id}/result``
    The screener-facing lease and report for that grant.

Invariants this module holds, and that its tests pin:

- no scheduler or sweep creates, claims, or advances a grant; every transition
  needs an explicit operator or leaseholder call;
- a grant never changes the agent's status and never resolves the quarantine, so
  every hold stays fail-closed whatever the replay reports;
- a replay result is recorded as evidence about the replay. It never produces a
  ``CLEAR``, a misconduct ``REJECT``, or a no-fault ``V1``/``V2``/``V3`` ruling.
  Terminal decisions stay with the published decision record and the
  deadline/retry procedure;
- hidden challenge randomness is generated after the artifact identity is
  confirmed and is released only to the authenticated leaseholder.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ditto.api_models.verification_recovery import (
    AdminVerificationReadiness,
    AdminVerificationRecoveryRequest,
    AdminVerificationRecoveryResponse,
    ScreenerVerificationRecoveryClaim,
    ScreenerVerificationRecoveryResultRequest,
    ScreenerVerificationRecoveryResultResponse,
    VerificationAuditEvent,
    VerificationCheckState,
    VerificationCourtFailure,
    VerificationEvidenceBindings,
    VerificationFinalizerRead,
    VerificationRecoveryView,
    VerificationRuleState,
    VerificationWorkerAttempt,
)
from ditto.api_server.dependencies import get_session
from ditto.api_server.endpoints.admin_quarantine import require_admin
from ditto.api_server.endpoints.screener import require_screener
from ditto.db.models import (
    Agent,
    Score,
    ScreeningAttempt,
    ScreeningQuarantine,
    ScreeningVerificationEvent,
    ScreeningVerificationRecovery,
)
from ditto_screening_protocol import (
    INTEGRITY_CHECK_IDS,
    MANDATORY_VERIFICATION_CHECK_IDS,
    MANDATORY_VERIFICATION_CHECKS,
    NON_DECISIVE_V13_REASON_CODES,
    NOT_RECORDED,
    OPAQUE_ROLE_IDS,
    OPAQUE_ROLES_REQUIRING_PRIVATE_TESTS,
    PUBLISHED_RETRY_DEFAULTS,
    SECURITY_CHECK_IDS,
    AdjudicationRunDiagnostic,
    independent_worker_required,
)

logger = logging.getLogger(__name__)

admin_router = APIRouter(prefix="/admin", tags=["admin"])
screener_router = APIRouter(prefix="/screener", tags=["screener"])

SessionDep = Annotated[AsyncSession, Depends(get_session)]
AdminDep = Annotated[None, Depends(require_admin)]
ScreenerDep = Annotated[str, Depends(require_screener)]

CHALLENGE_MANIFEST_VERSION = 1
"""Version of the recovery challenge manifest this Platform release commits to.

Bumping it invalidates reuse of an earlier grant's challenge material, because
the manifest is one of the bound identities evidence must match."""

DISPATCH_WINDOW = timedelta(minutes=45)
"""How long a claimed grant stays the leaseholder's to report.

Past it the grant is parked as an incomplete platform-domain replay. It is not
requeued: a lapsed lease is a failure, and a further replay needs a new
operator-authorized grant on a new attempt."""

RECOVERY_EVIDENCE_SOURCES = (
    "agents",
    "screening_attempts",
    "screening_quarantines.court_diagnostic",
    "screening_verification_recoveries",
    "screening_verification_events",
)
"""Exactly the stores the ledger reads.

``screening_quarantines.review_notes``, ``review_audit``, ``evidence``, and
``finding`` summaries are deliberately excluded. They are reviewer narrative;
policy v13's evidence standard forbids reading verification evidence out of
them, and #2115 already records that active holds persist no per-check outcome.
"""

_FINALIZER_NOT_CONFIGURED_REASON = (
    "no effective v13 finalizer deadline is deployed; read "
    "get_screening_verification_state (#2100/#2115) for the authoritative "
    "finalizer state rather than computing a deadline here"
)


def _as_utc(value: datetime) -> datetime:
    """Read a stored timestamp as UTC-aware, whatever the driver returned."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _require_actor(actor: str | None) -> str:
    if actor is None or not 1 <= len(actor) <= 120:
        raise HTTPException(status_code=422, detail="X-Admin-Actor is required")
    return actor


def _digest_or_sentinel(value: str | None) -> str:
    """Render a digest, or the explicit ``not_recorded`` sentinel.

    A null digest is never rendered as null: a reader must not be able to read
    "absent" as "does not apply"."""
    return value if value else NOT_RECORDED


def _court_diagnostic(
    quarantine: ScreeningQuarantine | None,
) -> AdjudicationRunDiagnostic | None:
    """Load the sanitized court trace, dropping a row that no longer validates.

    Same handling as the merged ``get_screening_failure_diagnostic`` read: a
    stored trace that no longer matches the model is dropped rather than
    surfaced or raised, so schema drift cannot turn a hold into a 500."""
    if quarantine is None or quarantine.court_diagnostic is None:
        return None
    try:
        return AdjudicationRunDiagnostic.model_validate(quarantine.court_diagnostic)
    except ValidationError:
        logger.warning(
            "verification readiness dropped an invalid court trace attempt_id=%s",
            quarantine.attempt_id,
        )
        return None


def _recovery_view(row: ScreeningVerificationRecovery) -> VerificationRecoveryView:
    """Project a grant for the wire. ``challenge_seed_sealed`` is never included."""
    return VerificationRecoveryView(
        recovery_id=row.recovery_id,
        agent_id=row.agent_id,
        quarantine_id=row.quarantine_id,
        source_attempt_id=row.source_attempt_id,
        artifact_sha256=row.artifact_sha256,
        policy_version=row.policy_version,
        manifest_digest=row.manifest_digest,
        image_digest=row.image_digest,
        state=row.state,
        outstanding_checks=list(row.outstanding_checks),
        reused_evidence=list(row.reused_evidence),
        challenge_commitment=row.challenge_commitment,
        challenge_manifest_version=row.challenge_manifest_version,
        independent_worker_required=row.independent_worker_required,
        excluded_screener_hotkeys=list(row.excluded_screener_hotkeys),
        claimed_by=row.claimed_by,
        claimed_at=row.claimed_at,
        dispatch_deadline=row.dispatch_deadline,
        outcome=row.outcome,
        failure_domain=row.failure_domain,
        completed_checks=(
            list(row.completed_checks) if row.completed_checks is not None else None
        ),
        refuted_leads=(
            list(row.refuted_leads) if row.refuted_leads is not None else None
        ),
        reason=row.reason,
        actor=row.actor,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _event_view(row: ScreeningVerificationEvent) -> VerificationAuditEvent:
    return VerificationAuditEvent(
        event_id=row.event_id,
        event=row.event,
        actor=row.actor,
        detail=row.detail,
        created_at=row.created_at,
    )


def _append_event(
    session: AsyncSession,
    *,
    recovery_id: UUID,
    event: str,
    actor: str,
    detail: dict | None,
    now: datetime,
) -> ScreeningVerificationEvent:
    """Append one audit row. Callers never update or delete an earlier one."""
    row = ScreeningVerificationEvent(
        event_id=uuid4(),
        recovery_id=recovery_id,
        event=event,
        actor=actor,
        detail=detail,
        created_at=now,
    )
    session.add(row)
    return row


def _bindings_match(
    row: ScreeningVerificationRecovery,
    *,
    agent: Agent,
    quarantine: ScreeningQuarantine | None,
) -> bool:
    """Report whether a grant's evidence is still bound to the current artifact.

    Policy v13 permits reusing earlier evidence "only when all bound identities
    and relevant configuration are identical". A changed artifact SHA, screened
    image, policy version, or policy manifest makes the earlier result evidence
    about a different thing."""
    return (
        row.artifact_sha256 == agent.sha256
        and row.image_digest == agent.screened_image_sha256
        and row.challenge_manifest_version == CHALLENGE_MANIFEST_VERSION
        and quarantine is not None
        and row.policy_version == quarantine.policy_version
        and row.manifest_digest == quarantine.manifest_digest
    )


async def _load_readiness_inputs(
    session: AsyncSession, agent_id: UUID
) -> tuple[
    Agent,
    ScreeningQuarantine | None,
    list[ScreeningAttempt],
    ScreeningVerificationRecovery | None,
    list[ScreeningVerificationEvent],
]:
    agent = await session.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="screening submission not found")
    quarantine = await session.scalar(
        select(ScreeningQuarantine)
        .where(ScreeningQuarantine.agent_id == agent_id)
        .order_by(
            ScreeningQuarantine.created_at.desc(),
            ScreeningQuarantine.quarantine_id.desc(),
        )
        .limit(1)
    )
    attempts = list(
        (
            await session.scalars(
                select(ScreeningAttempt)
                .where(ScreeningAttempt.agent_id == agent_id)
                .order_by(
                    ScreeningAttempt.started_at.asc(),
                    ScreeningAttempt.attempt_id.asc(),
                )
            )
        ).all()
    )
    recovery = await session.scalar(
        select(ScreeningVerificationRecovery)
        .where(ScreeningVerificationRecovery.agent_id == agent_id)
        .order_by(
            ScreeningVerificationRecovery.created_at.desc(),
            ScreeningVerificationRecovery.recovery_id.desc(),
        )
        .limit(1)
    )
    events: list[ScreeningVerificationEvent] = []
    if recovery is not None:
        events = list(
            (
                await session.scalars(
                    select(ScreeningVerificationEvent)
                    .where(
                        ScreeningVerificationEvent.recovery_id == recovery.recovery_id
                    )
                    .order_by(
                        ScreeningVerificationEvent.created_at.asc(),
                        ScreeningVerificationEvent.event_id.asc(),
                    )
                )
            ).all()
        )
    return agent, quarantine, attempts, recovery, events


def _check_states(
    *,
    agent: Agent,
    quarantine: ScreeningQuarantine | None,
    recovery: ScreeningVerificationRecovery | None,
) -> list[VerificationCheckState]:
    """Report each published check's recorded state, defaulting to not_recorded.

    ``completed`` requires a recovery grant whose bound identities still match
    the current artifact and whose report named the check. Nothing else in the
    schema persists a per-check outcome today, so every other check reads
    ``not_recorded`` — the honest answer, and never a pass."""
    completed: set[str] = set()
    covered: set[str] = set()
    if recovery is not None and _bindings_match(
        recovery, agent=agent, quarantine=quarantine
    ):
        covered = set(recovery.outstanding_checks)
        if recovery.completed_checks:
            completed = (
                set(recovery.completed_checks) & MANDATORY_VERIFICATION_CHECK_IDS
            )
    states: list[VerificationCheckState] = []
    for check in MANDATORY_VERIFICATION_CHECKS:
        if check.check_id in completed:
            state = "completed"
        elif (
            recovery is not None
            and recovery.state == "failed"
            and (check.check_id in covered)
        ):
            state = "outstanding"
        else:
            state = NOT_RECORDED
        states.append(
            VerificationCheckState(
                check_id=check.check_id,
                ordinal=check.ordinal,
                lane=check.lane,
                title=check.title,
                state=state,
            )
        )
    return states


def _rule_states(
    rule_ids: tuple[str, ...],
    *,
    agent: Agent,
    quarantine: ScreeningQuarantine | None,
    recovery: ScreeningVerificationRecovery | None,
) -> list[VerificationRuleState]:
    """Report each I1-I8 / S1-S3 rule. A refuted lead is not a clearance.

    No stored field records a per-rule decision, and a quarantine finding's
    free-text categories are not a reason-code mapping, so the only non-default
    state is a lead an artifact-bound replay explicitly refuted."""
    refuted: set[str] = set()
    if (
        recovery is not None
        and recovery.refuted_leads
        and _bindings_match(recovery, agent=agent, quarantine=quarantine)
    ):
        refuted = set(recovery.refuted_leads)
    return [
        VerificationRuleState(
            rule_id=rule_id,
            state="refuted" if rule_id in refuted else NOT_RECORDED,
        )
        for rule_id in rule_ids
    ]


def _opaque_role_states() -> list[VerificationRuleState]:
    """Report every published opaque role as unrecorded, with its test duty.

    No artifact-bound opaque-component manifest is persisted, so no role can be
    reported as satisfied. ``private_tests_required`` is the published role
    requirement, not a claim about this artifact."""
    return [
        VerificationRuleState(
            rule_id=role_id,
            state=NOT_RECORDED,
            private_tests_required=role_id in OPAQUE_ROLES_REQUIRING_PRIVATE_TESTS,
        )
        for role_id in OPAQUE_ROLE_IDS
    ]


def _outstanding_check_ids(states: list[VerificationCheckState]) -> list[str]:
    return [state.check_id for state in states if state.state != "completed"]


def _reusable_check_ids(states: list[VerificationCheckState]) -> list[str]:
    return [state.check_id for state in states if state.state == "completed"]


async def _build_readiness(
    session: AsyncSession, agent_id: UUID
) -> AdminVerificationReadiness:
    agent, quarantine, attempts, recovery, events = await _load_readiness_inputs(
        session, agent_id
    )
    source_attempt = None
    if quarantine is not None:
        source_attempt = next(
            (
                attempt
                for attempt in attempts
                if attempt.attempt_id == quarantine.attempt_id
            ),
            None,
        )
    diagnostic = _court_diagnostic(quarantine)
    checks = _check_states(agent=agent, quarantine=quarantine, recovery=recovery)
    opaque_roles = _opaque_role_states()
    inventory_recorded = any(
        state.check_id == "opaque_component_inventory" and state.state == "completed"
        for state in checks
    )
    # With no recorded opaque inventory there is no basis to assert the private
    # paired suite does not apply, so this stays null rather than False.
    private_paired_required = (
        None
        if not inventory_recorded
        or any(role.state == NOT_RECORDED for role in opaque_roles)
        else any(bool(role.private_tests_required) for role in opaque_roles)
    )
    is_non_decisive = (
        quarantine is not None
        and quarantine.status == "active"
        and quarantine.reason_code in NON_DECISIVE_V13_REASON_CODES
    )
    return AdminVerificationReadiness(
        agent_id=agent_id,
        agent_status=agent.status,
        artifact_sha256=agent.sha256,
        policy_version=(
            quarantine.policy_version
            if quarantine is not None
            else agent.screening_policy_version
        ),
        quarantine_id=quarantine.quarantine_id if quarantine is not None else None,
        quarantine_status=quarantine.status if quarantine is not None else None,
        quarantine_reason_code=(
            quarantine.reason_code if quarantine is not None else None
        ),
        has_established_finding=(
            quarantine is not None and quarantine.finding_digest is not None
        ),
        is_non_decisive_hold=is_non_decisive,
        evidence_bindings=VerificationEvidenceBindings(
            artifact_sha256=agent.sha256,
            image_digest=_digest_or_sentinel(agent.screened_image_sha256),
            policy_digest=_digest_or_sentinel(
                quarantine.manifest_digest if quarantine is not None else None
            ),
            opaque_manifest_digest=NOT_RECORDED,
            verification_profile_digest=NOT_RECORDED,
            challenge_manifest_digest=_digest_or_sentinel(
                recovery.challenge_commitment if recovery is not None else None
            ),
        ),
        mandatory_checks=checks,
        outstanding_mandatory_checks=_outstanding_check_ids(checks),
        integrity_rules=_rule_states(
            INTEGRITY_CHECK_IDS, agent=agent, quarantine=quarantine, recovery=recovery
        ),
        security_rules=_rule_states(
            SECURITY_CHECK_IDS, agent=agent, quarantine=quarantine, recovery=recovery
        ),
        opaque_roles=opaque_roles,
        private_paired_required=private_paired_required,
        last_court_failure=(
            VerificationCourtFailure(
                attempt_id=quarantine.attempt_id,
                reason_code=quarantine.reason_code,
                stage=diagnostic.timeout_stage if diagnostic is not None else None,
                diagnostic=diagnostic,
            )
            if quarantine is not None
            else None
        ),
        attempts=[
            VerificationWorkerAttempt(
                attempt_id=attempt.attempt_id,
                screener_hotkey=attempt.screener_hotkey,
                policy_version=attempt.policy_version,
                status=attempt.status,
                reason_code=attempt.reason_code,
                failure_provider=attempt.failure_provider,
                started_at=attempt.started_at,
                finished_at=attempt.finished_at,
            )
            for attempt in attempts
        ],
        attempts_recorded=len(attempts),
        distinct_workers=len({attempt.screener_hotkey for attempt in attempts}),
        published_retry_defaults=PUBLISHED_RETRY_DEFAULTS,
        finalizer=VerificationFinalizerRead(
            finalizer_state="not_configured",
            finalizer_reason=_FINALIZER_NOT_CONFIGURED_REASON,
            verification_deadline=None,
            deadline_provenance=None,
            attempt_deadline=(
                source_attempt.deadline if source_attempt is not None else None
            ),
            source="screening_verification_state",
        ),
        recovery=_recovery_view(recovery) if recovery is not None else None,
        recovery_audit=[_event_view(event) for event in events],
        evidence_sources=list(RECOVERY_EVIDENCE_SOURCES),
        generated_at=datetime.now(UTC),
    )


@admin_router.get(
    "/screening-submissions/{agent_id}/verification-readiness",
    response_model=AdminVerificationReadiness,
)
async def get_verification_readiness(
    agent_id: UUID,
    _admin: AdminDep,
    session: SessionDep,
    x_admin_actor: Annotated[str | None, Header()] = None,
) -> AdminVerificationReadiness:
    """Report what this exact artifact has proved and what is still missing.

    Reading changes nothing: it does not clear, reject, rescreen, or queue any
    work, and it never reports an unrecorded check as passed."""
    actor = _require_actor(x_admin_actor)
    readiness = await _build_readiness(session, agent_id)
    logger.info(
        "admin_actor=%s read verification readiness agent_id=%s reason_code=%s "
        "outstanding=%d",
        actor,
        agent_id,
        readiness.quarantine_reason_code,
        len(readiness.outstanding_mandatory_checks),
    )
    return readiness


@admin_router.post(
    "/screening-submissions/{agent_id}/verification-recovery",
    response_model=AdminVerificationRecoveryResponse,
)
async def authorize_verification_recovery(
    agent_id: UUID,
    payload: AdminVerificationRecoveryRequest,
    _admin: AdminDep,
    session: SessionDep,
    x_admin_actor: Annotated[str | None, Header()] = None,
) -> AdminVerificationRecoveryResponse:
    """Authorize exactly one replay of the outstanding mandatory verification.

    Every pinned identity is a compare-and-swap guard, so a stale operator view
    cannot authorize work against an artifact, image, policy, or attempt that
    has since moved. The hold is untouched: this grants verification work, not a
    decision, and a completed replay still needs the published decision record.
    """
    actor = _require_actor(x_admin_actor)
    now = datetime.now(UTC)
    idempotent = False
    async with session.begin():
        agent = await session.scalar(
            select(Agent).where(Agent.agent_id == agent_id).with_for_update()
        )
        if agent is None:
            raise HTTPException(status_code=404, detail="agent not found")
        if agent.sha256 != payload.expected_sha256:
            raise HTTPException(status_code=409, detail="artifact identity changed")
        if agent.screened_image_sha256 != payload.expected_image_digest:
            raise HTTPException(status_code=409, detail="screened image changed")
        score_count = int(
            await session.scalar(
                select(func.count())
                .select_from(Score)
                .where(Score.agent_id == agent_id)
            )
            or 0
        )
        if score_count != payload.expected_score_count:
            raise HTTPException(status_code=409, detail="score count changed")
        attempt_count = int(
            await session.scalar(
                select(func.count())
                .select_from(ScreeningAttempt)
                .where(ScreeningAttempt.agent_id == agent_id)
            )
            or 0
        )
        if attempt_count != payload.expected_attempt_count:
            raise HTTPException(
                status_code=409, detail="screening attempt count changed"
            )
        quarantine = await session.scalar(
            select(ScreeningQuarantine)
            .where(
                ScreeningQuarantine.quarantine_id == payload.expected_quarantine_id,
                ScreeningQuarantine.agent_id == agent_id,
            )
            .with_for_update()
        )
        if quarantine is None or quarantine.status != "active":
            raise HTTPException(status_code=409, detail="screening quarantine changed")
        if quarantine.attempt_id != payload.expected_attempt_id:
            raise HTTPException(status_code=409, detail="screening attempt changed")
        if quarantine.policy_version != payload.expected_policy_version:
            raise HTTPException(status_code=409, detail="screening policy changed")
        if quarantine.manifest_digest != payload.expected_manifest_digest:
            raise HTTPException(status_code=409, detail="policy manifest changed")
        if quarantine.reason_code not in NON_DECISIVE_V13_REASON_CODES:
            raise HTTPException(
                status_code=409,
                detail="hold is not a non-decisive verification gap",
            )
        if quarantine.finding_digest is not None:
            raise HTTPException(
                status_code=409,
                detail="hold carries an established finding; use the decision path",
            )
        existing = await session.scalar(
            select(ScreeningVerificationRecovery)
            .where(
                ScreeningVerificationRecovery.source_attempt_id
                == payload.expected_attempt_id
            )
            .with_for_update()
        )
        if existing is not None:
            if (
                existing.artifact_sha256 != payload.expected_sha256
                or existing.manifest_digest != payload.expected_manifest_digest
                or existing.image_digest != payload.expected_image_digest
                or existing.policy_version != payload.expected_policy_version
            ):
                raise HTTPException(
                    status_code=409, detail="verification recovery guards changed"
                )
            if existing.state not in {"queued", "dispatched"}:
                raise HTTPException(
                    status_code=409,
                    detail="verification recovery for this attempt is terminal",
                )
            recovery = existing
            idempotent = True
        else:
            open_recovery = await session.scalar(
                select(ScreeningVerificationRecovery.recovery_id).where(
                    ScreeningVerificationRecovery.agent_id == agent_id,
                    ScreeningVerificationRecovery.state.in_(("queued", "dispatched")),
                )
            )
            if open_recovery is not None:
                raise HTTPException(
                    status_code=409,
                    detail="an open verification recovery already exists",
                )
            running_attempt = await session.scalar(
                select(ScreeningAttempt.attempt_id).where(
                    ScreeningAttempt.agent_id == agent_id,
                    ScreeningAttempt.status == "running",
                )
            )
            if running_attempt is not None:
                raise HTTPException(
                    status_code=409, detail="screening attempt is active"
                )
            attempts = list(
                (
                    await session.scalars(
                        select(ScreeningAttempt).where(
                            ScreeningAttempt.agent_id == agent_id
                        )
                    )
                ).all()
            )
            prior = await session.scalar(
                select(ScreeningVerificationRecovery)
                .where(ScreeningVerificationRecovery.agent_id == agent_id)
                .order_by(ScreeningVerificationRecovery.created_at.desc())
                .limit(1)
            )
            checks = _check_states(agent=agent, quarantine=quarantine, recovery=prior)
            outstanding = _outstanding_check_ids(checks)
            reusable = _reusable_check_ids(checks)
            # The artifact is committed and its identity is confirmed above;
            # only now is the hidden randomness drawn, so no challenge material
            # predates the bytes it will probe.
            seed = secrets.token_hex(32)
            recovery = ScreeningVerificationRecovery(
                recovery_id=uuid4(),
                agent_id=agent_id,
                quarantine_id=quarantine.quarantine_id,
                source_attempt_id=payload.expected_attempt_id,
                artifact_sha256=agent.sha256,
                policy_version=quarantine.policy_version,
                manifest_digest=quarantine.manifest_digest,
                image_digest=agent.screened_image_sha256,
                expected_score_count=score_count,
                expected_attempt_count=attempt_count,
                outstanding_checks=outstanding,
                reused_evidence=reusable,
                challenge_commitment=hashlib.sha256(seed.encode()).hexdigest(),
                challenge_manifest_version=CHALLENGE_MANIFEST_VERSION,
                challenge_seed_sealed=seed,
                # The published procedure requires an independent worker for a
                # platform or provider verification failure, and a non-decisive
                # infrastructure hold is at minimum one of those. Recording the
                # requirement is retry conduct, not a failure-domain ruling.
                independent_worker_required=independent_worker_required("platform"),
                excluded_screener_hotkeys=sorted(
                    {attempt.screener_hotkey for attempt in attempts}
                ),
                state="queued",
                reason=payload.reason,
                actor=actor,
                created_at=now,
                updated_at=now,
            )
            session.add(recovery)
            await session.flush()
            _append_event(
                session,
                recovery_id=recovery.recovery_id,
                event="authorized",
                actor=actor,
                detail={
                    "reason_code": quarantine.reason_code,
                    "outstanding_checks": outstanding,
                    "reused_evidence": reusable,
                    "challenge_commitment": recovery.challenge_commitment,
                    "independent_worker_required": (
                        recovery.independent_worker_required
                    ),
                },
                now=now,
            )
        await session.flush()
        events = list(
            (
                await session.scalars(
                    select(ScreeningVerificationEvent)
                    .where(
                        ScreeningVerificationEvent.recovery_id == recovery.recovery_id
                    )
                    .order_by(
                        ScreeningVerificationEvent.created_at.asc(),
                        ScreeningVerificationEvent.event_id.asc(),
                    )
                )
            ).all()
        )
        response = AdminVerificationRecoveryResponse(
            recovery=_recovery_view(recovery),
            audit=[_event_view(event) for event in events],
            idempotent=idempotent,
            agent_status=agent.status,
            quarantine_status=quarantine.status,
        )
    logger.info(
        "admin_actor=%s authorized verification recovery agent_id=%s attempt_id=%s "
        "recovery_id=%s idempotent=%s outstanding=%d",
        actor,
        agent_id,
        payload.expected_attempt_id,
        response.recovery.recovery_id,
        idempotent,
        len(response.recovery.outstanding_checks),
    )
    return response


@screener_router.post(
    "/verification-recovery/claim",
    response_model=ScreenerVerificationRecoveryClaim | None,
)
async def claim_verification_recovery(
    screener_hotkey: ScreenerDep,
    session: SessionDep,
) -> ScreenerVerificationRecoveryClaim | None:
    """Lease at most one operator-authorized verification replay.

    Returns null when nothing is authorized for this worker. A worker that
    already attempted the artifact is skipped while the grant requires an
    independent one, and a grant whose artifact moved since authorization is
    canceled rather than dispatched."""
    now = datetime.now(UTC)
    async with session.begin():
        candidates = list(
            (
                await session.scalars(
                    select(ScreeningVerificationRecovery)
                    .where(ScreeningVerificationRecovery.state == "queued")
                    .order_by(
                        ScreeningVerificationRecovery.created_at.asc(),
                        ScreeningVerificationRecovery.recovery_id.asc(),
                    )
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        for row in candidates:
            if row.independent_worker_required and screener_hotkey in set(
                row.excluded_screener_hotkeys
            ):
                continue
            agent = await session.get(Agent, row.agent_id)
            if agent is None or agent.sha256 != row.artifact_sha256:
                row.state = "canceled"
                row.updated_at = now
                _append_event(
                    session,
                    recovery_id=row.recovery_id,
                    event="canceled_artifact_changed",
                    actor=screener_hotkey,
                    detail={"expected_sha256": row.artifact_sha256},
                    now=now,
                )
                continue
            row.state = "dispatched"
            row.claimed_by = screener_hotkey
            row.claimed_at = now
            row.dispatch_deadline = now + DISPATCH_WINDOW
            row.updated_at = now
            _append_event(
                session,
                recovery_id=row.recovery_id,
                event="dispatched",
                actor=screener_hotkey,
                detail={
                    "outstanding_checks": list(row.outstanding_checks),
                    "challenge_commitment": row.challenge_commitment,
                },
                now=now,
            )
            claim = ScreenerVerificationRecoveryClaim(
                recovery_id=row.recovery_id,
                agent_id=row.agent_id,
                artifact_sha256=row.artifact_sha256,
                policy_version=row.policy_version,
                manifest_digest=row.manifest_digest,
                image_digest=row.image_digest,
                outstanding_checks=list(row.outstanding_checks),
                reused_evidence=list(row.reused_evidence),
                challenge_commitment=row.challenge_commitment,
                challenge_manifest_version=row.challenge_manifest_version,
                challenge_seed=row.challenge_seed_sealed,
                dispatch_deadline=row.dispatch_deadline,
                claimed_by=screener_hotkey,
            )
            logger.info(
                "screener=%s claimed verification recovery recovery_id=%s agent_id=%s",
                screener_hotkey,
                row.recovery_id,
                row.agent_id,
            )
            return claim
    return None


@screener_router.post(
    "/verification-recovery/{recovery_id}/result",
    response_model=ScreenerVerificationRecoveryResultResponse,
)
async def report_verification_recovery(
    recovery_id: UUID,
    payload: ScreenerVerificationRecoveryResultRequest,
    screener_hotkey: ScreenerDep,
    session: SessionDep,
) -> ScreenerVerificationRecoveryResultResponse:
    """Record what the replay proved. It never decides the hold.

    A complete report must cover every check the grant authorized; an incomplete
    one must name its failure domain. Either way the agent's status and the
    quarantine are untouched, so a failed or partial replay cannot become a
    clearance and cannot become a V1/V2/V3 rejection."""
    unknown_checks = sorted(
        set(payload.completed_checks) - MANDATORY_VERIFICATION_CHECK_IDS
    )
    if unknown_checks:
        raise HTTPException(
            status_code=422,
            detail=f"unknown mandatory check ids: {', '.join(unknown_checks)}",
        )
    known_rules = set(INTEGRITY_CHECK_IDS) | set(SECURITY_CHECK_IDS)
    unknown_leads = sorted(set(payload.refuted_leads) - known_rules)
    if unknown_leads:
        raise HTTPException(
            status_code=422,
            detail=f"unknown rule ids: {', '.join(unknown_leads)}",
        )
    if (
        payload.outcome == "verification_complete"
        and payload.failure_domain is not None
    ):
        raise HTTPException(
            status_code=422,
            detail="a complete verification does not carry a failure domain",
        )
    if payload.outcome == "verification_incomplete" and payload.failure_domain is None:
        raise HTTPException(
            status_code=422,
            detail="an incomplete verification must name its failure domain",
        )
    now = datetime.now(UTC)
    # A guard that has to park the grant first records that park, commits it,
    # and only then refuses: raising inside the transaction would roll the
    # append-only audit row back with it.
    refusal: str | None = None
    response: ScreenerVerificationRecoveryResultResponse | None = None
    async with session.begin():
        row = await session.scalar(
            select(ScreeningVerificationRecovery)
            .where(ScreeningVerificationRecovery.recovery_id == recovery_id)
            .with_for_update()
        )
        if row is None:
            raise HTTPException(
                status_code=404, detail="verification recovery not found"
            )
        if row.claimed_by != screener_hotkey:
            raise HTTPException(
                status_code=403,
                detail="verification recovery is leased to another worker",
            )
        if row.state != "dispatched":
            raise HTTPException(
                status_code=409, detail="verification recovery is not dispatched"
            )
        deadline = (
            _as_utc(row.dispatch_deadline)
            if row.dispatch_deadline is not None
            else None
        )
        agent = await session.scalar(
            select(Agent).where(Agent.agent_id == row.agent_id).with_for_update()
        )
        if deadline is not None and now > deadline:
            # A lapsed lease is an incomplete platform-domain replay, not a
            # ruling and not a fresh retry: another replay needs a new grant.
            row.state = "failed"
            row.outcome = "verification_incomplete"
            row.failure_domain = "platform"
            row.completed_checks = []
            row.updated_at = now
            _append_event(
                session,
                recovery_id=row.recovery_id,
                event="lease_expired",
                actor=screener_hotkey,
                detail={"dispatch_deadline": deadline.isoformat()},
                now=now,
            )
            refusal = "verification recovery lease expired"
        elif agent is None or agent.sha256 != row.artifact_sha256:
            row.state = "canceled"
            row.updated_at = now
            _append_event(
                session,
                recovery_id=row.recovery_id,
                event="canceled_artifact_changed",
                actor=screener_hotkey,
                detail={"expected_sha256": row.artifact_sha256},
                now=now,
            )
            refusal = "artifact identity changed"
        else:
            completed = sorted(set(payload.completed_checks))
            if payload.outcome == "verification_complete" and not set(
                row.outstanding_checks
            ) <= set(completed):
                # Accepting a partial report as complete is how an incomplete
                # replay would turn into a clearance. It is refused instead, and
                # the grant stays dispatched for a covering report.
                raise HTTPException(
                    status_code=409,
                    detail="reported completion does not cover the authorized checks",
                )
            row.state = (
                "completed" if payload.outcome == "verification_complete" else "failed"
            )
            row.outcome = payload.outcome
            row.failure_domain = payload.failure_domain
            row.completed_checks = completed
            row.refuted_leads = sorted(set(payload.refuted_leads))
            row.updated_at = now
            _append_event(
                session,
                recovery_id=row.recovery_id,
                event="reported",
                actor=screener_hotkey,
                detail={
                    "outcome": payload.outcome,
                    "failure_domain": payload.failure_domain,
                    "completed_checks": completed,
                    "refuted_leads": row.refuted_leads,
                    "detail_code": payload.detail_code,
                },
                now=now,
            )
            quarantine = await session.get(ScreeningQuarantine, row.quarantine_id)
            response = ScreenerVerificationRecoveryResultResponse(
                recovery=_recovery_view(row),
                agent_status=agent.status,
                quarantine_status=(
                    quarantine.status if quarantine is not None else NOT_RECORDED
                ),
                decision_recorded=False,
            )
    if refusal is not None:
        raise HTTPException(status_code=409, detail=refusal)
    assert response is not None
    logger.info(
        "screener=%s reported verification recovery recovery_id=%s outcome=%s "
        "failure_domain=%s completed=%d refuted=%d",
        screener_hotkey,
        recovery_id,
        payload.outcome,
        payload.failure_domain,
        len(response.recovery.completed_checks or []),
        len(response.recovery.refuted_leads or []),
    )
    return response
