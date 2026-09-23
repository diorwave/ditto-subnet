"""Operator and screener wire models for policy-v13 verification recovery.

Two surfaces live here:

- a read-only per-agent *readiness ledger* that answers "what has this exact
  artifact actually proved, and what is still missing"; and
- a bounded operator *recovery grant* that resumes only the missing mandatory
  verification against the unchanged committed artifact.

Neither one decides anything. Unknown evidence serializes as ``not_recorded``
(never ``false``, never inferred from L1 review notes), and a recovery report is
recorded as evidence about the replay rather than as a CLEAR, a REJECT, or a
no-fault V1/V2/V3 ruling. Terminal decisions stay with the published decision
record and the deadline/retry procedure.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from ditto_screening_protocol import (
    AdjudicationRunDiagnostic,
    PublishedRetryDefaults,
    VerificationEvidenceState,
    VerificationLane,
    VerificationRecoveryFailureDomain,
    VerificationRecoveryOutcome,
    VerificationRecoveryState,
)

RESUME_VERIFICATION_CONFIRMATION = "RESUME MANDATORY VERIFICATION ON THIS ARTIFACT"
"""The operator phrase :class:`AdminVerificationRecoveryRequest` pins.

Kept next to the model so a test can assert the two agree; the model spells the
literal inline because FastAPI needs it in the published schema.
"""

Digest = Annotated[str, Field(pattern=r"^(?:[0-9a-f]{64}|not_recorded)$")]
"""A 64-hex digest or the explicit ``not_recorded`` sentinel.

Typed as a string rather than ``str | None`` on purpose: a null would let a
reader treat missing evidence as "no digest applies", which is exactly the
inference policy v13's evidence standard forbids.
"""


class VerificationCheckState(BaseModel):
    """One published mandatory check and what the store actually holds."""

    model_config = ConfigDict(extra="ignore")

    check_id: str
    ordinal: int
    lane: VerificationLane
    title: str
    state: VerificationEvidenceState


class VerificationRuleState(BaseModel):
    """One I1-I8 / S1-S3 decision, or an opaque role's evidence state."""

    model_config = ConfigDict(extra="ignore")

    rule_id: str
    state: VerificationEvidenceState
    private_tests_required: bool | None = None
    """True when the published role requirement makes private paired testing
    mandatory. Null for the I/S rules, where it is not a role property."""


class VerificationEvidenceBindings(BaseModel):
    """The exact identities earlier evidence would have to match to be reused.

    One field per bound identity in policy v13's "Exact-artifact scope" that can
    be expressed as a digest. ``policy_digest`` is the manifest digest bound
    into the screener's signed verdict, which is the same value #2115 reports
    under that name.
    """

    model_config = ConfigDict(extra="ignore")

    artifact_sha256: Digest
    image_digest: Digest
    policy_digest: Digest
    opaque_manifest_digest: Digest
    verification_profile_digest: Digest
    challenge_manifest_digest: Digest


class VerificationCourtFailure(BaseModel):
    """The last automated-court failure on this hold.

    Reuses the sanitized ``AdjudicationRunDiagnostic`` trace shipped by #2095
    and #2102 instead of introducing a second court-failure shape.
    """

    model_config = ConfigDict(extra="ignore")

    attempt_id: UUID | None
    reason_code: str | None
    stage: str | None
    """``timeout_stage`` from the reused trace, or null when it recorded none."""

    diagnostic: AdjudicationRunDiagnostic | None


class VerificationWorkerAttempt(BaseModel):
    """One recorded screening attempt on this artifact, with its worker."""

    model_config = ConfigDict(extra="ignore")

    attempt_id: UUID
    screener_hotkey: str
    policy_version: int
    status: str
    reason_code: str | None
    failure_provider: str | None
    started_at: datetime
    finished_at: datetime | None


class VerificationFinalizerRead(BaseModel):
    """The effective artifact deadline, read from the finalizer surface.

    This ledger deliberately does **not** compute a deadline. The effective
    finalizer/deadline read is #2100 / #2115's
    ``get_screening_verification_state``; the field names here match it so one
    vocabulary survives. Until that surface is deployed, ``finalizer_state`` is
    ``not_configured`` and ``verification_deadline`` is null. The screening
    attempt lease deadline is reported separately and is not the verification
    deadline.
    """

    model_config = ConfigDict(extra="ignore")

    finalizer_state: Literal["pending", "ready", "finalized", "not_configured"]
    finalizer_reason: str
    verification_deadline: datetime | None
    deadline_provenance: str | None
    attempt_deadline: datetime | None
    source: Literal["screening_verification_state"]


class VerificationRecoveryView(BaseModel):
    """One append-only recovery grant, with the challenge kept private."""

    model_config = ConfigDict(extra="ignore")

    recovery_id: UUID
    agent_id: UUID
    quarantine_id: UUID
    source_attempt_id: UUID
    artifact_sha256: str
    policy_version: int
    manifest_digest: str
    image_digest: str | None
    state: VerificationRecoveryState
    outstanding_checks: list[str]
    reused_evidence: list[str]
    challenge_commitment: str
    """SHA-256 of the hidden randomness. The randomness itself is never here."""

    challenge_manifest_version: int
    independent_worker_required: bool
    excluded_screener_hotkeys: list[str]
    claimed_by: str | None
    claimed_at: datetime | None
    dispatch_deadline: datetime | None
    outcome: VerificationRecoveryOutcome | None
    failure_domain: VerificationRecoveryFailureDomain | None
    completed_checks: list[str] | None
    refuted_leads: list[str] | None
    reason: str
    actor: str
    created_at: datetime
    updated_at: datetime


class VerificationAuditEvent(BaseModel):
    """One append-only audit row for a recovery grant."""

    model_config = ConfigDict(extra="ignore")

    event_id: UUID
    event: str
    actor: str
    detail: dict | None
    created_at: datetime


class AdminVerificationReadiness(BaseModel):
    """Read-only verification readiness for one exact submission.

    Answers, for the exact committed artifact: which pinned identities bind a
    decision, which published mandatory checks and I1-I8 / S1-S3 rules have a
    recorded outcome, which remain outstanding, what the last court failure was,
    which workers attempted it, what the published retry defaults say, and
    whether a recovery grant exists. It is never a clearance and never a
    rejection.
    """

    model_config = ConfigDict(extra="ignore")

    agent_id: UUID
    agent_status: str
    artifact_sha256: str
    policy_version: int
    quarantine_id: UUID | None
    quarantine_status: str | None
    quarantine_reason_code: str | None
    has_established_finding: bool
    """True when the hold carries a verified finding.

    A finding-backed hold is the misconduct path, not a verification gap, and is
    refused by the recovery grant."""

    is_non_decisive_hold: bool
    evidence_bindings: VerificationEvidenceBindings
    mandatory_checks: list[VerificationCheckState]
    outstanding_mandatory_checks: list[str]
    integrity_rules: list[VerificationRuleState]
    security_rules: list[VerificationRuleState]
    opaque_roles: list[VerificationRuleState]
    private_paired_required: bool | None
    """Whether the mandatory private paired suite applies.

    Null (not False) whenever the opaque-component inventory itself is
    ``not_recorded``: with no recorded inventory there is no basis to say the
    suite does not apply."""

    last_court_failure: VerificationCourtFailure | None
    attempts: list[VerificationWorkerAttempt]
    attempts_recorded: int
    distinct_workers: int
    published_retry_defaults: PublishedRetryDefaults
    finalizer: VerificationFinalizerRead
    recovery: VerificationRecoveryView | None
    recovery_audit: list[VerificationAuditEvent]
    evidence_sources: list[str]
    """Exactly which persisted stores this ledger consulted.

    L1 review notes and reviewer summaries are deliberately absent: they are
    narrative, and policy v13 forbids inferring verification evidence from
    them."""

    generated_at: datetime


class AdminVerificationRecoveryRequest(BaseModel):
    """Compare-and-swap guards for authorizing one verification replay."""

    model_config = ConfigDict(extra="ignore")

    reason: Annotated[str, Field(min_length=8)]
    expected_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    expected_score_count: Annotated[int, Field(ge=0)]
    expected_attempt_id: UUID
    expected_attempt_count: Annotated[int, Field(ge=1)]
    expected_quarantine_id: UUID
    expected_policy_version: Annotated[int, Field(ge=1)]
    expected_manifest_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    expected_image_digest: Annotated[str | None, Field(min_length=1)] = None
    """The effective screened-image digest, or null when none is pinned.

    Explicitly part of the guard set: a rebuilt image is a different bound
    identity, so evidence and outstanding checks must be recomputed."""

    confirmation: Literal["RESUME MANDATORY VERIFICATION ON THIS ARTIFACT"]
    """Exact phrase, so a replay is never authorized by an incidental POST."""


class AdminVerificationRecoveryResponse(BaseModel):
    """The created (or idempotently replayed) grant, with its audit."""

    model_config = ConfigDict(extra="ignore")

    recovery: VerificationRecoveryView
    audit: list[VerificationAuditEvent]
    idempotent: bool
    agent_status: str
    """Unchanged by this call, and reported so an operator can see that."""

    quarantine_status: str
    """Also unchanged: authorizing a replay never releases the hold."""


class ScreenerVerificationRecoveryClaim(BaseModel):
    """What the claiming screener receives, including the private randomness."""

    model_config = ConfigDict(extra="ignore")

    recovery_id: UUID
    agent_id: UUID
    artifact_sha256: str
    policy_version: int
    manifest_digest: str
    image_digest: str | None
    outstanding_checks: list[str]
    reused_evidence: list[str]
    challenge_commitment: str
    challenge_manifest_version: int
    challenge_seed: str
    """Hidden challenge randomness, generated after artifact commitment.

    Released only here, only to the authenticated screener that holds the
    lease. It must never be logged, echoed to an operator surface, or written
    to an audit payload, and its contents must not reach the submission."""

    dispatch_deadline: datetime
    claimed_by: str


class ScreenerVerificationRecoveryResultRequest(BaseModel):
    """A worker's report about the replay it actually performed."""

    model_config = ConfigDict(extra="ignore")

    outcome: VerificationRecoveryOutcome
    completed_checks: list[str] = []
    failure_domain: VerificationRecoveryFailureDomain | None = None
    refuted_leads: list[str] = []
    """I1-I8 / S1-S3 leads this replay refuted.

    Recorded as evidence. Refuting a static lead does not clear the artifact and
    does not complete any mandatory check."""

    detail_code: Annotated[str | None, Field(max_length=64)] = None
    """Bounded machine code for the failure. Never free-form provider text."""


class ScreenerVerificationRecoveryResultResponse(BaseModel):
    """The recorded result, restating that no ruling followed from it."""

    model_config = ConfigDict(extra="ignore")

    recovery: VerificationRecoveryView
    agent_status: str
    quarantine_status: str
    decision_recorded: Literal[False]
    """A replay never produces a CLEAR, a REJECT, or a V1/V2/V3 ruling."""
