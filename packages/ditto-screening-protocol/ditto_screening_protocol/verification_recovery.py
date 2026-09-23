"""Published policy-v13 mandatory-verification inventory and recovery vocabulary.

Policy v13 has exactly two final outcomes and no indefinite hold, but the four
current court-failure holds proved that an operator cannot see *which* mandatory
check is still missing, nor resume only that check against the committed
artifact. This module is the single source for the published inventory those
surfaces report against, so Platform, Backroom, and the screener cannot drift
into three different spellings of the same check.

Nothing here decides anything. An entry in this inventory is a published
obligation, not evidence that it was met; evidence state lives in the durable
artifact-bound records and defaults to :data:`NOT_RECORDED`.

References:

- ``workers/screener/docs/policy-v13.md`` "Mandatory verification" (the 19
  numbered checks), "Black checklist" (I1-I8 / S1-S3), "Retry and deadline
  procedure" (the published retry defaults), and "Required decision record".
- ``workers/screener/docs/policy-v13-opaque-verification.md`` "Role
  requirements" (which opaque roles make private paired testing mandatory).
"""

from __future__ import annotations

from typing import Final, Literal

from pydantic import BaseModel, ConfigDict

NOT_RECORDED: Final = "not_recorded"
"""Sentinel for evidence that was never persisted for this exact artifact.

``not_recorded`` is deliberately not ``false``, ``null``, or ``pending``. A
missing per-check record proves only that the store does not hold the record.
It must never be inferred from L1 review notes, a reviewer summary, a score
projection, or the absence of a leaderboard field (policy v13, "Evidence
standards").
"""

VerificationEvidenceState = Literal[
    "not_recorded", "completed", "outstanding", "refuted"
]
"""State of one artifact-bound verification obligation.

``completed`` and ``refuted`` require a persisted artifact-bound record whose
bound identities match. ``outstanding`` means a recorded attempt covered the
check and did not complete it. ``not_recorded`` is the default.
"""

VerificationLane = Literal["artifact", "runtime", "private_paired", "review"]
"""Which execution lane can discharge a mandatory check.

- ``artifact``: archive/SHA and build/image-digest identity work.
- ``runtime``: served-path checks against the built image.
- ``private_paired``: the mandatory private metamorphic suite, whose hidden
  randomness must be generated after artifact commitment.
- ``review``: the source/policy review and its I1-I8 / S1-S3 decisions.
"""

VerificationRecoveryState = Literal[
    "queued", "dispatched", "completed", "failed", "canceled"
]
"""Lifecycle of one operator-authorized verification-recovery grant.

Every transition is operator- or worker-driven and appended to an audit trail.
No scheduler advances a grant, and no state in this enumeration is a screening
outcome: a ``completed`` grant reports that verification ran, never that the
artifact is cleared.
"""

VerificationRecoveryOutcome = Literal[
    "verification_complete", "verification_incomplete"
]
"""What a recovery worker may report about the replay it actually performed."""

VerificationRecoveryFailureDomain = Literal[
    "artifact", "submission", "platform", "provider"
]
"""Policy-v13 ``failure_domain`` vocabulary for an incomplete replay.

Identical vocabulary to the ``failure_domain`` field of the published decision
record. It is recorded as *evidence about the replay* and never as a ruling:
selecting ``platform`` here does not create a V2 rejection. When the
``review_timed_out`` finalizer's ``FailureDomain`` literal lands (#1871), this
alias must be collapsed onto it rather than maintained separately.
"""


class MandatoryVerificationCheck(BaseModel):
    """One published mandatory-verification obligation."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    check_id: str
    """Stable snake_case identifier used by every surface and stored record."""

    ordinal: int
    """1-based position in the published "Mandatory verification" list."""

    lane: VerificationLane
    title: str


_PUBLISHED_CHECKS: Final[tuple[tuple[str, VerificationLane, str], ...]] = (
    ("archive_and_sha", "artifact", "archive and SHA verification"),
    (
        "build_and_image_digest",
        "artifact",
        "build and image-digest verification",
    ),
    ("health", "runtime", "/health"),
    ("model_authority_run", "runtime", "ordinary model-authority /run"),
    ("tool_selection_run", "runtime", "tool-selection /run"),
    ("seed_and_memory_run", "runtime", "/seed followed by memory /run"),
    ("two_user_isolation", "runtime", "two-user isolation"),
    (
        "host_instruction_retention",
        "runtime",
        "host-system instruction retention",
    ),
    ("tool_revocation", "runtime", "tool revocation"),
    (
        "duplicate_suppression",
        "runtime",
        "successful-duplicate suppression",
    ),
    (
        "same_tool_different_argument",
        "runtime",
        "same-tool/different-argument execution",
    ),
    (
        "catalog_fidelity_and_reordering",
        "runtime",
        "catalog fidelity and reordering",
    ),
    (
        "timeout_and_delivery_unknown",
        "runtime",
        "timeout and delivery-unknown reporting",
    ),
    ("fallback_evidence_retention", "runtime", "fallback evidence retention"),
    (
        "response_field_and_long_answer",
        "runtime",
        "response-field and long-answer behavior",
    ),
    (
        "refusal_and_uncertainty",
        "runtime",
        "refusal and uncertainty preservation",
    ),
    ("token_accounting", "runtime", "complete token accounting"),
    ("opaque_component_inventory", "review", "opaque-component inventory"),
    ("integrity_and_security_review", "review", "I1-I8 and S1-S3 review"),
)

MANDATORY_VERIFICATION_CHECKS: Final[tuple[MandatoryVerificationCheck, ...]] = tuple(
    MandatoryVerificationCheck(
        check_id=check_id, ordinal=ordinal, lane=lane, title=title
    )
    for ordinal, (check_id, lane, title) in enumerate(_PUBLISHED_CHECKS, start=1)
)
"""The 19 published mandatory-verification checks, in published order.

The conditional private metamorphic suite is not a 20th entry. Policy v13 makes
it mandatory *within* the I1-I8 / S1-S3 review for I5, I7, I8, and materially
authoritative opaque components, so it is reported through the opaque-role
requirements and the ``private_paired`` lane rather than as its own check.
"""

MANDATORY_VERIFICATION_CHECK_IDS: Final[frozenset[str]] = frozenset(
    check.check_id for check in MANDATORY_VERIFICATION_CHECKS
)

INTEGRITY_CHECK_IDS: Final[tuple[str, ...]] = tuple(
    f"I{index}" for index in range(1, 9)
)
"""I1-I8, the published integrity rejection conditions."""

SECURITY_CHECK_IDS: Final[tuple[str, ...]] = ("S1", "S2", "S3")
"""S1-S3, the published security rejection conditions."""

OPAQUE_ROLE_IDS: Final[tuple[str, ...]] = (
    "unloaded_or_unreachable",
    "presentation_only_permutation",
    "evidence_selector_or_capability_router",
    "advisory_candidate_or_critic",
    "authoritative_planner",
    "scored_output_component",
    "executable_loader_or_generated_executable",
)
"""Opaque-component roles from the companion role-verification specification."""

OPAQUE_ROLES_REQUIRING_PRIVATE_TESTS: Final[frozenset[str]] = frozenset(
    {
        "evidence_selector_or_capability_router",
        "advisory_candidate_or_critic",
        "authoritative_planner",
        "scored_output_component",
    }
)
"""Roles whose published requirement includes private paired testing.

``unloaded_or_unreachable`` needs no behavioral test, and
``executable_loader_or_generated_executable`` needs controlled security tests
rather than the paired metamorphic suite.
"""

NON_DECISIVE_V13_REASON_CODES: Final[frozenset[str]] = frozenset(
    {
        "source-review-inconclusive",
        "source-review-invalid-risk",
        "source-review-inconsistent-verdict",
        "adjudicated-source-review-escalate",
        "behavioral-oracle-inconclusive",
        "challenge-inconclusive",
        "source-review-unavailable",
    }
)
"""Published reason codes that reached no decision.

A hold on one of these is a verification gap, not a finding. These are the only
holds a verification-recovery grant may target: a hold carrying an established
finding belongs to the misconduct path instead.
"""


class PublishedRetryDefaults(BaseModel):
    """The published "Retry and deadline procedure" recommended defaults."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    artifact_failure_retries: int
    provider_failure_retries: int
    platform_failure_retries: int
    independent_worker_required_for_platform_or_provider: bool
    maximum_verification_window_hours: int
    provenance: str
    enforced: bool
    """False until a deployed finalizer enforces these numbers.

    The published text calls them *recommended defaults*. Reporting them is not
    evidence of a production cutoff; the effective deadline and the enforced
    budget are read from the finalizer surface, not from this constant.
    """


PUBLISHED_RETRY_DEFAULTS: Final = PublishedRetryDefaults(
    artifact_failure_retries=1,
    provider_failure_retries=2,
    platform_failure_retries=2,
    independent_worker_required_for_platform_or_provider=True,
    maximum_verification_window_hours=24,
    provenance="policy-v13-published-defaults",
    enforced=False,
)


def independent_worker_required(
    failure_domain: VerificationRecoveryFailureDomain | None,
) -> bool:
    """Report whether the published procedure requires an independent worker.

    Platform and provider failures do; an artifact- or submission-controlled
    failure reproduces on any worker, so the requirement does not apply.
    """
    return failure_domain in {"platform", "provider"}


__all__ = [
    "INTEGRITY_CHECK_IDS",
    "MANDATORY_VERIFICATION_CHECKS",
    "MANDATORY_VERIFICATION_CHECK_IDS",
    "NON_DECISIVE_V13_REASON_CODES",
    "NOT_RECORDED",
    "OPAQUE_ROLES_REQUIRING_PRIVATE_TESTS",
    "OPAQUE_ROLE_IDS",
    "PUBLISHED_RETRY_DEFAULTS",
    "SECURITY_CHECK_IDS",
    "MandatoryVerificationCheck",
    "PublishedRetryDefaults",
    "VerificationEvidenceState",
    "VerificationLane",
    "VerificationRecoveryFailureDomain",
    "VerificationRecoveryOutcome",
    "VerificationRecoveryState",
    "independent_worker_required",
]
