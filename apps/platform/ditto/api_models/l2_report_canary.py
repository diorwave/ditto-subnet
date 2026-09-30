"""Exact-attempt, non-authoritative L2 canary wire contract."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ditto_screening_protocol import ScoredRuntimeEvidenceLease


class L2CanaryScheduleRequest(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    # FastAPI parses JSON into Python strings before model validation. Keep the
    # rest of this wire model strict while accepting canonical UUID strings.
    request_id: Annotated[UUID, Field(strict=False)]
    agent_id: Annotated[UUID, Field(strict=False)]
    source_attempt_id: Annotated[UUID, Field(strict=False)]
    artifact_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    policy_version: Literal[13]
    expected_agent_status: str
    expected_score_count: Annotated[int, Field(ge=0)]
    target_node_id: str
    review_label: Literal["candidate_clear", "known_reject"]
    run_mode: Literal["source_only", "full_runtime"] = "source_only"
    historical_ruling_kind: Literal["ath_clear", "screening_reject"] | None = None
    historical_ruling_id: Annotated[UUID | None, Field(strict=False)] = None
    confirm_report_only: Literal[True]

    @model_validator(mode="after")
    def historical_ruling_is_explicit_and_source_only(self) -> L2CanaryScheduleRequest:
        if (self.historical_ruling_kind is None) != (self.historical_ruling_id is None):
            raise ValueError("historical ruling kind and id must be supplied together")
        if self.historical_ruling_kind is not None and (
            self.run_mode != "source_only"
            or (self.historical_ruling_kind == "ath_clear")
            != (self.review_label == "candidate_clear")
        ):
            raise ValueError("historical ruling must match source-only review label")
        return self


class CanonicalFixtureRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    request_id: Annotated[UUID, Field(strict=False)]
    target_node_id: Annotated[str, Field(min_length=1, max_length=63)]
    confirm_report_only: Literal[True]


class CanonicalFixtureReviewRequest(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    reviewer_evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    reviewed_archive_sha256: Literal[
        "a3dacec019ce5ea6694bfbeb7669a5f9109514c38c6de7000c8dfa3f3f0f57b6"
    ]
    reviewed_dockerfile_sha256: Literal[
        "d3a1a2a1e5d43b0465c28712457d95432942ac8f017fd10d538859a901a54641"
    ]
    built_image_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    reviewer_evidence_url: Annotated[
        str, Field(pattern=r"^https://github\.com/ditto-assistant/ditto-subnet/")
    ]
    confirm_candidate_review: Literal[True]


class CanonicalFixtureScheduleRequest(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    confirm_report_only: Literal[True]


class L2CanaryView(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    canary_id: UUID
    request_id: UUID
    agent_id: UUID | None
    source_attempt_id: UUID | None
    source_kind: Literal["submission", "canonical_starter_fixture"] = "submission"
    fixture_key: str | None = None
    artifact_sha256: str
    target_node_id: str
    expected_agent_status: str | None
    expected_score_count: int | None
    review_label: str
    run_mode: Literal["source_only", "full_runtime"]
    source_attestation: dict | None = None
    status: str
    claimed_instance_id: str | None
    lease_expires_at: datetime | None
    report: dict | None
    error_code: str | None
    created_at: datetime
    completed_at: datetime | None


L2CanaryGuardName = Literal[
    "ath_clear_action",
    "attempt_owner",
    "agent_artifact_sha256",
    "attempt_policy_version",
    "agent_status",
    "score_row_count",
    "attempt_artifact_sha256",
    "historical_ruling_run_mode",
    "historical_ruling",
    "source_object_verified",
    "arrival_bench_version",
]


class L2CanaryGuardCheck(BaseModel):
    """One exact-source guard, in the order the scheduler evaluates it.

    ``passed`` is null when the caller supplied no expected value to compare,
    or, for ``source_object_verified``, because only scheduling re-hashes the
    stored object. ``conflict_detail`` is the exact 409 detail the scheduler
    answers when this is the first guard not known to pass.
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    guard: L2CanaryGuardName
    passed: bool | None
    current: str | int | None
    expected: str | int | None
    conflict_detail: str
    note: str | None = None


class L2CanaryPreflightView(BaseModel):
    """The scheduler's exact-source guards on current state; advisory only.

    It authorizes nothing: scheduling reruns the same predicate under row locks
    and re-hashes the stored object before any canary is queued.
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    authority: Literal["none"] = "none"
    agent_id: UUID
    source_attempt_id: UUID
    agent_artifact_sha256: str
    source_attempt_artifact_sha256: str | None
    agent_status: str
    attempt_policy_version: int
    # Null when unavailable; the arrival_bench_version guard then fails exactly
    # as scheduling refuses it.
    arrival_bench_version: int | None
    score_row_count: int
    attempt_agent_id: UUID
    # Legacy attempts predate artifact pinning; only a historical ruling can
    # schedule them, and the ruling does not prove what the old attempt ran.
    legacy_null_attempt_sha256: bool
    active_canary_id: UUID | None
    # Whether a claim could lease now: the same report-only scored-runtime
    # packet lookup the claim path performs. A queued canary waits otherwise.
    report_only_packet_available: bool
    guards: list[L2CanaryGuardCheck]
    # False when any guard failed; null when none failed but at least one
    # expected value was not supplied (or object verification is pending).
    guards_pass: bool | None


class L2CanaryClaimRequest(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    instance_id: Annotated[str, Field(min_length=1, max_length=63)]
    settings_revision: Annotated[int, Field(ge=0)]
    settings_checksum: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class L2CanaryClaimResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    canary_id: UUID
    agent_id: UUID
    source_attempt_id: UUID
    artifact_sha256: str
    bench_version: int
    policy_version: int
    run_mode: Literal["source_only", "full_runtime"] = "source_only"
    source_kind: Literal["submission", "canonical_starter_fixture"] = "submission"
    source_attestation: dict | None = None
    miner_hotkey: str
    lease_token: str
    lease_expires_at: datetime
    download_url: str
    scored_runtime_evidence: ScoredRuntimeEvidenceLease


class L2CanaryCompleteRequest(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    lease_token: str
    status: Literal["succeeded", "incomplete"]
    report: dict
    error_code: Annotated[str, Field(min_length=1, max_length=120)] | None = None

    @model_validator(mode="after")
    def bounded_report(self) -> L2CanaryCompleteRequest:
        if len(json.dumps(self.report, separators=(",", ":"))) > 512_000:
            raise ValueError("canary report exceeds 512000 bytes")
        return self


class L2CanaryCompleteResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    accepted: bool
