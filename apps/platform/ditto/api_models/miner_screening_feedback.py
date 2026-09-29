"""Miner-private screening failure feedback wire models."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from ditto.api_models.upload import _SS58_PATTERN

MinerAdjudicationRefusal = Literal[
    "adjudicator-unavailable",
    "adjudicator-no-evidence",
    "adjudicator-evidence-incomplete",
    "adjudicator-packet-too-large",
    "adjudicator-failed",
    "adjudicator-operator-requested",
    "uncited-decision",
    "cited-unknown-member",
    "cited-unread-source",
    "inadmissible-citations",
    "verdict-contract-failed",
]
"""Host-named reasons the automated court refused to decide.

Closed on purpose: a code the Platform does not know is omitted rather than
echoed, so a new worker code never reaches a miner without review here.
"""


class MinerScreeningReviewNote(BaseModel):
    """One entry of the owner's digest-verified source-review notes ledger.

    Summaries are reviewer-authored and never contain source text, prompts,
    or challenge values. ``path``/``line`` name a location in the miner's own
    archive. Reviewer confidence and stage are not carried.
    """

    model_config = ConfigDict(extra="ignore")

    kind: Literal["concern", "cleared", "observation"]
    category: str
    path: str | None = None
    line: int | None = None
    summary: str


class MinerScreeningCitation(BaseModel):
    """One ``path:line`` in the miner's own archive the court relied on."""

    model_config = ConfigDict(extra="ignore")

    path: str
    line: Annotated[int, Field(ge=1)]


class MinerScreeningAdjudication(BaseModel):
    """The automated court's digest-verified decision on one attempt.

    ``escalate`` means the court refused to decide and an operator reviews the
    hold; ``refusal`` names why. The court's model, prompt revision, run
    diagnostics, and completion telemetry are operator-only and never carried.
    """

    model_config = ConfigDict(extra="ignore")

    decision: Literal["clear", "reject", "escalate"]
    reason: str
    reject_invariant: str | None = None
    clear_clause: str | None = None
    citations: list[MinerScreeningCitation] = Field(default_factory=list)
    refusal: MinerAdjudicationRefusal | None = None


class MinerScreeningFailure(BaseModel):
    model_config = ConfigDict(extra="ignore")

    attempt_id: UUID
    status: str
    policy_version: Annotated[int, Field(ge=1)]
    started_at: datetime
    finished_at: datetime | None = None
    reason_code: str | None = None
    public_reason: str | None = None
    provider: str | None = None
    lane: str | None = None
    detail: str | None = None
    log_tail: str | None = None
    captured_at: datetime | None = None
    review_notes: list[MinerScreeningReviewNote] = Field(default_factory=list)
    """Digest-verified source-review notes recorded for this attempt."""
    adjudication: MinerScreeningAdjudication | None = None
    """Digest-verified automated court decision recorded for this attempt."""


class MinerScreeningFeedbackResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    agent_id: UUID
    miner_hotkey: Annotated[str, Field(pattern=_SS58_PATTERN)]
    agent_status: str
    attempts: list[MinerScreeningFailure]
