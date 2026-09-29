"""Owner-only source-review notes and court decision on screening feedback (#1249)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import get_args
from uuid import UUID, uuid4

import bittensor
import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ditto.api_models.miner_screening_feedback import MinerAdjudicationRefusal
from ditto.db.models import (
    AgentStatus,
    ScreeningAttempt,
    ScreeningQuarantine,
    ScreeningReviewEvent,
)
from ditto.tests.api_server.endpoints.test_miner_logs import _login
from ditto.tests.api_server.endpoints.test_validator import (
    _SHA256,
    _install_chain,
    _install_db,
    _seed_agent,
)
from ditto_screening_protocol import SourceReviewInvariant
from ditto_screening_protocol.models import (
    AdjudicationCompletionReceipt,
    AdjudicationRunDiagnostic,
    SourceReviewAdjudication,
    SourceReviewNote,
    source_review_notes_digest,
)

_SCREENER = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
_MODEL = "z-ai/glm-5.3-flash"
_PROMPT_REVISION = "adjudicator-v7-policy-v13"
_NOTES = [
    SourceReviewNote(
        kind="concern",
        category="answer_lookup",
        path="src/router.rs",
        line=42,
        summary="Routes a benchmark-shaped prompt to a lookup table",
        confidence=0.83,
        stage="l2",
    ),
    SourceReviewNote(
        kind="cleared",
        category="model_invocation",
        path="src/main.rs",
        line=6,
        summary="Served model authors the graded response",
        confidence=0.91,
        stage="l1",
    ),
]
_REJECT_REASON = "The lookup at src/router.rs:42 answers without the model."
# Operator-only values seeded on the record; none may reach the owner payload.
_OPERATOR_ONLY = (
    _MODEL,
    _PROMPT_REVISION,
    "notes_considered",
    "run_diagnostic",
    "completion_receipt",
    "escalation_code",
    "provider-http-error",
    "together",
    "openrouter",
    "confidence",
    "stage",
    "finding",
    "review_audit",
    "OPERATOR-FINDING-SUMMARY",
    "read_bytes_used",
    "digest",
    "completion_receipt_signature",
    "review_settings_revision",
    "verification_receipts",
)


def _adjudication(decision: str) -> SourceReviewAdjudication:
    basis: dict[str, object] = {
        "clear": {
            "clear_clause": "model_authors_graded_slot",
            "reason": "The served model authors the graded response.",
            "citations": [{"path": "src/main.rs", "line": 6}],
        },
        "reject": {
            "reject_invariant": SourceReviewInvariant.EVALUATION_INDEPENDENCE,
            "reason": _REJECT_REASON,
            "citations": [{"path": "src/router.rs", "line": 42}],
            "completion_receipt": AdjudicationCompletionReceipt(
                elapsed_ms=4300,
                observed_model=_MODEL,
                gateway_provider="openrouter",
                observed_upstream="together",
                request_count=1,
            ),
        },
        "escalate": {
            "escalation_code": "adjudicator-failed",
            "reason": (
                "Automated adjudication did not complete; held for operator review"
            ),
            "run_diagnostic": AdjudicationRunDiagnostic(
                error_class="HTTPStatusError",
                failure_code="provider-http-error",
                escalation_code="adjudicator-failed",
                http_status=502,
                elapsed_ms=1200,
                model=_MODEL,
                provider="openrouter",
                upstream="together",
            ),
        },
    }[decision]
    return SourceReviewAdjudication.model_validate(
        {
            "decision": decision,
            "notes_considered": len(_NOTES),
            "model": _MODEL,
            "prompt_revision": _PROMPT_REVISION,
            "policy_version": 13,
            **basis,
        }
    )


async def _seed_review(
    maker: async_sessionmaker[AsyncSession],
    *,
    agent_id: UUID,
    decision: str | None,
    status: str = "quarantined",
    quarantine: bool = True,
    event: bool = True,
    notes_digest: str | None = None,
    adjudication_digest: str | None = None,
) -> UUID:
    now = datetime.now(UTC)
    attempt_id = uuid4()
    quarantine_id = uuid4()
    notes_json = [note.model_dump(mode="json") for note in _NOTES]
    digest = notes_digest or source_review_notes_digest(_NOTES)
    adjudication = _adjudication(decision) if decision is not None else None
    async with maker() as session, session.begin():
        session.add(
            ScreeningAttempt(
                attempt_id=attempt_id,
                agent_id=agent_id,
                screener_hotkey=_SCREENER,
                policy_version=13,
                status=status,
                started_at=now - timedelta(minutes=5),
                deadline=now + timedelta(minutes=40),
                finished_at=now,
                public_reason="Submission held for anti-cheat review",
                reason_code=(
                    f"adjudicated-source-review-{decision}" if decision else None
                ),
            )
        )
        await session.flush()
        if quarantine:
            session.add(
                ScreeningQuarantine(
                    quarantine_id=quarantine_id,
                    agent_id=agent_id,
                    attempt_id=attempt_id,
                    screener_hotkey=_SCREENER,
                    policy_version=13,
                    manifest_digest="12" * 32,
                    reason_code=(
                        f"adjudicated-source-review-{decision}"
                        if decision
                        else "source-review-inconclusive"
                    ),
                    review_audit={"read_bytes_used": 1234},
                    review_audit_digest="34" * 32,
                    review_notes=notes_json,
                    review_notes_digest=digest,
                    finding={"summary": "OPERATOR-FINDING-SUMMARY"},
                    status="active",
                )
            )
            await session.flush()
        if event:
            session.add(
                ScreeningReviewEvent(
                    event_id=uuid4(),
                    agent_id=agent_id,
                    attempt_id=attempt_id,
                    quarantine_id=quarantine_id if quarantine else None,
                    event_kind="automated",
                    artifact_sha256=_SHA256,
                    policy_version=13,
                    actor=f"screener:{_SCREENER}",
                    reviewer_model=_MODEL,
                    outcome="quarantine",
                    effective_decision="hold",
                    prior_agent_status=AgentStatus.SCREENING,
                    next_agent_status=AgentStatus.QUARANTINED,
                    evidence={
                        "finding": {"summary": "OPERATOR-FINDING-SUMMARY"},
                        "review_audit": {"read_bytes_used": 1234},
                        "review_notes": notes_json,
                        "review_notes_digest": digest,
                        "adjudication": (
                            adjudication.model_dump(mode="json")
                            if adjudication is not None
                            else None
                        ),
                        "adjudication_digest": (
                            adjudication_digest
                            or (
                                adjudication.canonical_digest()
                                if adjudication is not None
                                else None
                            )
                        ),
                        "completion_receipt_signature": "0x" + "ab" * 64,
                        "review_settings_revision": 7,
                        "verification_receipts": [],
                    },
                    created_at=now,
                )
            )
    return attempt_id


async def _feedback(
    client: httpx.AsyncClient, *, agent_id: UUID, token: str | None
) -> httpx.Response:
    headers = {"authorization": f"Bearer {token}"} if token else {}
    return await client.get(
        f"/api/v1/me/agents/{agent_id}/screening-feedback", headers=headers
    )


def _assert_no_operator_fields(payload: object) -> None:
    text = json.dumps(payload)
    for value in _OPERATOR_ONLY:
        assert value not in text, value


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["clear", "reject"])
async def test_owner_reads_notes_ledger_and_court_decision(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
    decision: str,
) -> None:
    miner = bittensor.Keypair.create_from_uri("//Alice")
    agent_id = await _seed_agent(
        session_maker, status=AgentStatus.QUARANTINED, miner_hotkey=miner.ss58_address
    )
    attempt_id = await _seed_review(session_maker, agent_id=agent_id, decision=decision)
    _install_db(app, session_maker)
    _install_chain(app)
    token = await _login(client, keypair=miner)

    response = await _feedback(client, agent_id=agent_id, token=token)

    assert response.status_code == 200, response.text
    attempt = response.json()["attempts"][0]
    assert attempt["attempt_id"] == str(attempt_id)
    assert attempt["review_notes"] == [
        {
            "kind": "concern",
            "category": "answer_lookup",
            "path": "src/router.rs",
            "line": 42,
            "summary": "Routes a benchmark-shaped prompt to a lookup table",
        },
        {
            "kind": "cleared",
            "category": "model_invocation",
            "path": "src/main.rs",
            "line": 6,
            "summary": "Served model authors the graded response",
        },
    ]
    court = attempt["adjudication"]
    assert set(court) == {
        "decision",
        "reason",
        "reject_invariant",
        "clear_clause",
        "citations",
        "refusal",
    }
    assert court["decision"] == decision
    assert court["refusal"] is None
    if decision == "reject":
        assert court["reason"] == _REJECT_REASON
        assert court["reject_invariant"] == "i8_evaluation_independence"
        assert court["clear_clause"] is None
        assert court["citations"] == [{"path": "src/router.rs", "line": 42}]
    else:
        assert court["clear_clause"] == "model_authors_graded_slot"
        assert court["reject_invariant"] is None
        assert court["citations"] == [{"path": "src/main.rs", "line": 6}]
    _assert_no_operator_fields(response.json())


@pytest.mark.asyncio
async def test_owner_sees_escalation_with_refusal_named_and_no_diagnostic(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    miner = bittensor.Keypair.create_from_uri("//Alice")
    agent_id = await _seed_agent(
        session_maker, status=AgentStatus.QUARANTINED, miner_hotkey=miner.ss58_address
    )
    await _seed_review(session_maker, agent_id=agent_id, decision="escalate")
    _install_db(app, session_maker)
    _install_chain(app)
    token = await _login(client, keypair=miner)

    response = await _feedback(client, agent_id=agent_id, token=token)

    assert response.status_code == 200, response.text
    court = response.json()["attempts"][0]["adjudication"]
    assert court == {
        "decision": "escalate",
        "reason": "Automated adjudication did not complete; held for operator review",
        "reject_invariant": None,
        "clear_clause": None,
        "citations": [],
        "refusal": "adjudicator-failed",
    }
    _assert_no_operator_fields(response.json())


@pytest.mark.asyncio
async def test_unverified_ledger_and_court_are_omitted_not_shown(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    miner = bittensor.Keypair.create_from_uri("//Alice")
    agent_id = await _seed_agent(
        session_maker, status=AgentStatus.QUARANTINED, miner_hotkey=miner.ss58_address
    )
    await _seed_review(
        session_maker,
        agent_id=agent_id,
        decision="reject",
        notes_digest="0" * 64,
        adjudication_digest="1" * 64,
    )
    _install_db(app, session_maker)
    _install_chain(app)
    token = await _login(client, keypair=miner)

    response = await _feedback(client, agent_id=agent_id, token=token)

    assert response.status_code == 200, response.text
    attempt = response.json()["attempts"][0]
    assert attempt["review_notes"] == []
    assert attempt["adjudication"] is None


@pytest.mark.asyncio
async def test_quarantine_ledger_is_the_fallback_without_an_event(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    miner = bittensor.Keypair.create_from_uri("//Alice")
    agent_id = await _seed_agent(
        session_maker, status=AgentStatus.QUARANTINED, miner_hotkey=miner.ss58_address
    )
    await _seed_review(session_maker, agent_id=agent_id, decision=None, event=False)
    _install_db(app, session_maker)
    _install_chain(app)
    token = await _login(client, keypair=miner)

    response = await _feedback(client, agent_id=agent_id, token=token)

    assert response.status_code == 200, response.text
    attempt = response.json()["attempts"][0]
    assert [note["path"] for note in attempt["review_notes"]] == [
        "src/router.rs",
        "src/main.rs",
    ]
    assert attempt["adjudication"] is None
    _assert_no_operator_fields(response.json())


@pytest.mark.asyncio
async def test_other_miner_and_anonymous_caller_cannot_read_review_notes(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    owner = bittensor.Keypair.create_from_uri("//Alice")
    attacker = bittensor.Keypair.create_from_uri("//Bob")
    agent_id = await _seed_agent(
        session_maker, status=AgentStatus.QUARANTINED, miner_hotkey=owner.ss58_address
    )
    await _seed_review(session_maker, agent_id=agent_id, decision="reject")
    _install_db(app, session_maker)
    _install_chain(app)
    attacker_token = await _login(client, keypair=attacker)

    foreign = await _feedback(client, agent_id=agent_id, token=attacker_token)
    anonymous = await _feedback(client, agent_id=agent_id, token=None)
    foreign_mcp = await client.post(
        "/mcp",
        headers={"authorization": f"Bearer {attacker_token}"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_my_screening_feedback",
                "arguments": {"agent_id": str(agent_id)},
            },
        },
    )
    # The public submission view carries no ledger for a held (active) review.
    public = await client.get(f"/api/v1/public/agent/{agent_id}/pipeline")

    assert foreign.status_code == 404
    assert anonymous.status_code == 401
    for response in (foreign, anonymous, foreign_mcp, public):
        assert "Routes a benchmark-shaped prompt" not in response.text
        assert _REJECT_REASON not in response.text
        assert "src/router.rs" not in response.text
    assert public.status_code == 200, public.text


@pytest.mark.asyncio
async def test_owner_reads_review_notes_through_miner_mcp(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    miner = bittensor.Keypair.create_from_uri("//Alice")
    agent_id = await _seed_agent(
        session_maker, status=AgentStatus.QUARANTINED, miner_hotkey=miner.ss58_address
    )
    await _seed_review(session_maker, agent_id=agent_id, decision="escalate")
    _install_db(app, session_maker)
    _install_chain(app)
    token = await _login(client, keypair=miner)

    response = await client.post(
        "/mcp",
        headers={"authorization": f"Bearer {token}"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_my_screening_feedback",
                "arguments": {"agent_id": str(agent_id)},
            },
        },
    )

    assert response.status_code == 200, response.text
    feedback = json.loads(response.json()["result"]["content"][0]["text"])
    attempt = feedback["attempts"][0]
    assert len(attempt["review_notes"]) == 2
    assert attempt["adjudication"]["refusal"] == "adjudicator-failed"
    _assert_no_operator_fields(feedback)


def test_refusal_vocabulary_matches_the_worker_escalation_codes() -> None:
    """Every code the court host escalates with is named to the miner."""
    adjudicator = (
        Path(__file__).resolve().parents[6]
        / "workers/screener/ditto_screener/adjudicator.py"
    )
    if not adjudicator.exists():
        pytest.skip("screener worker source is not in this checkout")
    emitted = set(
        re.findall(r'_escalate\(\s*"([a-z0-9-]+)"', adjudicator.read_text())
    ) | set(re.findall(r'escalation_code="([a-z0-9-]+)"', adjudicator.read_text()))
    assert emitted
    assert emitted <= set(get_args(MinerAdjudicationRefusal))
