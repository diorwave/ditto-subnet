"""Terminal ATH rulings never leave an active screening quarantine behind.

Regression coverage for ditto-subnet#2038: a scored policy rescreen can hold an
active quarantine while the agent keeps its board position, and a terminal ATH
reject of that exact agent used to leave the row active with no guarded way to
close it.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ditto.api_server.dependencies import get_chain_client, get_session
from ditto.db.models import (
    Agent,
    AgentStatus,
    AthReview,
    AthReviewAction,
    Score,
    ScreeningAttempt,
    ScreeningQuarantine,
    ScreeningQuarantineResolution,
    ScreeningReviewEvent,
)
from ditto.db.queries import screening_review_events
from ditto.db.queries.agents import resolve_review
from ditto.db.queries.benchmark_rollout import MIN_SCOREABLE_BENCH_VERSION
from ditto.db.queries.source_review_queue_slo import (
    load_source_review_queue_slo_snapshot,
)

_TOKEN = "test-admin-token-at-least-32-characters"
_HEADERS = {"Authorization": f"Bearer {_TOKEN}", "X-Admin-Actor": "operator"}
_T0 = datetime(2026, 9, 20, 12, tzinfo=UTC)
_HOTKEY = "5" + "T" * 47
_ATH_REASON = "Family compiler on served /run (I5); precedent family-compiler"
_MINER_REASON = "Rejected by ATH review"


def _install(app: FastAPI, maker: async_sessionmaker[AsyncSession]) -> None:
    app.state.config = replace(app.state.config, admin_api_token=_TOKEN)

    async def _session() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    app.dependency_overrides[get_session] = _session
    # The batch resolver resolves a chain client even though a reject never
    # prepares a release dataset.
    app.dependency_overrides[get_chain_client] = lambda: MagicMock()


async def _seed(
    maker: async_sessionmaker[AsyncSession],
    *,
    status: AgentStatus,
    ath_resolution: str | None,
) -> tuple[UUID, str, UUID]:
    """One scored agent carrying an active quarantine from a retained rescreen.

    ``ath_resolution=None`` holds the agent in a pending ATH review;
    ``"reject"`` reproduces the pre-fix ghost: a resolved terminal ruling with
    the quarantine still active.
    """
    agent_id, attempt_id, quarantine_id = uuid4(), uuid4(), uuid4()
    sha256 = agent_id.hex * 2
    async with maker() as session, session.begin():
        session.add(
            Agent(
                agent_id=agent_id,
                miner_hotkey=_HOTKEY,
                name="teacup",
                sha256=sha256,
                status=status,
                review_reason=_ATH_REASON,
                screening_reason=_MINER_REASON,
                screening_reason_code="source-review-high-risk",
                screening_policy_version=13,
                created_at=_T0,
            )
        )
        for index in range(3):
            session.add(
                Score(
                    agent_id=agent_id,
                    validator_hotkey=f"validator-{index}",
                    run_id=f"run-{index}",
                    signature=None,
                    seed=7,
                    composite=0.91,
                    tool_mean=0.91,
                    memory_mean=0.9,
                    median_ms=100,
                    n=114,
                    details={"bench_version": MIN_SCOREABLE_BENCH_VERSION},
                    generated_at=_T0 + timedelta(minutes=index),
                )
            )
        await session.flush()
        session.add(
            ScreeningAttempt(
                attempt_id=attempt_id,
                agent_id=agent_id,
                screener_hotkey=_HOTKEY,
                policy_version=13,
                status="quarantined",
                started_at=_T0 + timedelta(hours=1),
                deadline=_T0 + timedelta(hours=2),
                finished_at=_T0 + timedelta(hours=1, minutes=5),
                artifact_sha256=sha256,
            )
        )
        await session.flush()
        session.add(
            ScreeningQuarantine(
                quarantine_id=quarantine_id,
                agent_id=agent_id,
                attempt_id=attempt_id,
                screener_hotkey=_HOTKEY,
                policy_version=13,
                manifest_digest="b" * 64,
                reason_code="source-review-high-risk",
                status="active",
                created_at=_T0 + timedelta(hours=1, minutes=5),
            )
        )
        resolved = ath_resolution is not None
        session.add(
            AthReview(
                review_id=uuid4(),
                agent_id=agent_id,
                status="resolved" if resolved else "pending",
                opened_at=_T0 + timedelta(hours=2),
                resolved_at=_T0 + timedelta(hours=3) if resolved else None,
                resolved_by="operator" if resolved else None,
                resolution=ath_resolution,
                resolution_reason=_ATH_REASON if resolved else None,
                original_duplicate_of=None,
                original_reason=_ATH_REASON,
                original_policy_version=13,
                original_evidence={
                    "sha256": sha256,
                    "score_count": 3,
                    "previous_status": AgentStatus.SCORED.value,
                },
                algorithm_provenance={
                    "snapshot": "manual-admin-hold",
                    "review_kind": "benchmark_overfit",
                    "algorithm_version": "manual-ath-review-v1",
                    "opened_by": "operator",
                    "backfilled": False,
                    "opened_at_source": "admin-request",
                },
            )
        )
    return agent_id, sha256, quarantine_id


async def _active_quarantine_count(
    maker: async_sessionmaker[AsyncSession], agent_id: UUID
) -> int:
    async with maker() as session:
        return int(
            await session.scalar(
                select(func.count())
                .select_from(ScreeningQuarantine)
                .where(
                    ScreeningQuarantine.agent_id == agent_id,
                    ScreeningQuarantine.status == "active",
                )
            )
            or 0
        )


async def test_terminal_ath_reject_closes_matching_active_quarantine(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_id, sha256, quarantine_id = await _seed(
        session_maker, status=AgentStatus.ATH_PENDING_REVIEW, ath_resolution=None
    )
    moderation = AsyncMock()
    monkeypatch.setattr(
        screening_review_events, "record_moderation_audit_if_enabled", moderation
    )
    _install(app, session_maker)

    response = await client.post(
        f"/api/v1/admin/copy-reviews/{agent_id}/resolve",
        json={"resolution": "reject", "reason": _ATH_REASON},
        headers=_HEADERS,
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["agent_status"] == AgentStatus.BANNED
    assert body["reconciled_quarantine_ids"] == [str(quarantine_id)]
    assert await _active_quarantine_count(session_maker, agent_id) == 0
    async with session_maker() as session:
        quarantine = await session.get(ScreeningQuarantine, quarantine_id)
        review = await session.scalar(
            select(AthReview).where(AthReview.agent_id == agent_id)
        )
        agent = await session.get(Agent, agent_id)
        resolutions = (
            await session.scalars(
                select(ScreeningQuarantineResolution).where(
                    ScreeningQuarantineResolution.quarantine_id == quarantine_id
                )
            )
        ).all()
        event = await session.scalar(
            select(ScreeningReviewEvent).where(
                ScreeningReviewEvent.quarantine_id == quarantine_id
            )
        )
        assert review is not None
        action = await session.scalar(
            select(AthReviewAction).where(
                AthReviewAction.review_id == review.review_id,
                AthReviewAction.action == "reject",
            )
        )
    assert agent is not None and quarantine is not None
    assert agent.status == AgentStatus.BANNED
    assert agent.screening_reason == _MINER_REASON
    assert (quarantine.status, quarantine.resolution, quarantine.resolved_by) == (
        "resolved",
        "reject",
        "operator",
    )
    assert (
        quarantine.resolution_reason == f"Closed by terminal ATH ruling: {_ATH_REASON}"
    )
    assert [(row.resolution, row.actor) for row in resolutions] == [
        ("reject", "operator")
    ]
    assert event is not None
    assert (event.prior_agent_status, event.next_agent_status) == ("banned", "banned")
    assert event.evidence["terminal_reconciliation"] == {
        "source": "ath_ruling",
        "agent_status": "banned",
        "artifact_sha256": sha256,
        "ath_review_id": str(review.review_id),
        "ath_resolution": "reject",
        "ath_resolved_at": review.resolved_at.isoformat()
        if review.resolved_at
        else None,
    }
    assert action is not None
    assert action.evidence["reconciled_quarantine_ids"] == [str(quarantine_id)]
    # The ATH ruling is the authoritative public outcome; closing the orphan
    # publishes no second moderation record.
    moderation.assert_not_awaited()

    audit = await client.get(
        f"/api/v1/admin/copy-reviews/{agent_id}/audit", headers=_HEADERS
    )
    assert audit.status_code == 200
    assert audit.json()["action_history"][-1]["reconciled_quarantine_ids"] == [
        str(quarantine_id)
    ]
    listing = await client.get("/api/v1/admin/screening-quarantines", headers=_HEADERS)
    assert listing.json()["count"] == 0


async def test_clear_leaves_a_non_terminal_quarantine_untouched(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    agent_id, _sha256, _quarantine_id = await _seed(
        session_maker, status=AgentStatus.ATH_PENDING_REVIEW, ath_resolution=None
    )
    _install(app, session_maker)

    response = await client.post(
        f"/api/v1/admin/copy-reviews/{agent_id}/resolve",
        json={"resolution": "clear", "reason": "Served path uses the real model"},
        headers=_HEADERS,
    )

    assert response.status_code == 200, response.text
    assert response.json()["reconciled_quarantine_ids"] == []
    assert await _active_quarantine_count(session_maker, agent_id) == 1


async def test_operator_reconciles_preexisting_terminal_ghost(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    agent_id, sha256, quarantine_id = await _seed(
        session_maker, status=AgentStatus.BANNED, ath_resolution="reject"
    )
    _install(app, session_maker)

    listing = await client.get("/api/v1/admin/screening-quarantines", headers=_HEADERS)
    assert listing.status_code == 200
    body = listing.json()
    assert (body["count"], body["terminal_ghost_count"], body["actionable_count"]) == (
        1,
        1,
        0,
    )
    assert body["oldest_actionable_created_at"] is None
    assert body["items"][0]["terminal_ghost"] is True
    assert body["items"][0]["agent_status"] == AgentStatus.BANNED
    async with session_maker() as session:
        snapshot = await load_source_review_queue_slo_snapshot(session)
    assert snapshot.terminal_quarantine_ghost_count == 1
    assert (snapshot.backlog_count, snapshot.oldest_age_seconds) == (0, None)

    # The unfenced single resolver still refuses, and names the fenced path.
    single = await client.post(
        f"/api/v1/admin/screening-quarantines/{quarantine_id}/resolve",
        json={"resolution": "reject", "reason": "Close the orphan"},
        headers=_HEADERS,
    )
    assert single.status_code == 409
    assert "fenced batch reject" in single.json()["message"]

    decision = {
        "quarantine_id": str(quarantine_id),
        "expected_agent_id": str(agent_id),
        "expected_artifact_sha256": sha256,
        "resolution": "reject",
        "reason": "Agent is banned under its ATH ruling; closing the orphaned hold",
    }
    stale = await client.post(
        "/api/v1/admin/screening-quarantines/batch-preview",
        json={"decisions": [{**decision, "expected_artifact_sha256": "0" * 64}]},
        headers=_HEADERS,
    )
    assert stale.json()["items"][0]["disposition"] == "conflict"
    assert stale.json()["items"][0]["message"] == "submission identity changed"
    release = await client.post(
        "/api/v1/admin/screening-quarantines/batch-preview",
        json={"decisions": [{**decision, "resolution": "release"}]},
        headers=_HEADERS,
    )
    released = release.json()["items"][0]
    assert (released["disposition"], released["terminal_reconciliation"]) == (
        "conflict",
        True,
    )

    preview = await client.post(
        "/api/v1/admin/screening-quarantines/batch-preview",
        json={"decisions": [decision]},
        headers=_HEADERS,
    )
    assert preview.status_code == 200
    item = preview.json()["items"][0]
    assert item["disposition"] == "ready"
    assert item["resulting_agent_status"] == AgentStatus.BANNED
    assert item["terminal_reconciliation"] is True
    assert item["public_record_hash"] is None
    request = {
        "decisions": [decision],
        "preview_token": preview.json()["preview_token"],
        "confirmed": True,
    }
    executed = await client.post(
        "/api/v1/admin/screening-quarantines/batch-resolve",
        json=request,
        headers=_HEADERS,
    )
    assert executed.status_code == 200
    applied = executed.json()["items"][0]
    assert (applied["status"], applied["agent_status"]) == ("applied", "banned")
    assert applied["terminal_reconciliation"] is True

    replay = await client.post(
        "/api/v1/admin/screening-quarantines/batch-resolve",
        json=request,
        headers=_HEADERS,
    )
    assert replay.json()["already_applied_count"] == 1

    async with session_maker() as session:
        agent = await session.get(Agent, agent_id)
        review = await session.scalar(
            select(AthReview).where(AthReview.agent_id == agent_id)
        )
        event = await session.scalar(
            select(ScreeningReviewEvent).where(
                ScreeningReviewEvent.quarantine_id == quarantine_id
            )
        )
        resolutions = int(
            await session.scalar(
                select(func.count())
                .select_from(ScreeningQuarantineResolution)
                .where(ScreeningQuarantineResolution.quarantine_id == quarantine_id)
            )
            or 0
        )
        snapshot = await load_source_review_queue_slo_snapshot(session)
    # The terminal ruling is untouched: same status, same miner-visible reason.
    assert agent is not None and review is not None and event is not None
    assert agent.status == AgentStatus.BANNED
    assert agent.screening_reason == _MINER_REASON
    assert agent.screening_reason_code == "source-review-high-risk"
    assert (review.status, review.resolution) == ("resolved", "reject")
    assert resolutions == 1
    assert event.actor == "operator"
    assert event.evidence["terminal_reconciliation"]["source"] == (
        "operator_reconciliation"
    )
    assert event.evidence["terminal_reconciliation"]["ath_review_id"] == str(
        review.review_id
    )
    assert snapshot.terminal_quarantine_ghost_count == 0
    assert await _active_quarantine_count(session_maker, agent_id) == 0


async def test_concurrent_ath_reject_and_screening_resolution_serialize(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    """The ATH ruling takes the screening resolvers' lock order.

    A screening resolution locks the quarantine and then the agent. While it
    holds the quarantine, a terminal ATH reject must wait for it instead of
    taking the agent lock first (a lock-order inversion Postgres would break
    with a deadlock), then close the quarantine once the resolution finds the
    agent is not quarantined and backs off.
    """
    agent_id, _sha256, quarantine_id = await _seed(
        session_maker, status=AgentStatus.ATH_PENDING_REVIEW, ath_resolution=None
    )
    _install(app, session_maker)

    async with session_maker() as screening, session_maker() as observer:
        await screening.begin()
        await screening.execute(
            select(ScreeningQuarantine)
            .where(ScreeningQuarantine.quarantine_id == quarantine_id)
            .with_for_update()
        )
        ruling = asyncio.create_task(
            client.post(
                f"/api/v1/admin/copy-reviews/{agent_id}/resolve",
                json={"resolution": "reject", "reason": _ATH_REASON},
                headers=_HEADERS,
            )
        )
        waiting = 0
        for _ in range(100):
            waiting = int(
                await observer.scalar(
                    text(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE datname = current_database() "
                        "AND wait_event_type = 'Lock'"
                    )
                )
                or 0
            )
            await observer.rollback()
            if waiting or ruling.done():
                break
            await asyncio.sleep(0.05)
        assert waiting == 1, "the ATH ruling must queue behind the quarantine lock"
        assert not ruling.done()

        agent = await asyncio.wait_for(
            screening.scalar(
                select(Agent).where(Agent.agent_id == agent_id).with_for_update()
            ),
            timeout=5,
        )
        assert agent is not None
        assert agent.status == AgentStatus.ATH_PENDING_REVIEW
        await screening.rollback()

    response = await asyncio.wait_for(ruling, timeout=10)
    assert response.status_code == 200, response.text
    assert response.json()["reconciled_quarantine_ids"] == [str(quarantine_id)]
    assert await _active_quarantine_count(session_maker, agent_id) == 0


async def test_cli_ban_closes_matching_active_quarantine(
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    """The owner-only ``scripts/resolve_review.py`` ban obeys the same rule."""
    agent_id, _sha256, quarantine_id = await _seed(
        session_maker, status=AgentStatus.ATH_PENDING_REVIEW, ath_resolution=None
    )

    async with session_maker() as session, session.begin():
        agent = await resolve_review(
            session, agent_id=agent_id, decision=AgentStatus.BANNED
        )
        assert agent is not None and agent.status == AgentStatus.BANNED

    assert await _active_quarantine_count(session_maker, agent_id) == 0
    async with session_maker() as session:
        event = await session.scalar(
            select(ScreeningReviewEvent).where(
                ScreeningReviewEvent.quarantine_id == quarantine_id
            )
        )
    assert event is not None
    assert event.actor == "cli:scripts/resolve_review.py"
    assert event.evidence["terminal_reconciliation"]["ath_review_id"] is None
