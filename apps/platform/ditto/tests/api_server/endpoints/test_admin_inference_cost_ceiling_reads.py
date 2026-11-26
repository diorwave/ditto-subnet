"""The cost-ceiling operator reads (#3271) against a real grant ledger.

Two claims an operator acts on: which wall a run hit (the failure taxonomy's
``allowance_walls``) and what one run costs (the ledger-cost distribution the
ceiling is sized from).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ditto.api_models.inference_concurrency_settings import (
    InferenceConcurrencySettings,
)
from ditto.api_models.ticket_status import TicketStatus
from ditto.api_server.dependencies import get_session
from ditto.db.models import Agent, AgentStatus, InferenceGrant, ValidatorTicket
from ditto.db.queries.inference_concurrency_settings import (
    insert_inference_concurrency_settings_revision,
)

pytestmark = pytest.mark.asyncio

_TAXONOMY = "/api/v1/admin/inference-failure-taxonomy"
_DISTRIBUTION = "/api/v1/admin/inference-ledger-cost-distribution"
_ADMIN_TOKEN = "test-admin-token-at-least-32-characters"
_HEADERS = {"Authorization": f"Bearer {_ADMIN_TOKEN}"}


def _install(app: FastAPI, session_maker: async_sessionmaker[AsyncSession]) -> None:
    app.state.config = replace(app.state.config, admin_api_token=_ADMIN_TOKEN)

    async def _session() -> AsyncIterator[AsyncSession]:
        async with session_maker() as session:
            yield session

    app.dependency_overrides[get_session] = _session


async def _grant(
    session: AsyncSession,
    *,
    expires_at: datetime,
    bench_version: int = 15,
    status: str = "active",
    request_count: int = 0,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    embedding_tokens: int = 0,
    ledger: int = 0,
    mode: str = "off",
    ceiling: int | None = None,
    would_decline: int = 0,
    accounting_version: int = 2,
) -> None:
    agent = Agent(
        agent_id=uuid4(),
        miner_hotkey=f"miner-{uuid4().hex[:8]}",
        name="cost-ceiling-reads",
        sha256=uuid4().hex * 2,
        status=AgentStatus.EVALUATING,
        created_at=expires_at - timedelta(hours=3),
    )
    ticket = ValidatorTicket(
        agent_id=agent.agent_id,
        validator_hotkey=f"validator-{uuid4().hex[:12]}",
        slot_id="slot-0",
        status=TicketStatus.ISSUED,
        issued_at=expires_at - timedelta(hours=2),
        deadline=expires_at,
        bench_version=bench_version,
        attempt_count=1,
    )
    session.add_all([agent, ticket])
    await session.flush()
    session.add(
        InferenceGrant(
            grant_id=uuid4(),
            agent_id=agent.agent_id,
            bench_version=bench_version,
            validator_hotkey=ticket.validator_hotkey,
            slot_id=ticket.slot_id,
            ticket_deadline=ticket.deadline,
            status=status,
            generation=1,
            allowed_models=["openai/gpt-oss-20b"],
            request_budget=100,
            token_budget=1_000_000,
            embedding_model="test-embedding",
            embedding_profile="openrouter-embedding-test-v1",
            embedding_provider="perplexity",
            embedding_dimensions=768,
            embedding_request_budget=1000,
            embedding_token_budget=1_000_000,
            embedding_request_count=0,
            embedding_tokens=embedding_tokens,
            embedding_cost_microusd=0,
            embedding_active_requests=0,
            request_count=request_count,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_microusd=0,
            active_requests=0,
            ledger_cost_microusd=ledger,
            cost_ceiling_microusd=ceiling,
            cost_ceiling_mode=mode,
            cost_ceiling_would_decline=would_decline,
            usage_accounting_version=accounting_version,
            expires_at=expires_at,
        )
    )
    await session.flush()


def _by_window(body: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {int(row["window_seconds"]): row for row in body["allowance_walls"]}


async def test_reads_require_the_admin_token(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    _install(app, session_maker)
    assert (await client.get(_DISTRIBUTION)).status_code == 401
    for hours in (0, 745):
        response = await client.get(f"{_DISTRIBUTION}?hours={hours}", headers=_HEADERS)
        assert response.status_code == 422


async def test_taxonomy_splits_run_walls_and_keeps_an_unexplained_exhaustion(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    _install(app, session_maker)
    now = datetime.now(UTC)
    async with session_maker() as session, session.begin():
        # Live run that spent its enforced ceiling, and its token wall too:
        # admission names the cost wall first, so it counts there only.
        await _grant(
            session,
            expires_at=now + timedelta(minutes=30),
            status="exhausted",
            prompt_tokens=1_000_000,
            ledger=5_000,
            mode="enforce",
            ceiling=5_000,
        )
        # Ended two hours ago at the chat token wall.
        await _grant(
            session,
            expires_at=now - timedelta(hours=2),
            status="exhausted",
            prompt_tokens=900_000,
            completion_tokens=100_000,
        )
        # Ended two days ago at the request wall. Admission rolls the
        # exhausted status back with the decline, so the meter decides.
        await _grant(session, expires_at=now - timedelta(days=2), request_count=100)
        # Shadow at its ceiling is not a wall; it only counts would_decline.
        await _grant(
            session,
            expires_at=now - timedelta(minutes=10),
            ledger=9_000,
            mode="shadow",
            ceiling=5_000,
            would_decline=3,
        )
        # A v1 grant marked exhausted: its counters prove nothing.
        await _grant(
            session,
            expires_at=now - timedelta(minutes=5),
            status="exhausted",
            prompt_tokens=2_000_000,
            accounting_version=1,
        )
        # Outside every window.
        await _grant(
            session,
            expires_at=now - timedelta(days=8),
            status="exhausted",
            prompt_tokens=1_000_000,
        )

    body = (await client.get(_TAXONOMY, headers=_HEADERS)).json()
    assert body["allowance_window_seconds"] == [3600, 86400, 604800]
    walls = _by_window(body)
    assert walls[3600] == {
        "window_seconds": 3600,
        "grants_at_wall": 2,
        "request": 0,
        "token": 0,
        "cost": 1,
        "unknown": 1,
    }
    assert walls[86400]["token"] == 1
    assert walls[86400]["grants_at_wall"] == 3
    assert walls[604800] == {
        "window_seconds": 604800,
        "grants_at_wall": 4,
        "request": 1,
        "token": 1,
        "cost": 1,
        "unknown": 1,
    }


async def test_a_clean_ledger_reports_every_wall_window_as_zero(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    _install(app, session_maker)
    body = (await client.get(_TAXONOMY, headers=_HEADERS)).json()
    assert [row["grants_at_wall"] for row in body["allowance_walls"]] == [0, 0, 0]


async def test_distribution_sizes_the_ceiling_from_ended_booked_leases(
    app: FastAPI,
    client: httpx.AsyncClient,
    session_maker: async_sessionmaker[AsyncSession],
) -> None:
    _install(app, session_maker)
    now = datetime.now(UTC)
    async with session_maker() as session, session.begin():
        ended = now - timedelta(hours=1)
        for ledger in (100, 200, 300, 400):
            await _grant(session, expires_at=ended, prompt_tokens=10, ledger=ledger)
        # A run that receipted nothing is a genuine zero.
        await _grant(session, expires_at=ended)
        # Usage with no ledger: settled before the ledger existed.
        await _grant(session, expires_at=ended, embedding_tokens=50)
        await _grant(
            session,
            expires_at=ended,
            prompt_tokens=10,
            ledger=900,
            mode="shadow",
            ceiling=500,
            would_decline=4,
        )
        await _grant(
            session,
            expires_at=ended,
            prompt_tokens=10,
            ledger=500,
            mode="enforce",
            ceiling=500,
        )
        # Other bench, live lease (excluded), and a lease before the window.
        await _grant(
            session, expires_at=ended, bench_version=14, ledger=7, prompt_tokens=1
        )
        await _grant(session, expires_at=now + timedelta(hours=1), ledger=99_999)
        await _grant(session, expires_at=now - timedelta(days=9), ledger=88_888)
        await insert_inference_concurrency_settings_revision(
            session,
            parent_revision=0,
            scope="*",
            settings=InferenceConcurrencySettings(
                run_cost_ceiling_microusd=750, cost_ceiling_mode="shadow"
            ).model_dump(mode="json"),
            checksum="e" * 64,
            reason="size the ceiling from the ledger",
            actor="tester",
        )

    response = await client.get(_DISTRIBUTION, headers=_HEADERS)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["aggregation_basis"] == "grant_expires_at_ended_leases"
    assert body["run_cost_ceiling_microusd"] == 750
    assert body["cost_ceiling_mode"] == "shadow"
    assert body["case_cost_report_microusd"] is None
    assert [bench["bench_version"] for bench in body["benches"]] == [15, 14]
    bench = body["benches"][0]
    # Booked: 0, 100, 200, 300, 400, 500, 900 (seven); one unbooked left out.
    assert bench == {
        "bench_version": 15,
        "grants": 8,
        "unbooked_grants": 1,
        "p50_microusd": 300,
        "p95_microusd": 900,
        "p99_microusd": 900,
        "max_microusd": 900,
        "total_microusd": 2400,
        "shadow_grants": 1,
        "enforce_grants": 1,
        "would_decline": 4,
        "grants_with_would_decline": 1,
        "cost_wall_grants": 1,
    }
