"""Report-only L2 canaries pinned to an ``l2-report-canary*`` review posture."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException, Request, Response
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ditto.api_models.agent_status import AgentStatus
from ditto.api_models.l2_report_canary import (
    L2CanaryClaimRequest,
    L2CanaryClaimResponse,
    L2CanaryScheduleRequest,
)
from ditto.api_models.screener_review_settings import (
    ScreenerReviewSettings,
    review_settings_checksum,
)
from ditto.api_server.endpoints import l2_report_canary as endpoints
from ditto.api_server.storage import S3StorageClient
from ditto.db.models import (
    ScreenerL2ReportCanary,
    ScreenerNode,
    ScreenerReviewSettingsRevision,
    ScreeningAttempt,
)
from ditto.tests.api_server.endpoints.test_l2_report_canary import _packet
from ditto.tests.api_server.endpoints.test_screener import _seed_agent

_SHA = "d" * 64


async def _seed_revision(
    maker: async_sessionmaker[AsyncSession],
    *,
    scope: str,
    settings: ScreenerReviewSettings,
    mode: str | None = None,
) -> ScreenerReviewSettingsRevision:
    stored = settings.model_dump(mode="json")
    if mode is not None:
        stored["mode"] = mode
    row = ScreenerReviewSettingsRevision(
        parent_revision=0,
        scope=scope,
        settings=stored,
        checksum=review_settings_checksum(settings),
        reason="report-only canary posture under test",
        actor="test",
    )
    async with maker() as session, session.begin():
        session.add(row)
    return row


async def _seed_source(
    maker: async_sessionmaker[AsyncSession],
) -> tuple[str, UUID, UUID]:
    agent_id = await _seed_agent(maker, status=AgentStatus.REJECTED, sha256=_SHA)
    node_id = f"canary-pin-{uuid4().hex[:12]}"
    attempt_id = uuid4()
    now = datetime.now(UTC)
    async with maker() as session, session.begin():
        session.add(
            ScreenerNode(
                environment="prod",
                node_id=node_id,
                provider="hetzner",
                provider_resource_id=node_id,
                screener_hotkey=f"hotkey-{node_id}",
                token_hash="f" * 64,
                token_expires_at=now + timedelta(hours=1),
                status="active",
                capacity=1,
            )
        )
        await session.flush()
        session.add(
            ScreeningAttempt(
                attempt_id=attempt_id,
                agent_id=agent_id,
                artifact_sha256=_SHA,
                screener_hotkey=f"hotkey-{node_id}",
                policy_version=13,
                status="rejected",
                started_at=now - timedelta(minutes=1),
                deadline=now,
                finished_at=now,
            )
        )
    return node_id, agent_id, attempt_id


def _schedule_request(
    *, node_id: str, agent_id: UUID, attempt_id: UUID, revision: int | None
) -> L2CanaryScheduleRequest:
    return L2CanaryScheduleRequest(
        request_id=uuid4(),
        agent_id=agent_id,
        source_attempt_id=attempt_id,
        artifact_sha256=_SHA,
        policy_version=13,
        expected_agent_status="rejected",
        expected_score_count=0,
        target_node_id=node_id,
        review_label="known_reject",
        review_settings_revision=revision,
        confirm_report_only=True,
    )


async def _schedule(
    maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    payload: L2CanaryScheduleRequest,
):
    monkeypatch.setattr(endpoints, "arrival_bench_version", AsyncMock(return_value=13))
    async with maker() as session:
        return await endpoints.schedule_l2_report_canary(
            payload, None, session, cast(S3StorageClient, SimpleNamespace())
        )


async def _claim(
    maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    *,
    node_id: str,
    attempt_id: UUID,
    revision: int,
    checksum: str,
) -> L2CanaryClaimResponse | None:
    monkeypatch.setattr(
        endpoints,
        "scored_runtime_evidence_for_lease",
        AsyncMock(return_value=_packet(attempt_id, _SHA)),
    )
    storage = cast(
        S3StorageClient,
        SimpleNamespace(
            presigned_get_url=AsyncMock(return_value="https://example.test/source")
        ),
    )
    request = cast(
        Request, SimpleNamespace(state=SimpleNamespace(screener_node_id=node_id))
    )
    async with maker() as session:
        return await endpoints.claim_l2_report_canary(
            L2CanaryClaimRequest(
                instance_id=f"{node_id}-worker-1",
                settings_revision=revision,
                settings_checksum=checksum,
            ),
            request,
            Response(),
            f"hotkey-{node_id}",
            session,
            storage,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("worker_revision", ["node_effective", "stale"])
async def test_pinned_canary_claims_under_pinned_revision_not_node_effective(
    session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    worker_revision: str,
) -> None:
    node_id, agent_id, attempt_id = await _seed_source(session_maker)
    node_settings = ScreenerReviewSettings(mode="enforce")
    node_rev = await _seed_revision(
        session_maker, scope=node_id, settings=node_settings
    )
    pin_settings = ScreenerReviewSettings(
        mode="enforce", source_review_timeout_seconds=1800, timeout_seconds=900
    )
    pin = await _seed_revision(
        session_maker, scope="l2-report-canary-ctl137", settings=pin_settings
    )

    scheduled = await _schedule(
        session_maker,
        monkeypatch,
        _schedule_request(
            node_id=node_id,
            agent_id=agent_id,
            attempt_id=attempt_id,
            revision=pin.revision,
        ),
    )
    assert (
        scheduled.review_settings_revision,
        scheduled.review_settings_scope,
        scheduled.review_settings_checksum,
    ) == (pin.revision, pin.scope, pin.checksum)

    before = datetime.now(UTC)
    claimed = await _claim(
        session_maker,
        monkeypatch,
        node_id=node_id,
        attempt_id=attempt_id,
        # A worker whose node posture moved on can still run a pinned canary.
        revision=node_rev.revision if worker_revision == "node_effective" else 1,
        checksum=node_rev.checksum if worker_revision == "node_effective" else "0" * 64,
    )
    assert claimed is not None
    assert claimed.review_settings_override is not None
    assert claimed.review_settings_override.model_dump() == {
        "revision": pin.revision,
        "scope": "l2-report-canary-ctl137",
        "checksum": pin.checksum,
    }
    # 1800 s L1 + 900 s L2 + 10 min source-only overhead, not the node's
    # 3600 s + 1200 s posture.
    lease = claimed.lease_expires_at - before
    assert timedelta(minutes=55) <= lease < timedelta(minutes=56)
    async with session_maker() as session:
        row = await session.get(ScreenerL2ReportCanary, scheduled.canary_id)
    assert row is not None
    assert (row.settings_revision, row.settings_checksum) == (
        pin.revision,
        pin.checksum,
    )
    packet = _packet(attempt_id, _SHA).model_dump(mode="json")
    row.runtime_evidence_sha256 = hashlib.sha256(
        json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    report = {
        "kind": "l2_report_canary_v1",
        "authority": "none",
        "review_mode": "enforce_preview",
        "canary_id": str(row.canary_id),
        "agent_id": str(agent_id),
        "source_attempt_id": str(attempt_id),
        "artifact_sha256": _SHA,
        "policy_version": 13,
        "run_mode": "source_only",
        "settings_revision": pin.revision,
        "settings_checksum": pin.checksum,
        "scored_runtime_evidence": packet,
    }
    assert endpoints._valid_report(row, report)
    assert not endpoints._valid_report(
        row, {**report, "settings_revision": node_rev.revision}
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["*", "node", "bootstrap", "inherit", "missing"])
async def test_schedule_rejects_production_or_inherit_pin_scope(
    session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
) -> None:
    node_id, agent_id, attempt_id = await _seed_source(session_maker)
    revision = 999_999
    if scope != "missing":
        pin = await _seed_revision(
            session_maker,
            scope={
                "*": "*",
                "node": node_id,
                "bootstrap": "bootstrap",
                "inherit": "l2-report-canary-inherit",
            }[scope],
            settings=ScreenerReviewSettings(mode="enforce"),
            mode="inherit" if scope == "inherit" else None,
        )
        revision = pin.revision
    with pytest.raises(HTTPException) as raised:
        await _schedule(
            session_maker,
            monkeypatch,
            _schedule_request(
                node_id=node_id,
                agent_id=agent_id,
                attempt_id=attempt_id,
                revision=revision,
            ),
        )
    assert raised.value.status_code == (404 if scope == "missing" else 422)
    async with session_maker() as session:
        queued = await session.scalar(
            select(ScreenerL2ReportCanary.canary_id).where(
                ScreenerL2ReportCanary.source_attempt_id == attempt_id
            )
        )
    assert queued is None


@pytest.mark.asyncio
async def test_pinned_claim_rejects_checksum_drift(
    session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node_id, agent_id, attempt_id = await _seed_source(session_maker)
    node_rev = await _seed_revision(
        session_maker, scope=node_id, settings=ScreenerReviewSettings(mode="enforce")
    )
    pin = await _seed_revision(
        session_maker,
        scope="l2-report-canary-drift",
        settings=ScreenerReviewSettings(mode="enforce", timeout_seconds=900),
    )
    scheduled = await _schedule(
        session_maker,
        monkeypatch,
        _schedule_request(
            node_id=node_id,
            agent_id=agent_id,
            attempt_id=attempt_id,
            revision=pin.revision,
        ),
    )
    async with session_maker() as session, session.begin():
        await session.execute(
            update(ScreenerReviewSettingsRevision)
            .where(ScreenerReviewSettingsRevision.revision == pin.revision)
            .values(checksum="e" * 64)
        )

    assert (
        await _claim(
            session_maker,
            monkeypatch,
            node_id=node_id,
            attempt_id=attempt_id,
            revision=node_rev.revision,
            checksum=node_rev.checksum,
        )
        is None
    )
    async with session_maker() as session:
        row = await session.get(ScreenerL2ReportCanary, scheduled.canary_id)
    assert row is not None
    assert (row.status, row.error_code) == ("incomplete", "review-settings-pin-changed")
    assert row.lease_token_hash is None


@pytest.mark.asyncio
async def test_unpinned_canary_still_requires_node_settings(
    session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node_id, agent_id, attempt_id = await _seed_source(session_maker)
    node_rev = await _seed_revision(
        session_maker, scope=node_id, settings=ScreenerReviewSettings(mode="enforce")
    )
    scheduled = await _schedule(
        session_maker,
        monkeypatch,
        _schedule_request(
            node_id=node_id, agent_id=agent_id, attempt_id=attempt_id, revision=None
        ),
    )
    assert scheduled.review_settings_revision is None

    with pytest.raises(HTTPException) as raised:
        await _claim(
            session_maker,
            monkeypatch,
            node_id=node_id,
            attempt_id=attempt_id,
            revision=node_rev.revision - 1,
            checksum="0" * 64,
        )
    assert raised.value.status_code == 409
    assert raised.value.detail == "canary review settings changed"

    claimed = await _claim(
        session_maker,
        monkeypatch,
        node_id=node_id,
        attempt_id=attempt_id,
        revision=node_rev.revision,
        checksum=node_rev.checksum,
    )
    assert claimed is not None
    assert claimed.review_settings_override is None
    async with session_maker() as session:
        row = await session.get(ScreenerL2ReportCanary, scheduled.canary_id)
    assert row is not None
    assert (row.settings_revision, row.settings_checksum) == (
        node_rev.revision,
        node_rev.checksum,
    )
