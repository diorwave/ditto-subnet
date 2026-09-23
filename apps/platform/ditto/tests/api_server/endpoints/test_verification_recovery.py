"""Policy-v13 verification readiness ledger and bounded recovery replay.

Every case here is one of the failure shapes #2117 lists: a verdict-contract
court failure, a provider completion timeout, a static lead later refuted, stale
artifact / image / policy guards, a duplicate replay, independent-worker
selection, and private-challenge non-disclosure. The recurring assertion is the
one the four holds depend on: whatever the replay reports, the agent's status and
its quarantine are unchanged, and no decision record appears.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ditto.api_models.agent_status import AgentStatus
from ditto.api_models.verification_recovery import RESUME_VERIFICATION_CONFIRMATION
from ditto.api_server.dependencies import get_session
from ditto.api_server.endpoints.verification_recovery import (
    CHALLENGE_MANIFEST_VERSION,
    RECOVERY_EVIDENCE_SOURCES,
)
from ditto.db.models import (
    Agent,
    ScreenerNode,
    ScreeningAttempt,
    ScreeningQuarantine,
    ScreeningVerificationEvent,
    ScreeningVerificationRecovery,
)
from ditto_screening_protocol import (
    INTEGRITY_CHECK_IDS,
    MANDATORY_VERIFICATION_CHECKS,
    NOT_RECORDED,
    OPAQUE_ROLE_IDS,
    SCREENING_POLICY_VERSION,
    SECURITY_CHECK_IDS,
)

_ADMIN_TOKEN = "test-admin-token-at-least-32-characters"
_ADMIN_HEADERS = {
    "Authorization": f"Bearer {_ADMIN_TOKEN}",
    "X-Admin-Actor": "backroom:verification-reviewer",
}
_FLEET_HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
_FLEET_HEADERS = {
    "Authorization": "Bearer test-screener-token-at-least-32-characters",
    "X-Screener-Hotkey": _FLEET_HOTKEY,
}
_SECOND_HOTKEY = "5IndependentScreenerHotkeyXXXXXXXXXXXXXXXXXXXXX"
_SECOND_TOKEN = "test-second-screener-token-at-least-32-chars"
_SECOND_HEADERS = {
    "Authorization": f"Bearer {_SECOND_TOKEN}",
    "X-Screener-Hotkey": _SECOND_HOTKEY,
}
_SHA256 = "ab" * 32
_MANIFEST_DIGEST = "cd" * 32
_IMAGE_DIGEST = "ef" * 32
_MINER_HOTKEY = "5MinerHotkeyPlaceholderXXXXXXXXXXXXXXXXXXXXXXX"
_RESUME = RESUME_VERIFICATION_CONFIRMATION

_VERDICT_CONTRACT_TRACE = {
    "error_class": "ValueError",
    "escalation_code": "adjudicator-failed",
    "timeout_stage": "response",
    "elapsed_ms": 41_200,
    "prompt_tokens": 1180,
    "completion_tokens": 0,
    "final_tool_call_returned": False,
    "model": "z-ai/glm-5.3-flash",
    "provider": "openrouter",
    "upstream": "sail-research",
}
"""The verdict-contract failure shape reported on Sky v2 / whoamI v10."""

_PROVIDER_TIMEOUT_TRACE = {
    "error_class": "TimeoutError",
    "escalation_code": "adjudicator-failed",
    "timeout_stage": "completion",
    "elapsed_ms": 315_295,
    "prompt_tokens": 1180,
    "completion_tokens": None,
    "final_tool_call_returned": False,
    "model": "z-ai/glm-5.3-flash",
    "provider": "openrouter",
    "upstream": None,
}
"""The 315,295 ms silent-completion shape reported on ditto v1."""


def _install_db(app: FastAPI, maker: async_sessionmaker[AsyncSession]) -> None:
    async def _session() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    app.dependency_overrides[get_session] = _session


def _configure(app: FastAPI) -> None:
    app.state.config = replace(app.state.config, admin_api_token=_ADMIN_TOKEN)


async def _seed_hold(
    maker: async_sessionmaker[AsyncSession],
    *,
    reason_code: str = "adjudicated-source-review-escalate",
    court_diagnostic: dict | None = None,
    finding_digest: str | None = None,
    review_notes: list | None = None,
    image_digest: str | None = _IMAGE_DIGEST,
    quarantine_status: str = "active",
    extra_attempt_hotkeys: tuple[str, ...] = (),
    name: str = "held-artifact",
    version: int = 1,
    attempt_artifact_sha256: str | None = None,
) -> tuple[UUID, UUID, UUID]:
    """Seed one quarantined v13 submission and return its ids."""
    agent_id = uuid4()
    attempt_id = uuid4()
    quarantine_id = uuid4()
    now = datetime.now(UTC)
    async with maker() as session, session.begin():
        session.add(
            Agent(
                agent_id=agent_id,
                miner_hotkey=_MINER_HOTKEY,
                name=name,
                version=version,
                sha256=_SHA256,
                status=AgentStatus.QUARANTINED,
                screening_policy_version=SCREENING_POLICY_VERSION,
                created_at=now - timedelta(hours=3),
                screened_image_sha256=image_digest,
                screened_image_size_bytes=4096 if image_digest else None,
                screened_image_id=("sha256:" + "34" * 32) if image_digest else None,
                screened_image_ref=(
                    f"ditto-screen/{agent_id}:latest" if image_digest else None
                ),
                screened_image_upload_id=uuid4() if image_digest else None,
                screened_image_verified_at=now if image_digest else None,
            )
        )
        await session.flush()
        for index, hotkey in enumerate((_FLEET_HOTKEY, *extra_attempt_hotkeys)):
            session.add(
                ScreeningAttempt(
                    attempt_id=attempt_id if index == 0 else uuid4(),
                    agent_id=agent_id,
                    artifact_sha256=attempt_artifact_sha256 if index == 0 else None,
                    screener_hotkey=hotkey,
                    policy_version=SCREENING_POLICY_VERSION,
                    status="quarantined" if index == 0 else "failed",
                    started_at=now - timedelta(minutes=30 + index),
                    deadline=now - timedelta(minutes=20 + index),
                    finished_at=now - timedelta(minutes=25 + index),
                    public_reason="Submission held for anti-cheat review",
                    reason_code=reason_code,
                )
            )
        session.add(
            ScreeningQuarantine(
                quarantine_id=quarantine_id,
                agent_id=agent_id,
                attempt_id=attempt_id,
                screener_hotkey=_FLEET_HOTKEY,
                policy_version=SCREENING_POLICY_VERSION,
                manifest_digest=_MANIFEST_DIGEST,
                finding_digest=finding_digest,
                reason_code=reason_code,
                review_notes=review_notes,
                review_notes_digest=("9a" * 32) if review_notes is not None else None,
                court_diagnostic=court_diagnostic,
                status=quarantine_status,
                created_at=now - timedelta(minutes=25),
            )
        )
    return agent_id, attempt_id, quarantine_id


async def _seed_independent_worker(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as session, session.begin():
        session.add(
            ScreenerNode(
                environment="prod",
                node_id="independent-1",
                provider="test",
                provider_resource_id="test-resource-independent-1",
                screener_hotkey=_SECOND_HOTKEY,
                token_hash=hashlib.sha256(_SECOND_TOKEN.encode()).hexdigest(),
                token_expires_at=datetime.now(UTC) + timedelta(hours=1),
                status="active",
                capacity=1,
            )
        )


def _grant_body(
    *,
    attempt_id: UUID,
    quarantine_id: UUID,
    sha256: str = _SHA256,
    score_count: int = 0,
    attempt_count: int = 1,
    policy_version: int = SCREENING_POLICY_VERSION,
    manifest_digest: str = _MANIFEST_DIGEST,
    image_digest: str | None = _IMAGE_DIGEST,
    reason: str = "court failed without a finding; resume mandatory verification",
) -> dict[str, Any]:
    return {
        "reason": reason,
        "expected_sha256": sha256,
        "expected_score_count": score_count,
        "expected_attempt_id": str(attempt_id),
        "expected_attempt_count": attempt_count,
        "expected_quarantine_id": str(quarantine_id),
        "expected_policy_version": policy_version,
        "expected_manifest_digest": manifest_digest,
        "expected_image_digest": image_digest,
        "confirmation": _RESUME,
    }


def _readiness_url(agent_id: UUID) -> str:
    return f"/api/v1/admin/screening-submissions/{agent_id}/verification-readiness"


def _recovery_url(agent_id: UUID) -> str:
    return f"/api/v1/admin/screening-submissions/{agent_id}/verification-recovery"


async def _assert_hold_intact(
    maker: async_sessionmaker[AsyncSession], agent_id: UUID
) -> None:
    """The invariant every case shares: the hold did not move."""
    async with maker() as session:
        agent = await session.get(Agent, agent_id)
        assert agent is not None
        assert agent.status == AgentStatus.QUARANTINED
        quarantine = await session.scalar(
            select(ScreeningQuarantine).where(ScreeningQuarantine.agent_id == agent_id)
        )
        assert quarantine is not None
        assert quarantine.status == "active"
        assert quarantine.resolution is None
        assert quarantine.resolved_at is None


class TestVerificationReadiness:
    async def test_unknown_agent_is_not_found(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _configure(app)
        _install_db(app, session_maker)

        response = await client.get(_readiness_url(uuid4()), headers=_ADMIN_HEADERS)

        assert response.status_code == 404

    async def test_requires_an_operator_actor(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _configure(app)
        agent_id, _, _ = await _seed_hold(session_maker)
        _install_db(app, session_maker)

        response = await client.get(
            _readiness_url(agent_id),
            headers={"Authorization": _ADMIN_HEADERS["Authorization"]},
        )

        assert response.status_code == 422

    async def test_verdict_contract_failure_is_reported_without_inferring_evidence(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        """A verdict-contract court failure leaves every check unrecorded.

        The hold carries L1 review notes. They must not become verification
        evidence, and they must not appear among the consulted stores."""
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(
            session_maker,
            court_diagnostic=_VERDICT_CONTRACT_TRACE,
            review_notes=[
                {
                    "path": "agent/router.py",
                    "line": 12,
                    "note": "reviewer narrative that is not verification evidence",
                }
            ],
        )
        _install_db(app, session_maker)

        response = await client.get(_readiness_url(agent_id), headers=_ADMIN_HEADERS)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["quarantine_id"] == str(quarantine_id)
        assert body["is_non_decisive_hold"] is True
        assert body["has_established_finding"] is False
        assert body["last_court_failure"]["attempt_id"] == str(attempt_id)
        assert body["last_court_failure"]["stage"] == "response"
        assert body["last_court_failure"]["diagnostic"]["error_class"] == "ValueError"
        assert (
            body["last_court_failure"]["diagnostic"]["escalation_code"]
            == "adjudicator-failed"
        )
        assert body["last_court_failure"]["diagnostic"]["upstream"] == "sail-research"
        assert {check["state"] for check in body["mandatory_checks"]} == {NOT_RECORDED}
        assert len(body["mandatory_checks"]) == len(MANDATORY_VERIFICATION_CHECKS)
        assert body["outstanding_mandatory_checks"] == [
            check.check_id for check in MANDATORY_VERIFICATION_CHECKS
        ]
        assert [rule["rule_id"] for rule in body["integrity_rules"]] == list(
            INTEGRITY_CHECK_IDS
        )
        assert {rule["state"] for rule in body["integrity_rules"]} == {NOT_RECORDED}
        assert [rule["rule_id"] for rule in body["security_rules"]] == list(
            SECURITY_CHECK_IDS
        )
        assert {rule["state"] for rule in body["security_rules"]} == {NOT_RECORDED}
        assert [role["rule_id"] for role in body["opaque_roles"]] == list(
            OPAQUE_ROLE_IDS
        )
        assert body["private_paired_required"] is None
        assert body["recovery"] is None
        assert body["evidence_sources"] == list(RECOVERY_EVIDENCE_SOURCES)
        assert not any("review_notes" in source for source in body["evidence_sources"])
        assert "review_notes" not in response.text
        assert "reviewer narrative" not in response.text

    async def test_provider_timeout_court_failure_is_reported(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _configure(app)
        agent_id, _, _ = await _seed_hold(
            session_maker, court_diagnostic=_PROVIDER_TIMEOUT_TRACE
        )
        _install_db(app, session_maker)

        response = await client.get(_readiness_url(agent_id), headers=_ADMIN_HEADERS)

        assert response.status_code == 200, response.text
        failure = response.json()["last_court_failure"]
        assert failure["stage"] == "completion"
        assert failure["diagnostic"]["error_class"] == "TimeoutError"
        assert failure["diagnostic"]["elapsed_ms"] == 315_295
        assert failure["diagnostic"]["upstream"] is None

    async def test_unknown_digests_serialize_as_not_recorded(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        """An unpinned image and the absent profile digests stay explicit.

        A null would let a reader treat unknown evidence as inapplicable."""
        _configure(app)
        agent_id, _, _ = await _seed_hold(session_maker, image_digest=None)
        _install_db(app, session_maker)

        response = await client.get(_readiness_url(agent_id), headers=_ADMIN_HEADERS)

        assert response.status_code == 200, response.text
        bindings = response.json()["evidence_bindings"]
        assert bindings == {
            "artifact_sha256": _SHA256,
            "image_digest": NOT_RECORDED,
            "policy_digest": _MANIFEST_DIGEST,
            "opaque_manifest_digest": NOT_RECORDED,
            "verification_profile_digest": NOT_RECORDED,
            "challenge_manifest_digest": NOT_RECORDED,
        }

    async def test_finalizer_deadline_is_deferred_not_invented(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        """The ledger reports the attempt lease deadline and no artifact deadline.

        The effective finalizer read is #2100 / #2115's; computing a second
        24-hour window here is exactly what #2100 refused."""
        _configure(app)
        agent_id, _, _ = await _seed_hold(session_maker)
        _install_db(app, session_maker)

        response = await client.get(_readiness_url(agent_id), headers=_ADMIN_HEADERS)

        assert response.status_code == 200, response.text
        finalizer = response.json()["finalizer"]
        assert finalizer["finalizer_state"] == "not_configured"
        assert finalizer["verification_deadline"] is None
        assert finalizer["deadline_provenance"] is None
        assert finalizer["attempt_deadline"] is not None
        assert finalizer["source"] == "screening_verification_state"
        defaults = response.json()["published_retry_defaults"]
        assert defaults["platform_failure_retries"] == 2
        assert defaults["provider_failure_retries"] == 2
        assert defaults["artifact_failure_retries"] == 1
        assert defaults["maximum_verification_window_hours"] == 24
        assert defaults["enforced"] is False

    async def test_reading_readiness_changes_nothing(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _configure(app)
        agent_id, _, _ = await _seed_hold(session_maker)
        _install_db(app, session_maker)

        first = await client.get(_readiness_url(agent_id), headers=_ADMIN_HEADERS)
        second = await client.get(_readiness_url(agent_id), headers=_ADMIN_HEADERS)

        assert first.status_code == 200
        assert second.status_code == 200
        async with session_maker() as session:
            recovery = await session.scalar(select(ScreeningVerificationRecovery))
        assert recovery is None
        await _assert_hold_intact(session_maker, agent_id)


class TestAuthorizeVerificationRecovery:
    async def test_grant_queues_the_outstanding_checks_and_keeps_the_hold(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(
            session_maker, court_diagnostic=_VERDICT_CONTRACT_TRACE
        )
        _install_db(app, session_maker)

        response = await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json=_grant_body(attempt_id=attempt_id, quarantine_id=quarantine_id),
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["idempotent"] is False
        assert body["agent_status"] == AgentStatus.QUARANTINED
        assert body["quarantine_status"] == "active"
        recovery = body["recovery"]
        assert recovery["state"] == "queued"
        assert recovery["outstanding_checks"] == [
            check.check_id for check in MANDATORY_VERIFICATION_CHECKS
        ]
        assert recovery["reused_evidence"] == []
        assert recovery["independent_worker_required"] is True
        assert recovery["excluded_screener_hotkeys"] == [_FLEET_HOTKEY]
        assert recovery["challenge_manifest_version"] == CHALLENGE_MANIFEST_VERSION
        assert len(recovery["challenge_commitment"]) == 64
        assert [event["event"] for event in body["audit"]] == ["authorized"]
        assert body["audit"][0]["actor"] == _ADMIN_HEADERS["X-Admin-Actor"]
        await _assert_hold_intact(session_maker, agent_id)

    async def test_challenge_randomness_is_fresh_and_never_disclosed(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        """Two grants draw different randomness, and no operator surface leaks it.

        The stored seed is the private challenge material: only its commitment
        may appear in an admin response, a readiness read, or an audit row."""
        _configure(app)
        seeds: list[str] = []
        commitments: list[str] = []
        for index in range(2):
            agent_id, attempt_id, quarantine_id = await _seed_hold(
                session_maker, name=f"held-artifact-{index}"
            )
            _install_db(app, session_maker)
            created = await client.post(
                _recovery_url(agent_id),
                headers=_ADMIN_HEADERS,
                json=_grant_body(attempt_id=attempt_id, quarantine_id=quarantine_id),
            )
            assert created.status_code == 200, created.text
            readiness = await client.get(
                _readiness_url(agent_id), headers=_ADMIN_HEADERS
            )
            assert readiness.status_code == 200, readiness.text
            async with session_maker() as session:
                row = await session.scalar(
                    select(ScreeningVerificationRecovery).where(
                        ScreeningVerificationRecovery.agent_id == agent_id
                    )
                )
            assert row is not None
            seeds.append(row.challenge_seed_sealed)
            commitments.append(row.challenge_commitment)
            assert (
                hashlib.sha256(row.challenge_seed_sealed.encode()).hexdigest()
                == row.challenge_commitment
            )
            assert row.challenge_seed_sealed not in created.text
            assert row.challenge_seed_sealed not in readiness.text
            assert "challenge_seed" not in created.text
            assert "challenge_seed" not in readiness.text
            assert row.challenge_commitment in created.text
            assert (
                readiness.json()["evidence_bindings"]["challenge_manifest_digest"]
                == row.challenge_commitment
            )

        assert seeds[0] != seeds[1]
        assert commitments[0] != commitments[1]

    @pytest.mark.parametrize(
        ("mutation", "detail"),
        [
            ({"expected_sha256": "11" * 32}, "artifact identity changed"),
            ({"expected_image_digest": "22" * 32}, "screened image changed"),
            ({"expected_score_count": 3}, "score count changed"),
            ({"expected_attempt_count": 9}, "screening attempt count changed"),
            ({"expected_policy_version": 12}, "screening policy changed"),
            ({"expected_manifest_digest": "33" * 32}, "policy manifest changed"),
        ],
    )
    async def test_stale_guards_are_refused(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
        mutation: dict[str, Any],
        detail: str,
    ) -> None:
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(session_maker)
        _install_db(app, session_maker)
        body = _grant_body(attempt_id=attempt_id, quarantine_id=quarantine_id)
        body.update(mutation)

        response = await client.post(
            _recovery_url(agent_id), headers=_ADMIN_HEADERS, json=body
        )

        assert response.status_code == 409, response.text
        assert response.json()["message"] == detail
        async with session_maker() as session:
            recovery = await session.scalar(select(ScreeningVerificationRecovery))
        assert recovery is None
        await _assert_hold_intact(session_maker, agent_id)

    async def test_wrong_attempt_or_quarantine_is_refused(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(session_maker)
        _install_db(app, session_maker)

        wrong_attempt = await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json=_grant_body(attempt_id=uuid4(), quarantine_id=quarantine_id),
        )
        wrong_quarantine = await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json=_grant_body(attempt_id=attempt_id, quarantine_id=uuid4()),
        )

        assert wrong_attempt.status_code == 409
        assert wrong_attempt.json()["message"] == "screening attempt changed"
        assert wrong_quarantine.status_code == 409
        assert wrong_quarantine.json()["message"] == "screening quarantine changed"

    async def test_confirmation_phrase_is_mandatory(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(session_maker)
        _install_db(app, session_maker)
        body = _grant_body(attempt_id=attempt_id, quarantine_id=quarantine_id)
        body["confirmation"] = "yes please"

        response = await client.post(
            _recovery_url(agent_id), headers=_ADMIN_HEADERS, json=body
        )

        assert response.status_code == 422

    async def test_finding_backed_hold_is_refused(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        """A hold with an established finding belongs to the decision path.

        The recovery grant exists for verification gaps only; it must not become
        a way to re-litigate a proven finding."""
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(
            session_maker,
            reason_code="suspicious-source",
            finding_digest="7c" * 32,
        )
        _install_db(app, session_maker)

        response = await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json=_grant_body(attempt_id=attempt_id, quarantine_id=quarantine_id),
        )
        readiness = await client.get(_readiness_url(agent_id), headers=_ADMIN_HEADERS)

        assert response.status_code == 409, response.text
        assert (
            response.json()["message"] == "hold is not a non-decisive verification gap"
        )
        assert readiness.json()["has_established_finding"] is True
        assert readiness.json()["is_non_decisive_hold"] is False

    async def test_duplicate_replay_is_idempotent_then_refused(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        """One grant per exact attempt; a changed guard set is a conflict.

        A duplicate authorization must not create a second paid replay, which is
        the duplicate-work rule in the published retry procedure."""
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(session_maker)
        _install_db(app, session_maker)
        body = _grant_body(attempt_id=attempt_id, quarantine_id=quarantine_id)

        first = await client.post(
            _recovery_url(agent_id), headers=_ADMIN_HEADERS, json=body
        )
        replay = await client.post(
            _recovery_url(agent_id), headers=_ADMIN_HEADERS, json=body
        )
        moved = await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json={**body, "expected_manifest_digest": "44" * 32},
        )

        assert first.status_code == 200, first.text
        assert replay.status_code == 200, replay.text
        assert replay.json()["idempotent"] is True
        assert (
            replay.json()["recovery"]["recovery_id"]
            == first.json()["recovery"]["recovery_id"]
        )
        assert (
            replay.json()["recovery"]["challenge_commitment"]
            == (first.json()["recovery"]["challenge_commitment"])
        )
        assert moved.status_code == 409
        async with session_maker() as session:
            rows = list(
                (await session.scalars(select(ScreeningVerificationRecovery))).all()
            )
        assert len(rows) == 1

    async def test_a_grant_for_a_different_attempt_is_refused(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(session_maker)
        later_attempt_id = uuid4()
        now = datetime.now(UTC)
        async with session_maker() as session, session.begin():
            session.add(
                ScreeningAttempt(
                    attempt_id=later_attempt_id,
                    agent_id=agent_id,
                    screener_hotkey=_FLEET_HOTKEY,
                    policy_version=SCREENING_POLICY_VERSION,
                    status="failed",
                    started_at=now - timedelta(minutes=5),
                    deadline=now,
                    finished_at=now,
                    reason_code="adjudicated-source-review-escalate",
                )
            )
        _install_db(app, session_maker)

        first = await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json=_grant_body(
                attempt_id=attempt_id, quarantine_id=quarantine_id, attempt_count=2
            ),
        )
        second = await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json=_grant_body(
                attempt_id=later_attempt_id,
                quarantine_id=quarantine_id,
                attempt_count=2,
            ),
        )

        assert first.status_code == 200, first.text
        # The second call names an attempt the active quarantine does not hold,
        # so it is refused on the attempt guard before the open-grant guard.
        assert second.status_code == 409
        assert second.json()["message"] == "screening attempt changed"


class TestVerificationRecoveryDispatch:
    async def test_independent_worker_is_required_for_the_replay(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        """The worker that already failed this artifact cannot claim the replay.

        The published retry procedure requires at least one independent worker
        for a platform or provider verification failure."""
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(session_maker)
        await _seed_independent_worker(session_maker)
        _install_db(app, session_maker)
        granted = await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json=_grant_body(attempt_id=attempt_id, quarantine_id=quarantine_id),
        )
        assert granted.status_code == 200, granted.text

        same_worker = await client.post(
            "/api/v1/screener/verification-recovery/claim", headers=_FLEET_HEADERS
        )
        independent = await client.post(
            "/api/v1/screener/verification-recovery/claim", headers=_SECOND_HEADERS
        )

        assert same_worker.status_code == 200, same_worker.text
        assert same_worker.json() is None
        assert independent.status_code == 200, independent.text
        claim = independent.json()
        assert claim["claimed_by"] == _SECOND_HOTKEY
        assert claim["artifact_sha256"] == _SHA256
        assert claim["outstanding_checks"] == [
            check.check_id for check in MANDATORY_VERIFICATION_CHECKS
        ]
        assert len(claim["challenge_seed"]) == 64
        assert (
            hashlib.sha256(claim["challenge_seed"].encode()).hexdigest()
            == claim["challenge_commitment"]
        )
        await _assert_hold_intact(session_maker, agent_id)

    async def test_a_claimed_grant_cannot_be_claimed_again(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(
            session_maker, extra_attempt_hotkeys=()
        )
        await _seed_independent_worker(session_maker)
        _install_db(app, session_maker)
        await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json=_grant_body(attempt_id=attempt_id, quarantine_id=quarantine_id),
        )

        first = await client.post(
            "/api/v1/screener/verification-recovery/claim", headers=_SECOND_HEADERS
        )
        second = await client.post(
            "/api/v1/screener/verification-recovery/claim", headers=_SECOND_HEADERS
        )

        assert first.json() is not None
        assert second.json() is None

    async def test_a_changed_artifact_cancels_the_grant_instead_of_dispatching(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(session_maker)
        await _seed_independent_worker(session_maker)
        _install_db(app, session_maker)
        await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json=_grant_body(attempt_id=attempt_id, quarantine_id=quarantine_id),
        )
        async with session_maker() as session, session.begin():
            agent = await session.get(Agent, agent_id)
            assert agent is not None
            agent.sha256 = "55" * 32

        claim = await client.post(
            "/api/v1/screener/verification-recovery/claim", headers=_SECOND_HEADERS
        )

        assert claim.status_code == 200, claim.text
        assert claim.json() is None
        async with session_maker() as session:
            row = await session.scalar(select(ScreeningVerificationRecovery))
        assert row is not None
        assert row.state == "canceled"
        assert row.claimed_by is None

    async def test_no_grant_means_nothing_is_dispatched(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        """A hold alone never produces verification work.

        There is no automatic trigger: without an operator grant the claim
        endpoint has nothing to hand out."""
        _configure(app)
        await _seed_hold(session_maker)
        await _seed_independent_worker(session_maker)
        _install_db(app, session_maker)

        claim = await client.post(
            "/api/v1/screener/verification-recovery/claim", headers=_SECOND_HEADERS
        )

        assert claim.status_code == 200, claim.text
        assert claim.json() is None


class TestVerificationRecoveryResult:
    async def _dispatch(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> tuple[UUID, dict[str, Any]]:
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(session_maker)
        await _seed_independent_worker(session_maker)
        _install_db(app, session_maker)
        granted = await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json=_grant_body(attempt_id=attempt_id, quarantine_id=quarantine_id),
        )
        assert granted.status_code == 200, granted.text
        claimed = await client.post(
            "/api/v1/screener/verification-recovery/claim", headers=_SECOND_HEADERS
        )
        assert claimed.status_code == 200, claimed.text
        claim = claimed.json()
        assert claim is not None
        return agent_id, claim

    async def test_complete_verification_never_clears_the_hold(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        agent_id, claim = await self._dispatch(app, client, session_maker)

        response = await client.post(
            f"/api/v1/screener/verification-recovery/{claim['recovery_id']}/result",
            headers=_SECOND_HEADERS,
            json={
                "outcome": "verification_complete",
                "completed_checks": claim["outstanding_checks"],
            },
        )
        readiness = await client.get(_readiness_url(agent_id), headers=_ADMIN_HEADERS)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["decision_recorded"] is False
        assert body["agent_status"] == AgentStatus.QUARANTINED
        assert body["quarantine_status"] == "active"
        assert body["recovery"]["state"] == "completed"
        assert body["recovery"]["failure_domain"] is None
        assert readiness.json()["outstanding_mandatory_checks"] == []
        assert {check["state"] for check in readiness.json()["mandatory_checks"]} == {
            "completed"
        }
        await _assert_hold_intact(session_maker, agent_id)

    async def test_provider_failure_is_recorded_without_a_v3_ruling(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        agent_id, claim = await self._dispatch(app, client, session_maker)

        response = await client.post(
            f"/api/v1/screener/verification-recovery/{claim['recovery_id']}/result",
            headers=_SECOND_HEADERS,
            json={
                "outcome": "verification_incomplete",
                "completed_checks": ["archive_and_sha"],
                "failure_domain": "provider",
                "detail_code": "provider-completion-timeout",
            },
        )
        readiness = await client.get(_readiness_url(agent_id), headers=_ADMIN_HEADERS)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["recovery"]["state"] == "failed"
        assert body["recovery"]["failure_domain"] == "provider"
        assert body["decision_recorded"] is False
        checks = {
            check["check_id"]: check["state"]
            for check in readiness.json()["mandatory_checks"]
        }
        assert checks["archive_and_sha"] == "completed"
        assert checks["health"] == "outstanding"
        assert "V3" not in response.text
        await _assert_hold_intact(session_maker, agent_id)

    async def test_a_refuted_static_lead_is_evidence_not_a_clearance(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        """Refuting an I5 lead does not clear the artifact.

        The replay refutes the lead and still leaves the remaining mandatory
        checks outstanding, so the hold stands."""
        agent_id, claim = await self._dispatch(app, client, session_maker)

        response = await client.post(
            f"/api/v1/screener/verification-recovery/{claim['recovery_id']}/result",
            headers=_SECOND_HEADERS,
            json={
                "outcome": "verification_incomplete",
                "completed_checks": ["archive_and_sha", "build_and_image_digest"],
                "failure_domain": "platform",
                "refuted_leads": ["I5"],
            },
        )
        readiness = await client.get(_readiness_url(agent_id), headers=_ADMIN_HEADERS)

        assert response.status_code == 200, response.text
        assert response.json()["recovery"]["refuted_leads"] == ["I5"]
        body = readiness.json()
        states = {rule["rule_id"]: rule["state"] for rule in body["integrity_rules"]}
        assert states["I5"] == "refuted"
        assert states["I1"] == NOT_RECORDED
        assert body["outstanding_mandatory_checks"]
        assert body["agent_status"] == AgentStatus.QUARANTINED
        await _assert_hold_intact(session_maker, agent_id)

    async def test_partial_completion_cannot_be_reported_as_complete(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        agent_id, claim = await self._dispatch(app, client, session_maker)

        response = await client.post(
            f"/api/v1/screener/verification-recovery/{claim['recovery_id']}/result",
            headers=_SECOND_HEADERS,
            json={
                "outcome": "verification_complete",
                "completed_checks": ["archive_and_sha"],
            },
        )

        assert response.status_code == 409, response.text
        assert (
            response.json()["message"]
            == "reported completion does not cover the authorized checks"
        )
        await _assert_hold_intact(session_maker, agent_id)

    async def test_another_worker_cannot_report_the_replay(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _agent_id, claim = await self._dispatch(app, client, session_maker)

        response = await client.post(
            f"/api/v1/screener/verification-recovery/{claim['recovery_id']}/result",
            headers=_FLEET_HEADERS,
            json={"outcome": "verification_complete", "completed_checks": []},
        )

        assert response.status_code == 403, response.text

    async def test_a_reported_grant_cannot_be_reported_twice(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _agent_id, claim = await self._dispatch(app, client, session_maker)
        url = f"/api/v1/screener/verification-recovery/{claim['recovery_id']}/result"
        payload = {
            "outcome": "verification_complete",
            "completed_checks": claim["outstanding_checks"],
        }

        first = await client.post(url, headers=_SECOND_HEADERS, json=payload)
        second = await client.post(url, headers=_SECOND_HEADERS, json=payload)

        assert first.status_code == 200, first.text
        assert second.status_code == 409
        assert second.json()["message"] == "verification recovery is not dispatched"

    async def test_unknown_check_and_rule_ids_are_rejected(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _agent_id, claim = await self._dispatch(app, client, session_maker)
        url = f"/api/v1/screener/verification-recovery/{claim['recovery_id']}/result"

        bad_check = await client.post(
            url,
            headers=_SECOND_HEADERS,
            json={
                "outcome": "verification_incomplete",
                "completed_checks": ["definitely_not_a_check"],
                "failure_domain": "platform",
            },
        )
        bad_rule = await client.post(
            url,
            headers=_SECOND_HEADERS,
            json={
                "outcome": "verification_incomplete",
                "completed_checks": [],
                "failure_domain": "platform",
                "refuted_leads": ["I9"],
            },
        )
        missing_domain = await client.post(
            url,
            headers=_SECOND_HEADERS,
            json={"outcome": "verification_incomplete", "completed_checks": []},
        )

        assert bad_check.status_code == 422
        assert bad_rule.status_code == 422
        assert missing_domain.status_code == 422

    async def test_an_expired_lease_parks_the_grant_as_a_platform_failure(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        """A lapsed lease is an incomplete replay, never a ruling or a free retry."""
        agent_id, claim = await self._dispatch(app, client, session_maker)
        async with session_maker() as session, session.begin():
            row = await session.get(
                ScreeningVerificationRecovery, UUID(claim["recovery_id"])
            )
            assert row is not None
            row.dispatch_deadline = datetime.now(UTC) - timedelta(minutes=1)

        response = await client.post(
            f"/api/v1/screener/verification-recovery/{claim['recovery_id']}/result",
            headers=_SECOND_HEADERS,
            json={
                "outcome": "verification_complete",
                "completed_checks": claim["outstanding_checks"],
            },
        )

        assert response.status_code == 409, response.text
        assert response.json()["message"] == "verification recovery lease expired"
        async with session_maker() as session:
            row = await session.get(
                ScreeningVerificationRecovery, UUID(claim["recovery_id"])
            )
        assert row is not None
        assert row.state == "failed"
        assert row.outcome == "verification_incomplete"
        assert row.failure_domain == "platform"
        await _assert_hold_intact(session_maker, agent_id)


_CLAIM_URL = "/api/v1/screener/verification-recovery/claim"

_IDENTITY_CHANGES = {
    # identity changed after authorization -> the reason the guard must report
    "artifact_sha": "artifact_sha_changed",
    "quarantine_resolved": "quarantine_resolved",
    "quarantine_replaced": "quarantine_replaced",
    "image_digest": "screened_image_changed",
    "image_cleared": "screened_image_changed",
    "policy_version": "policy_version_changed",
    "manifest_digest": "policy_manifest_changed",
}


async def _change_identity(
    maker: async_sessionmaker[AsyncSession],
    *,
    agent_id: UUID,
    quarantine_id: UUID,
    identity: str,
) -> None:
    """Move exactly one guarded identity, as production would between calls."""
    now = datetime.now(UTC)
    async with maker() as session, session.begin():
        agent = await session.get(Agent, agent_id)
        quarantine = await session.get(ScreeningQuarantine, quarantine_id)
        assert agent is not None
        assert quarantine is not None
        if identity == "artifact_sha":
            agent.sha256 = "55" * 32
        elif identity == "image_digest":
            agent.screened_image_sha256 = "77" * 32
        elif identity == "image_cleared":
            # The explicit-null case: the grant pinned an image and none is
            # pinned now. None must not compare equal to the granted digest.
            agent.screened_image_sha256 = None
            agent.screened_image_size_bytes = None
            agent.screened_image_id = None
            agent.screened_image_ref = None
            agent.screened_image_upload_id = None
            agent.screened_image_verified_at = None
        elif identity == "policy_version":
            quarantine.policy_version = SCREENING_POLICY_VERSION + 1
        elif identity == "manifest_digest":
            quarantine.manifest_digest = "88" * 32
        elif identity in {"quarantine_resolved", "quarantine_replaced"}:
            quarantine.status = "resolved"
            quarantine.resolved_at = now
            quarantine.resolved_by = "backroom:test-operator"
            quarantine.resolution = "release"
            quarantine.resolution_reason = "operator resolved the hold"
            if identity == "quarantine_replaced":
                await session.flush()
                replacement_attempt = uuid4()
                session.add(
                    ScreeningAttempt(
                        attempt_id=replacement_attempt,
                        agent_id=agent_id,
                        screener_hotkey=_FLEET_HOTKEY,
                        policy_version=SCREENING_POLICY_VERSION,
                        status="quarantined",
                        started_at=now - timedelta(minutes=2),
                        deadline=now + timedelta(minutes=8),
                        finished_at=now,
                        reason_code="adjudicated-source-review-escalate",
                    )
                )
                await session.flush()
                session.add(
                    ScreeningQuarantine(
                        quarantine_id=uuid4(),
                        agent_id=agent_id,
                        attempt_id=replacement_attempt,
                        screener_hotkey=_FLEET_HOTKEY,
                        policy_version=SCREENING_POLICY_VERSION,
                        manifest_digest=_MANIFEST_DIGEST,
                        reason_code="adjudicated-source-review-escalate",
                        status="active",
                        created_at=now,
                    )
                )
        else:  # pragma: no cover - test table guard
            raise AssertionError(identity)


async def _grant_and_audit(
    maker: async_sessionmaker[AsyncSession], agent_id: UUID
) -> tuple[ScreeningVerificationRecovery, list[ScreeningVerificationEvent]]:
    async with maker() as session:
        row = await session.scalar(
            select(ScreeningVerificationRecovery).where(
                ScreeningVerificationRecovery.agent_id == agent_id
            )
        )
        assert row is not None
        events = list(
            (
                await session.scalars(
                    select(ScreeningVerificationEvent)
                    .where(ScreeningVerificationEvent.recovery_id == row.recovery_id)
                    .order_by(
                        ScreeningVerificationEvent.created_at.asc(),
                        ScreeningVerificationEvent.event_id.asc(),
                    )
                )
            ).all()
        )
    return row, events


class TestVerificationRecoveryIdentityGuards:
    """Every authorized identity is re-verified under lock at claim and report.

    Peyton's review on #2122: a grant must not dispatch, or release its hidden
    challenge, after the hold is resolved or replaced or the screened image,
    policy version, or manifest moves; and a report about moved identities must
    never be applied.
    """

    async def _authorize(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> tuple[UUID, UUID]:
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(session_maker)
        await _seed_independent_worker(session_maker)
        _install_db(app, session_maker)
        granted = await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json=_grant_body(attempt_id=attempt_id, quarantine_id=quarantine_id),
        )
        assert granted.status_code == 200, granted.text
        return agent_id, quarantine_id

    @pytest.mark.parametrize(("identity", "reason"), list(_IDENTITY_CHANGES.items()))
    async def test_identity_moved_before_claim_is_never_dispatched(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
        identity: str,
        reason: str,
    ) -> None:
        agent_id, quarantine_id = await self._authorize(app, client, session_maker)
        await _change_identity(
            session_maker,
            agent_id=agent_id,
            quarantine_id=quarantine_id,
            identity=identity,
        )

        claim = await client.post(_CLAIM_URL, headers=_SECOND_HEADERS)
        again = await client.post(_CLAIM_URL, headers=_SECOND_HEADERS)
        readiness = await client.get(_readiness_url(agent_id), headers=_ADMIN_HEADERS)

        assert claim.status_code == 200, claim.text
        assert claim.json() is None
        assert again.json() is None
        row, events = await _grant_and_audit(session_maker, agent_id)
        assert row.state == "canceled"
        assert row.claimed_by is None
        assert row.claimed_at is None
        assert row.dispatch_deadline is None
        assert row.outcome is None
        assert [event.event for event in events] == [
            "authorized",
            "canceled_stale_identity",
        ]
        assert events[-1].detail is not None
        assert events[-1].detail["stage"] == "claim"
        assert events[-1].detail["reason"] == reason
        # No response and no audit row ever carried the hidden randomness.
        assert row.challenge_seed_sealed not in claim.text
        assert row.challenge_seed_sealed not in readiness.text
        assert "challenge_seed" not in readiness.text
        for event in events:
            assert row.challenge_seed_sealed not in str(event.detail)

    @pytest.mark.parametrize(("identity", "reason"), list(_IDENTITY_CHANGES.items()))
    async def test_identity_moved_before_report_is_rejected_as_stale(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
        identity: str,
        reason: str,
    ) -> None:
        agent_id, quarantine_id = await self._authorize(app, client, session_maker)
        claimed = await client.post(_CLAIM_URL, headers=_SECOND_HEADERS)
        assert claimed.status_code == 200, claimed.text
        claim = claimed.json()
        assert claim is not None
        await _change_identity(
            session_maker,
            agent_id=agent_id,
            quarantine_id=quarantine_id,
            identity=identity,
        )

        report = await client.post(
            f"/api/v1/screener/verification-recovery/{claim['recovery_id']}/result",
            headers=_SECOND_HEADERS,
            json={
                "outcome": "verification_complete",
                "completed_checks": claim["outstanding_checks"],
                "refuted_leads": ["I5"],
            },
        )
        readiness = await client.get(_readiness_url(agent_id), headers=_ADMIN_HEADERS)

        assert report.status_code == 409, report.text
        assert report.json()["message"] == (
            f"verification recovery identity changed: {reason}"
        )
        row, events = await _grant_and_audit(session_maker, agent_id)
        # Recorded as rejected evidence, never applied.
        assert row.state == "canceled"
        assert row.outcome is None
        assert row.failure_domain is None
        assert row.completed_checks is None
        assert row.refuted_leads is None
        assert [event.event for event in events] == [
            "authorized",
            "dispatched",
            "report_rejected_stale",
        ]
        detail = events[-1].detail
        assert detail is not None
        assert detail["stage"] == "report"
        assert detail["reason"] == reason
        assert detail["rejected_report"]["outcome"] == "verification_complete"
        assert detail["rejected_report"]["refuted_leads"] == ["I5"]
        body = readiness.json()
        assert "completed" not in {check["state"] for check in body["mandatory_checks"]}
        assert {rule["state"] for rule in body["integrity_rules"]} == {NOT_RECORDED}
        assert body["agent_status"] == AgentStatus.QUARANTINED
        assert claim["challenge_seed"] not in readiness.text
        assert claim["challenge_seed"] not in str(detail)

    async def test_unchanged_identities_still_dispatch_and_accept(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        agent_id, _quarantine_id = await self._authorize(app, client, session_maker)

        claimed = await client.post(_CLAIM_URL, headers=_SECOND_HEADERS)
        claim = claimed.json()
        assert claim is not None
        report = await client.post(
            f"/api/v1/screener/verification-recovery/{claim['recovery_id']}/result",
            headers=_SECOND_HEADERS,
            json={
                "outcome": "verification_complete",
                "completed_checks": claim["outstanding_checks"],
            },
        )

        assert report.status_code == 200, report.text
        assert report.json()["recovery"]["state"] == "completed"
        assert report.json()["decision_recorded"] is False
        row, events = await _grant_and_audit(session_maker, agent_id)
        assert row.state == "completed"
        assert [event.event for event in events] == [
            "authorized",
            "dispatched",
            "reported",
        ]
        await _assert_hold_intact(session_maker, agent_id)

    async def test_a_pinned_attempt_for_other_bytes_cannot_be_granted(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        """The attempt's immutable pinned SHA (#2149) outranks the agent row."""
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(
            session_maker, attempt_artifact_sha256="66" * 32
        )
        _install_db(app, session_maker)

        response = await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json=_grant_body(attempt_id=attempt_id, quarantine_id=quarantine_id),
        )

        assert response.status_code == 409, response.text
        assert response.json()["message"] == "screening attempt artifact changed"
        async with session_maker() as session:
            assert await session.scalar(select(ScreeningVerificationRecovery)) is None

    async def test_a_matching_pinned_attempt_dispatches(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> None:
        _configure(app)
        agent_id, attempt_id, quarantine_id = await _seed_hold(
            session_maker, attempt_artifact_sha256=_SHA256
        )
        await _seed_independent_worker(session_maker)
        _install_db(app, session_maker)

        granted = await client.post(
            _recovery_url(agent_id),
            headers=_ADMIN_HEADERS,
            json=_grant_body(attempt_id=attempt_id, quarantine_id=quarantine_id),
        )
        claimed = await client.post(_CLAIM_URL, headers=_SECOND_HEADERS)

        assert granted.status_code == 200, granted.text
        assert granted.json()["audit"][0]["detail"]["attempt_artifact_pinned"] is True
        assert claimed.json() is not None
        assert claimed.json()["artifact_sha256"] == _SHA256
