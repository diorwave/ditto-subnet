"""Subnet liveness signals (ditto-subnet#2600): ok and breach per signal.

Every case seeds real Postgres rows and runs the production read, including
its ``READ ONLY`` transaction. Only ``active_bench_version`` is pinned for the
scorer-pin cases, because activating v13 for real needs a full rollout history
that is irrelevant to the signal under test.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ditto.api_models.subnet_liveness import SubnetLiveness, SubnetLivenessSignal
from ditto.api_models.ticket_status import TicketStatus
from ditto.api_server import subnet_liveness
from ditto.api_server.subnet_liveness import load_subnet_liveness
from ditto.db.models import (
    Agent,
    AgentStatus,
    AthReview,
    ScoreAuditEntry,
    ScreenerHeartbeat,
    ScreenerNode,
    ScreenerNodeChannelSettingsRevision,
    ScreeningAttempt,
    ScreeningQuarantine,
    SourceEmissionCollectorCursor,
    V13ScorerCohortPin,
    ValidatorHeartbeat,
    ValidatorTicket,
)
from ditto.tests.db.queries.test_benchmark_rollout import _heartbeat
from ditto_screening_protocol import SCREENING_FLOOR_POLICY_VERSION

# The version required with no policy activation on record.
SCREENING_POLICY_VERSION = SCREENING_FLOOR_POLICY_VERSION

pytestmark = pytest.mark.asyncio

_NETUID = 118
_MINER = "5" + "F" * 47
_NODE_HOTKEY = "5NodeHotkeyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
_VALIDATOR = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
_PIN_HOTKEYS = tuple(
    sorted(
        (
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
            "5DhaT8U7LVwnnJNUU8VL1XEipicatoaDVVq7cHo227gogVZm",
        )
    )
)


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


async def _read(
    session_maker: async_sessionmaker[AsyncSession], now: datetime
) -> SubnetLiveness:
    async with session_maker() as session:
        return await load_subnet_liveness(
            session, environment="prod", netuid=_NETUID, now=now
        )


def _signal(liveness: SubnetLiveness, name: str) -> SubnetLivenessSignal:
    return next(signal for signal in liveness.signals if signal.name == name)


async def _agent(
    session_maker: async_sessionmaker[AsyncSession],
    *,
    status: AgentStatus,
    created_at: datetime,
) -> UUID:
    agent_id = uuid4()
    async with session_maker() as session, session.begin():
        session.add(
            Agent(
                agent_id=agent_id,
                miner_hotkey=_MINER,
                name=f"agent-{agent_id.hex[:8]}",
                sha256=hashlib.sha256(agent_id.bytes).hexdigest(),
                status=status,
                created_at=created_at,
            )
        )
    return agent_id


async def _node(
    session_maker: async_sessionmaker[AsyncSession],
    *,
    now: datetime,
    concurrency: int,
    revision_at: datetime,
    heartbeat_at: datetime | None,
) -> None:
    async with session_maker() as session, session.begin():
        session.add(
            ScreenerNode(
                environment="prod",
                node_id="subnet-screener-1",
                provider="hetzner",
                provider_resource_id="test-resource-1",
                screener_hotkey=_NODE_HOTKEY,
                token_hash=hashlib.sha256(b"node-token").hexdigest(),
                token_expires_at=now + timedelta(hours=1),
                status="active",
                capacity=4,
                registered_at=revision_at - timedelta(days=1),
            )
        )
    async with session_maker() as session, session.begin():
        session.add(
            ScreenerNodeChannelSettingsRevision(
                environment="prod",
                node_id="subnet-screener-1",
                parent_revision=0,
                settings={"screening_concurrency": concurrency},
                reason="liveness test admission",
                actor="test",
                created_at=revision_at,
            )
        )
        if heartbeat_at is not None:
            session.add(
                ScreenerHeartbeat(
                    screener_hotkey=_NODE_HOTKEY,
                    instance_id="subnet-screener-1",
                    software_version="0.21.0",
                    protocol_version=4,
                    policy_version=SCREENING_POLICY_VERSION,
                    state="polling",
                    first_seen_at=heartbeat_at - timedelta(days=1),
                    reported_at=heartbeat_at,
                    seen_at=heartbeat_at,
                    signature="ab" * 64,
                )
            )


class TestScreeningAdmission:
    async def test_open_admission_is_ok_while_uploads_wait(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        await _node(
            session_maker,
            now=now,
            concurrency=2,
            revision_at=now - timedelta(hours=3),
            heartbeat_at=now - timedelta(seconds=10),
        )
        await _agent(
            session_maker,
            status=AgentStatus.UPLOADED,
            created_at=now - timedelta(minutes=10),
        )

        liveness = await _read(session_maker, now)
        admission = _signal(liveness, "screening_admission")
        assert admission.status == "ok"
        assert admission.value == 0
        assert admission.since is None
        assert admission.detail["effective_slots"] == 2
        assert admission.detail["ready_nodes"] == 1
        assert admission.detail["claimable_uploads"] == 1

    async def test_leftover_zero_revision_breaches_while_uploads_wait(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        """The #2474 shape: a ready node held at concurrency 0 for hours."""
        now = _now()
        await _node(
            session_maker,
            now=now,
            concurrency=0,
            revision_at=now - timedelta(hours=2),
            heartbeat_at=now - timedelta(seconds=10),
        )
        oldest = now - timedelta(hours=1)
        await _agent(session_maker, status=AgentStatus.UPLOADED, created_at=oldest)

        liveness = await _read(session_maker, now)
        admission = _signal(liveness, "screening_admission")
        assert admission.status == "breach"
        assert admission.detail["effective_slots"] == 0
        assert admission.detail["ready_nodes"] == 1
        assert admission.detail["open_nodes"] == 0
        assert admission.detail["zero_since"] == (now - timedelta(hours=2)).isoformat()
        # Admission was already 0 when the upload arrived: the clock starts at
        # the upload, the later of the two.
        assert admission.since == oldest
        assert admission.value == pytest.approx(3600)
        assert liveness.status == "breach"

    async def test_closed_admission_with_nothing_waiting_is_ok(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        await _node(
            session_maker,
            now=now,
            concurrency=0,
            revision_at=now - timedelta(hours=2),
            heartbeat_at=now - timedelta(seconds=10),
        )

        admission = _signal(await _read(session_maker, now), "screening_admission")
        assert admission.status == "ok"
        assert admission.value == 0
        assert admission.detail["effective_slots"] == 0

    async def test_stale_heartbeat_closes_admission_from_its_ready_window(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        await _node(
            session_maker,
            now=now,
            concurrency=2,
            revision_at=now - timedelta(days=2),
            heartbeat_at=now - timedelta(hours=5),
        )
        await _agent(
            session_maker,
            status=AgentStatus.UPLOADED,
            created_at=now - timedelta(hours=6),
        )

        admission = _signal(await _read(session_maker, now), "screening_admission")
        assert admission.status == "breach"
        assert admission.detail["ready_nodes"] == 0
        assert admission.since == now - timedelta(hours=5) + timedelta(seconds=180)


class TestOldestClaimableUpload:
    async def test_fresh_upload_is_ok(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        await _agent(
            session_maker,
            status=AgentStatus.UPLOADED,
            created_at=now - timedelta(minutes=5),
        )

        signal = _signal(await _read(session_maker, now), "oldest_claimable_upload")
        assert signal.status == "ok"
        assert signal.value == pytest.approx(300)
        assert signal.detail["claimable_uploads"] == 1

    async def test_old_unclaimed_upload_breaches(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        oldest = now - timedelta(hours=5)
        await _agent(session_maker, status=AgentStatus.UPLOADED, created_at=oldest)
        await _agent(
            session_maker,
            status=AgentStatus.UPLOADED,
            created_at=now - timedelta(minutes=1),
        )

        signal = _signal(await _read(session_maker, now), "oldest_claimable_upload")
        assert signal.status == "breach"
        assert signal.since == oldest
        assert signal.detail["claimable_uploads"] == 2

    async def test_upload_with_a_running_attempt_is_not_claimable(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        agent_id = await _agent(
            session_maker,
            status=AgentStatus.UPLOADED,
            created_at=now - timedelta(hours=5),
        )
        async with session_maker() as session, session.begin():
            session.add(
                ScreeningAttempt(
                    attempt_id=uuid4(),
                    agent_id=agent_id,
                    screener_hotkey=_NODE_HOTKEY,
                    policy_version=SCREENING_POLICY_VERSION,
                    status="running",
                    started_at=now - timedelta(minutes=5),
                    deadline=now + timedelta(minutes=5),
                )
            )

        signal = _signal(await _read(session_maker, now), "oldest_claimable_upload")
        assert signal.status == "ok"
        assert signal.detail["claimable_uploads"] == 0


async def _score_event(
    session_maker: async_sessionmaker[AsyncSession],
    *,
    agent_id: UUID,
    recorded_at: datetime,
    event: str = "score",
) -> None:
    async with session_maker() as session, session.begin():
        session.add(
            ScoreAuditEntry(
                agent_id=agent_id,
                validator_hotkey=_VALIDATOR if event == "score" else None,
                event=event,
                payload={},
                prev_hash="0" * 64,
                entry_hash=uuid4().hex * 2,
                recorded_at=recorded_at,
            )
        )


class TestScoringThroughput:
    async def test_recent_score_while_queued_is_ok(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        agent_id = await _agent(
            session_maker,
            status=AgentStatus.EVALUATING,
            created_at=now - timedelta(days=1),
        )
        await _score_event(
            session_maker, agent_id=agent_id, recorded_at=now - timedelta(minutes=20)
        )

        signal = _signal(await _read(session_maker, now), "scoring_throughput")
        assert signal.status == "ok"
        assert signal.detail["scores_last_hour"] == 1
        assert signal.detail["evaluating_agents"] == 1
        assert signal.value == pytest.approx(1200)

    async def test_no_score_for_hours_while_queued_breaches(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        """The #2490 shape: work queued, nothing accepted for hours."""
        now = _now()
        agent_id = await _agent(
            session_maker,
            status=AgentStatus.EVALUATING,
            created_at=now - timedelta(days=2),
        )
        last = now - timedelta(hours=5)
        await _score_event(session_maker, agent_id=agent_id, recorded_at=last)
        # A newer finalization event is not an accepted validator score.
        await _score_event(
            session_maker,
            agent_id=agent_id,
            recorded_at=now - timedelta(minutes=1),
            event="agent_finalized",
        )

        signal = _signal(await _read(session_maker, now), "scoring_throughput")
        assert signal.status == "breach"
        assert signal.since == last
        assert signal.detail["scores_last_hour"] == 0
        assert signal.detail["last_accepted_score_at"] == last.isoformat()

    async def test_silence_with_nothing_queued_is_ok(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        agent_id = await _agent(
            session_maker,
            status=AgentStatus.SCORED,
            created_at=now - timedelta(days=2),
        )
        await _score_event(
            session_maker, agent_id=agent_id, recorded_at=now - timedelta(days=1)
        )

        signal = _signal(await _read(session_maker, now), "scoring_throughput")
        assert signal.status == "ok"
        assert signal.value == 0

    async def test_queue_clock_starts_when_the_agent_entered_scoring(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        """An old upload that only just passed screening is not a stall."""
        now = _now()
        agent_id = await _agent(
            session_maker,
            status=AgentStatus.EVALUATING,
            created_at=now - timedelta(days=3),
        )
        async with session_maker() as session, session.begin():
            session.add(
                ScreeningAttempt(
                    attempt_id=uuid4(),
                    agent_id=agent_id,
                    screener_hotkey=_NODE_HOTKEY,
                    policy_version=SCREENING_POLICY_VERSION,
                    status="passed",
                    started_at=now - timedelta(minutes=40),
                    finished_at=now - timedelta(minutes=10),
                    deadline=now + timedelta(minutes=30),
                )
            )

        signal = _signal(await _read(session_maker, now), "scoring_throughput")
        assert signal.status == "ok"
        assert signal.since == now - timedelta(minutes=10)


def _packet(source: str) -> dict[str, Any]:
    keys = ["DITTOBENCH_DB"]
    digest = hashlib.sha256(
        ("scored-runtime-env-v1\n13\n" + source + "\n" + "\n".join(keys)).encode()
    ).hexdigest()
    return {
        "source_revision": source,
        "release_descriptor_digest": "sha256:" + "b" * 64,
        "scorer_image_digest": "sha256:" + "c" * 64,
        "scorer_env_sha256": digest,
        "injected_keys": keys,
    }


def _managed(hotkey: str, now: datetime, packet: dict[str, Any]) -> ValidatorHeartbeat:
    row = _heartbeat(hotkey, now, versions=[7, 13], protocol_version=18)
    row.benchmark_capacity = {
        "configured_slots": 1,
        "healthy_slots": ["slot-0"],
        "admission": "accepting",
        "active": [],
    }
    assert row.stack is not None and row.capabilities is not None
    row.stack["mode"] = "managed"
    row.stack["release_descriptor_digest"] = packet["release_descriptor_digest"]
    for component in row.stack["components"].values():
        component["provenance"] = "signed_descriptor"
        component["image_digest"] = packet["scorer_image_digest"]
        component["source_revision"] = packet["source_revision"]
    row.capabilities["scorer_benchmarks"]["source_revision"] = packet["source_revision"]
    row.capabilities["scorer_benchmarks"]["scored_runtime_env"] = {
        "bench_version": 13,
        "scope": "scorer-injected-env-only",
        "source_revision": packet["source_revision"],
        "injected_keys": packet["injected_keys"],
        "sha256": packet["scorer_env_sha256"],
    }
    return row


class TestV13ScorerCohortPin:
    @pytest.fixture(autouse=True)
    def _v13_active(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _active(*_args: object, **_kwargs: object) -> int:
            return 13

        monkeypatch.setattr(subnet_liveness, "active_bench_version", _active)

    async def _seed(
        self,
        session_maker: async_sessionmaker[AsyncSession],
        *,
        now: datetime,
        live_packets: list[dict[str, Any]],
    ) -> None:
        pinned = _packet("a" * 40)
        async with session_maker() as session, session.begin():
            session.add_all(
                [
                    _managed(hotkey, now, packet)
                    for hotkey, packet in zip(_PIN_HOTKEYS, live_packets, strict=True)
                ]
            )
            session.add(
                V13ScorerCohortPin(
                    bench_version=13,
                    hotkeys=list(_PIN_HOTKEYS),
                    packet=pinned,
                    slot_settings_revision=1,
                    slot_settings_checksum="0" * 64,
                    reason="liveness test pin",
                    actor="test",
                )
            )

    async def test_every_member_matching_is_ok(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        await self._seed(session_maker, now=now, live_packets=[_packet("a" * 40)] * 3)

        signal = _signal(await _read(session_maker, now), "v13_scorer_cohort_pin")
        assert signal.status == "ok"
        assert signal.value == 0
        assert signal.detail["matching_members"] == 3

    async def test_stale_pin_breaches(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        """The #2490 shape: members upgraded, the signed pin did not."""
        now = _now()
        await self._seed(session_maker, now=now, live_packets=[_packet("e" * 40)] * 3)

        signal = _signal(await _read(session_maker, now), "v13_scorer_cohort_pin")
        assert signal.status == "breach"
        assert signal.value == 3
        assert signal.detail["matching_members"] == 0

    async def test_one_stale_member_breaches_the_quorum(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        await self._seed(
            session_maker,
            now=now,
            live_packets=[_packet("a" * 40), _packet("a" * 40), _packet("e" * 40)],
        )

        signal = _signal(await _read(session_maker, now), "v13_scorer_cohort_pin")
        assert signal.status == "breach"
        assert signal.value == 1

    async def test_no_pin_is_not_applicable(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        signal = _signal(await _read(session_maker, _now()), "v13_scorer_cohort_pin")
        assert signal.status == "ok"
        assert signal.value is None


async def _quarantine(
    session_maker: async_sessionmaker[AsyncSession],
    *,
    agent_id: UUID,
    created_at: datetime,
) -> None:
    attempt_id = uuid4()
    async with session_maker() as session, session.begin():
        session.add(
            ScreeningAttempt(
                attempt_id=attempt_id,
                agent_id=agent_id,
                screener_hotkey=_NODE_HOTKEY,
                policy_version=SCREENING_POLICY_VERSION,
                status="quarantined",
                started_at=created_at - timedelta(minutes=30),
                finished_at=created_at,
                deadline=created_at + timedelta(hours=1),
            )
        )
    async with session_maker() as session, session.begin():
        session.add(
            ScreeningQuarantine(
                quarantine_id=uuid4(),
                agent_id=agent_id,
                attempt_id=attempt_id,
                screener_hotkey=_NODE_HOTKEY,
                policy_version=SCREENING_POLICY_VERSION,
                manifest_digest="b" * 64,
                reason_code="source-review-inconclusive",
                status="active",
                created_at=created_at,
            )
        )


class TestOldestActionableHold:
    async def test_recent_hold_is_ok(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        agent_id = await _agent(
            session_maker,
            status=AgentStatus.QUARANTINED,
            created_at=now - timedelta(hours=3),
        )
        await _quarantine(
            session_maker, agent_id=agent_id, created_at=now - timedelta(hours=2)
        )

        signal = _signal(await _read(session_maker, now), "oldest_actionable_hold")
        assert signal.status == "ok"
        assert signal.detail["active_quarantines"] == 1
        assert signal.detail["oldest_kind"] == "screening_quarantine"

    async def test_old_ath_hold_breaches(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        agent_id = await _agent(
            session_maker,
            status=AgentStatus.ATH_PENDING_REVIEW,
            created_at=now - timedelta(days=10),
        )
        opened = now - timedelta(days=4)
        async with session_maker() as session, session.begin():
            session.add(
                AthReview(
                    review_id=uuid4(),
                    agent_id=agent_id,
                    status="pending",
                    opened_at=opened,
                    original_policy_version=13,
                    original_evidence={},
                    algorithm_provenance={},
                )
            )

        signal = _signal(await _read(session_maker, now), "oldest_actionable_hold")
        assert signal.status == "breach"
        assert signal.since == opened
        assert signal.detail["oldest_kind"] == "ath_review"
        assert signal.detail["oldest_agent_id"] == str(agent_id)

    async def test_terminal_ghost_quarantine_is_excluded(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        """#2554: an active quarantine behind a banned agent is not actionable."""
        now = _now()
        agent_id = await _agent(
            session_maker,
            status=AgentStatus.BANNED,
            created_at=now - timedelta(days=30),
        )
        await _quarantine(
            session_maker, agent_id=agent_id, created_at=now - timedelta(days=20)
        )

        signal = _signal(await _read(session_maker, now), "oldest_actionable_hold")
        assert signal.status == "ok"
        assert signal.value == 0
        assert signal.detail["active_quarantines"] == 0


class TestLeaseOverrun:
    async def test_live_lease_is_ok(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        agent_id = await _agent(
            session_maker,
            status=AgentStatus.EVALUATING,
            created_at=now - timedelta(hours=1),
        )
        async with session_maker() as session, session.begin():
            session.add(
                ValidatorTicket(
                    agent_id=agent_id,
                    bench_version=13,
                    validator_hotkey=_VALIDATOR,
                    slot_id="slot-0",
                    status=TicketStatus.ISSUED,
                    issued_at=now - timedelta(minutes=30),
                    deadline=now + timedelta(minutes=60),
                )
            )

        signal = _signal(await _read(session_maker, now), "lease_overrun")
        assert signal.status == "ok"
        assert signal.value == 0
        assert signal.detail["open_validator_leases"] == 1
        assert signal.detail["oldest_validator_lease_age_seconds"] == 1800

    async def test_lease_open_long_past_its_deadline_breaches(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        agent_id = await _agent(
            session_maker,
            status=AgentStatus.EVALUATING,
            created_at=now - timedelta(hours=4),
        )
        deadline = now - timedelta(hours=1)
        async with session_maker() as session, session.begin():
            session.add(
                ValidatorTicket(
                    agent_id=agent_id,
                    bench_version=13,
                    validator_hotkey=_VALIDATOR,
                    slot_id="slot-0",
                    status=TicketStatus.ISSUED,
                    issued_at=now - timedelta(hours=3),
                    deadline=deadline,
                )
            )

        signal = _signal(await _read(session_maker, now), "lease_overrun")
        assert signal.status == "breach"
        assert signal.since == deadline
        assert signal.detail["worst_kind"] == "validator_ticket"


class TestSourceEmissionCollector:
    async def test_fresh_cursor_is_ok_and_missing_cursor_not_applicable(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        now = _now()
        missing = _signal(await _read(session_maker, now), "source_emission_collector")
        assert missing.status == "ok"
        assert missing.value is None

        async with session_maker() as session, session.begin():
            session.add(
                SourceEmissionCollectorCursor(
                    netuid=_NETUID,
                    block=100,
                    block_hash="0x" + "1" * 64,
                    updated_at=now - timedelta(seconds=40),
                )
            )
        signal = _signal(await _read(session_maker, now), "source_emission_collector")
        assert signal.status == "ok"
        assert signal.detail["cursor_block"] == 100
        assert signal.detail["blocked"] is False

    async def test_halted_cursor_breaches_without_leaking_the_reason(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        """The #2231 shape; the stored message may carry a provider URL."""
        now = _now()
        secret_url = "wss://archive.example/ws/provider-marker-not-for-responses"
        async with session_maker() as session, session.begin():
            session.add(
                SourceEmissionCollectorCursor(
                    netuid=_NETUID,
                    block=100,
                    block_hash="0x" + "1" * 64,
                    updated_at=now - timedelta(hours=6),
                    last_blocked_reason=f"SubstrateRequestException: {secret_url}",
                )
            )

        liveness = await _read(session_maker, now)
        signal = _signal(liveness, "source_emission_collector")
        assert signal.status == "breach"
        assert signal.detail["blocked"] is True
        assert signal.detail["blocked_reason_class"] == "SubstrateRequestException"
        assert "provider-marker" not in liveness.model_dump_json()


class TestReadOnlyBoundary:
    async def test_every_signal_is_reported_on_an_empty_database(
        self, session_maker: async_sessionmaker[AsyncSession]
    ) -> None:
        liveness = await _read(session_maker, _now())
        assert liveness.status == "ok"
        assert [signal.name for signal in liveness.signals] == [
            "screening_admission",
            "oldest_claimable_upload",
            "scoring_throughput",
            "v13_scorer_cohort_pin",
            "oldest_actionable_hold",
            "lease_overrun",
            "source_emission_collector",
        ]
        assert {item.name for item in liveness.unavailable} == {
            "disk_and_db_headroom",
            "v13_scorer_pin_declines",
        }

    async def test_a_write_inside_the_read_is_refused_by_postgres(
        self,
        session_maker: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _writes(session: AsyncSession, **_kwargs: object) -> Any:
            await session.execute(
                text("UPDATE screener_nodes SET status_reason = 'liveness write probe'")
            )
            raise AssertionError("the READ ONLY transaction accepted a write")

        monkeypatch.setattr(subnet_liveness, "hold_signal", _writes)
        with pytest.raises(DBAPIError, match="read-only transaction"):
            await _read(session_maker, _now())
