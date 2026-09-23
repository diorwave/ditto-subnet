"""Append-only operator grants that resume missing v13 mandatory verification.

Revision ID: 7b1c4e92da06
Revises: 3c9d5e7a1b42
Create Date: 2026-09-23

Four policy-v13 holds are blocked by automated court failures that establish
neither misconduct nor completed verification. An operator could only release,
reject, or order a full guarded rescreen. These two tables give the missing
third option a durable home: one append-only authorization per exact
non-decisive attempt, pinning every identity v13 binds a decision to, plus its
append-only attempt/evidence audit.

Neither table can clear, reject, or rule on a hold. Nothing schedules a grant;
it exists only because an operator authorized it.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "7b1c4e92da06"
down_revision: str | Sequence[str] | None = "3c9d5e7a1b42"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_NULLABLE_JSON = sa.JSON(none_as_null=True).with_variant(
    postgresql.JSONB(none_as_null=True), "postgresql"
)


def upgrade() -> None:
    """Create the grant and audit tables. Both are new; nothing is rewritten."""
    op.create_table(
        "screening_verification_recoveries",
        sa.Column("recovery_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("quarantine_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("source_attempt_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("artifact_sha256", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("manifest_digest", sa.Text(), nullable=False),
        sa.Column("image_digest", sa.Text(), nullable=True),
        sa.Column("expected_score_count", sa.Integer(), nullable=False),
        sa.Column("expected_attempt_count", sa.Integer(), nullable=False),
        sa.Column("outstanding_checks", _JSON, nullable=False),
        sa.Column("reused_evidence", _JSON, nullable=False),
        sa.Column("challenge_commitment", sa.Text(), nullable=False),
        sa.Column("challenge_manifest_version", sa.Integer(), nullable=False),
        sa.Column("challenge_seed_sealed", sa.Text(), nullable=False),
        sa.Column(
            "independent_worker_required",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("excluded_screener_hotkeys", _JSON, nullable=False),
        sa.Column(
            "state", sa.Text(), nullable=False, server_default=sa.text("'queued'")
        ),
        sa.Column("claimed_by", sa.Text(), nullable=True),
        sa.Column("claimed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("dispatch_deadline", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=True),
        sa.Column("failure_domain", sa.Text(), nullable=True),
        sa.Column("completed_checks", _NULLABLE_JSON, nullable=True),
        sa.Column("refuted_leads", _NULLABLE_JSON, nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("recovery_id"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.agent_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["quarantine_id"],
            ["screening_quarantines.quarantine_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_attempt_id"],
            ["screening_attempts.attempt_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "source_attempt_id",
            name="screening_verification_recoveries_attempt_key",
        ),
        sa.CheckConstraint(
            "length(artifact_sha256) = 64",
            name="screening_verification_recoveries_sha_check",
        ),
        sa.CheckConstraint(
            "policy_version > 0",
            name="screening_verification_recoveries_policy_check",
        ),
        sa.CheckConstraint(
            "expected_score_count >= 0 AND expected_attempt_count >= 0",
            name="screening_verification_recoveries_counts_check",
        ),
        sa.CheckConstraint(
            "challenge_manifest_version > 0",
            name="screening_verification_recoveries_manifest_version_check",
        ),
        sa.CheckConstraint(
            "state IN ('queued', 'dispatched', 'completed', 'failed', 'canceled')",
            name="screening_verification_recoveries_state_check",
        ),
        sa.CheckConstraint(
            "outcome IS NULL OR outcome IN "
            "('verification_complete', 'verification_incomplete')",
            name="screening_verification_recoveries_outcome_check",
        ),
        sa.CheckConstraint(
            "failure_domain IS NULL OR failure_domain IN "
            "('artifact', 'submission', 'platform', 'provider')",
            name="screening_verification_recoveries_domain_check",
        ),
        sa.CheckConstraint(
            "(state = 'completed' AND outcome = 'verification_complete') OR "
            "(state = 'failed' AND outcome = 'verification_incomplete' "
            "AND failure_domain IS NOT NULL) OR "
            "(state IN ('queued', 'dispatched', 'canceled') AND outcome IS NULL)",
            name="screening_verification_recoveries_terminal_check",
        ),
        sa.CheckConstraint(
            "state <> 'queued' OR (claimed_by IS NULL AND claimed_at IS NULL)",
            name="screening_verification_recoveries_claim_check",
        ),
        sa.CheckConstraint(
            "length(trim(reason)) >= 8",
            name="screening_verification_recoveries_reason_check",
        ),
        sa.CheckConstraint(
            "length(trim(actor)) BETWEEN 1 AND 120",
            name="screening_verification_recoveries_actor_check",
        ),
    )
    op.create_index(
        "screening_verification_recoveries_one_open_idx",
        "screening_verification_recoveries",
        ["agent_id"],
        unique=True,
        postgresql_where=sa.text("state IN ('queued', 'dispatched')"),
        sqlite_where=sa.text("state IN ('queued', 'dispatched')"),
    )
    op.create_index(
        "screening_verification_recoveries_agent_created_idx",
        "screening_verification_recoveries",
        ["agent_id", "created_at", "recovery_id"],
    )
    op.create_index(
        "screening_verification_recoveries_queued_idx",
        "screening_verification_recoveries",
        ["created_at"],
        postgresql_where=sa.text("state = 'queued'"),
        sqlite_where=sa.text("state = 'queued'"),
    )
    op.create_table(
        "screening_verification_events",
        sa.Column("event_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("recovery_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("event", sa.Text(), nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("detail", _NULLABLE_JSON, nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("event_id"),
        sa.ForeignKeyConstraint(
            ["recovery_id"],
            ["screening_verification_recoveries.recovery_id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "length(trim(actor)) BETWEEN 1 AND 120",
            name="screening_verification_events_actor_check",
        ),
    )
    op.create_index(
        "screening_verification_events_recovery_created_idx",
        "screening_verification_events",
        ["recovery_id", "created_at", "event_id"],
    )


def downgrade() -> None:
    """Drop the audit first so the grant table's dependents are gone."""
    op.drop_index(
        "screening_verification_events_recovery_created_idx",
        table_name="screening_verification_events",
    )
    op.drop_table("screening_verification_events")
    op.drop_index(
        "screening_verification_recoveries_queued_idx",
        table_name="screening_verification_recoveries",
    )
    op.drop_index(
        "screening_verification_recoveries_agent_created_idx",
        table_name="screening_verification_recoveries",
    )
    op.drop_index(
        "screening_verification_recoveries_one_open_idx",
        table_name="screening_verification_recoveries",
    )
    op.drop_table("screening_verification_recoveries")
