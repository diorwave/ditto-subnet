"""Pin report-only L2 canaries to an immutable review-settings revision.

Revision ID: 8d3e6a1f4b27
Revises: 5e2a8c4f9d17
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "8d3e6a1f4b27"
down_revision: str | Sequence[str] | None = "5e2a8c4f9d17"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "screener_l2_report_canaries"


def upgrade() -> None:
    op.add_column(
        _TABLE, sa.Column("review_settings_revision", sa.Integer(), nullable=True)
    )
    op.add_column(_TABLE, sa.Column("review_settings_scope", sa.Text(), nullable=True))
    op.add_column(
        _TABLE, sa.Column("review_settings_checksum", sa.Text(), nullable=True)
    )
    op.create_foreign_key(
        "screener_l2_canary_review_settings_revision_fkey",
        _TABLE,
        "screener_review_settings_revisions",
        ["review_settings_revision"],
        ["revision"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        op.f("ck_screener_l2_report_canaries_screener_l2_canary_pin_check"),
        _TABLE,
        "(review_settings_revision IS NULL "
        "AND review_settings_scope IS NULL "
        "AND review_settings_checksum IS NULL) OR "
        "(review_settings_revision IS NOT NULL "
        "AND review_settings_scope IS NOT NULL "
        "AND review_settings_checksum IS NOT NULL)",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_screener_l2_report_canaries_screener_l2_canary_pin_check"),
        _TABLE,
        type_="check",
    )
    op.drop_constraint(
        "screener_l2_canary_review_settings_revision_fkey",
        _TABLE,
        type_="foreignkey",
    )
    op.drop_column(_TABLE, "review_settings_checksum")
    op.drop_column(_TABLE, "review_settings_scope")
    op.drop_column(_TABLE, "review_settings_revision")
