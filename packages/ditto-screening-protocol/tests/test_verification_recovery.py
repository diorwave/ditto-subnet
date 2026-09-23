"""The published v13 verification inventory must match the policy document.

These assertions exist so a surface cannot quietly drop or rename an obligation:
the inventory is read straight out of ``workers/screener/docs/policy-v13.md``,
and a drifting spelling would let a ledger report an artifact as fully verified
while a published check was never in its list.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ditto_screening_protocol import (
    INTEGRITY_CHECK_IDS,
    MANDATORY_VERIFICATION_CHECK_IDS,
    MANDATORY_VERIFICATION_CHECKS,
    NON_DECISIVE_V13_REASON_CODES,
    NOT_RECORDED,
    OPAQUE_ROLE_IDS,
    OPAQUE_ROLES_REQUIRING_PRIVATE_TESTS,
    PUBLISHED_RETRY_DEFAULTS,
    SECURITY_CHECK_IDS,
    independent_worker_required,
)

_POLICY = (
    Path(__file__).resolve().parents[3]
    / "workers"
    / "screener"
    / "docs"
    / "policy-v13.md"
)


def _policy_text() -> str:
    if not _POLICY.exists():  # pragma: no cover - monorepo layout guard
        pytest.skip(f"policy document not available at {_POLICY}")
    return _POLICY.read_text()


def test_inventory_covers_every_published_mandatory_check() -> None:
    """The published list is numbered 1-19; the inventory mirrors it exactly."""
    text = _policy_text()
    section = text.split("## Mandatory verification", 1)[1].split(
        "Minimum profile:", 1
    )[0]
    numbered = re.findall(r"^(\d+)\. ", section, re.M)
    assert numbered, "the published mandatory-verification list was not found"
    assert len(MANDATORY_VERIFICATION_CHECKS) == len(numbered)
    assert [check.ordinal for check in MANDATORY_VERIFICATION_CHECKS] == [
        index + 1 for index in range(len(numbered))
    ]
    assert len(MANDATORY_VERIFICATION_CHECK_IDS) == len(MANDATORY_VERIFICATION_CHECKS)


def test_integrity_and_security_rule_ids_match_the_black_checklist() -> None:
    text = _policy_text()
    for rule_id in (*INTEGRITY_CHECK_IDS, *SECURITY_CHECK_IDS):
        assert f"### {rule_id}: " in text, rule_id
    assert INTEGRITY_CHECK_IDS == ("I1", "I2", "I3", "I4", "I5", "I6", "I7", "I8")
    assert SECURITY_CHECK_IDS == ("S1", "S2", "S3")


def test_non_decisive_reason_codes_match_the_published_list() -> None:
    """Only these holds are verification gaps rather than findings."""
    text = _policy_text()
    section = text.split("### Non-decisive results", 1)[1].split(
        "## Retry and deadline procedure", 1
    )[0]
    for reason_code in NON_DECISIVE_V13_REASON_CODES:
        assert f"`{reason_code}`" in section, reason_code


def test_published_retry_defaults_match_the_document() -> None:
    """The recommended defaults are quoted, not invented, and not enforced here."""
    text = _policy_text()
    section = text.split("Recommended defaults:", 1)[1].split("```", 2)[1]
    assert "artifact-controlled failure retries: 1" in section
    assert "provider failure retries: 2" in section
    assert "platform failure retries: 2" in section
    assert "independent worker required for platform/provider failure: yes" in section
    assert "maximum verification window: 24 hours" in section
    assert PUBLISHED_RETRY_DEFAULTS.artifact_failure_retries == 1
    assert PUBLISHED_RETRY_DEFAULTS.provider_failure_retries == 2
    assert PUBLISHED_RETRY_DEFAULTS.platform_failure_retries == 2
    assert (
        PUBLISHED_RETRY_DEFAULTS.independent_worker_required_for_platform_or_provider
        is True
    )
    assert PUBLISHED_RETRY_DEFAULTS.maximum_verification_window_hours == 24
    assert PUBLISHED_RETRY_DEFAULTS.enforced is False


def test_independent_worker_requirement_follows_the_failure_domain() -> None:
    assert independent_worker_required("platform") is True
    assert independent_worker_required("provider") is True
    assert independent_worker_required("artifact") is False
    assert independent_worker_required("submission") is False
    assert independent_worker_required(None) is False


def test_opaque_roles_and_their_private_test_duty_are_published() -> None:
    """Every role comes from the companion spec, with its stated test duty."""
    spec = _POLICY.with_name("policy-v13-opaque-verification.md")
    if not spec.exists():  # pragma: no cover - monorepo layout guard
        pytest.skip(f"opaque specification not available at {spec}")
    text = spec.read_text()
    # The role section of the companion spec is one "### <role>" heading per
    # role, under "## Role requirements".
    roles = re.findall(
        r"^### (.+)$",
        text.split("## Role requirements", 1)[1].split("## Behavioral package", 1)[0],
        re.M,
    )
    assert len(roles) == len(OPAQUE_ROLE_IDS)
    assert set(OPAQUE_ROLE_IDS) >= OPAQUE_ROLES_REQUIRING_PRIVATE_TESTS
    # The unloaded role's published requirement says no behavioral test is
    # needed, so it must never be reported as owing the paired suite.
    assert "unloaded_or_unreachable" not in OPAQUE_ROLES_REQUIRING_PRIVATE_TESTS
    assert "No private behavioral test is required." in text


def test_not_recorded_is_the_explicit_unknown_sentinel() -> None:
    assert NOT_RECORDED == "not_recorded"
