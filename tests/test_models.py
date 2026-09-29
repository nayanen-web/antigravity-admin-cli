"""Unit tests for models: state sets, coverage, and report serialization."""

from datetime import datetime, timezone

from agy_admin.models import (
    AUTO_ALLOW_STATES,
    AUTO_DISALLOW_STATES,
    CONTROLLED_STATES,
    UNCONTROLLABLE_STATES,
    ActionOutcome,
    CapViolation,
    Coverage,
    EnforceResult,
    ReasonCode,
    RefusedAction,
    UserAssessment,
    UserMetric,
    UserStatus,
)


def test_user_metric_defaults_to_unknown_not_allowed():
    """An unassessed metric must never imply the user has access."""
    assert UserMetric(user_id="a@corp.com").status == UserStatus.UNKNOWN


def test_user_metric_to_dict():
    now = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    m = UserMetric(
        user_id="developer1@example.com",
        status=UserStatus.ENFORCEABLE_ALLOWED,
        total_requests=42,
        total_tokens=150000,
        prompt_tokens=120000,
        candidates_tokens=30000,
        clients=["antigravity_hub", "antigravity_cli"],
        models=["gemini-3.7-flash"],
        first_active=now,
        last_active=now,
    )

    d = m.to_dict()
    assert d["user_id"] == "developer1@example.com"
    assert d["status"] == "ENFORCEABLE_ALLOWED"
    assert d["reason"] == "-"
    assert d["total_requests"] == 42
    assert "antigravity_hub" in d["clients"]
    assert "gemini-3.7-flash" in d["models"]


def test_automatic_action_sets_are_whitelists():
    """Automation acts on explicit states, never on "everything else"."""
    assert AUTO_DISALLOW_STATES == frozenset({UserStatus.ENFORCEABLE_ALLOWED})
    assert AUTO_ALLOW_STATES == frozenset({UserStatus.CAPPED_BY_TOOL})
    # An administrator block is never auto-restored.
    assert UserStatus.BLOCKED_BY_ADMIN not in AUTO_ALLOW_STATES
    # Nor is a user the tool has never seen.
    assert UserStatus.NO_ACCESS not in AUTO_ALLOW_STATES
    assert UserStatus.UNKNOWN not in AUTO_ALLOW_STATES
    assert UserStatus.NOT_ENFORCEABLE not in AUTO_DISALLOW_STATES
    assert UNCONTROLLABLE_STATES == frozenset(
        {UserStatus.NOT_ENFORCEABLE, UserStatus.UNKNOWN}
    )
    # Uncontrollable states are excluded from every action set: there is no
    # escape hatch that lets an operator act on them.
    for state in UNCONTROLLABLE_STATES:
        assert state not in AUTO_DISALLOW_STATES
        assert state not in AUTO_ALLOW_STATES
        assert state not in CONTROLLED_STATES
    assert CONTROLLED_STATES == frozenset(
        {
            UserStatus.ENFORCEABLE_ALLOWED,
            UserStatus.CAPPED_BY_TOOL,
            UserStatus.BLOCKED_BY_ADMIN,
        }
    )


def test_coverage_from_assessments():
    assessments = {
        "a": UserAssessment(user_id="a", status=UserStatus.ENFORCEABLE_ALLOWED),
        "b": UserAssessment(user_id="b", status=UserStatus.CAPPED_BY_TOOL),
        "c": UserAssessment(
            user_id="c",
            status=UserStatus.NOT_ENFORCEABLE,
            reason=ReasonCode.GROUP_GRANT_PRESENT,
        ),
        "d": UserAssessment(
            user_id="d",
            status=UserStatus.NOT_ENFORCEABLE,
            reason=ReasonCode.PRIVILEGED_ROLE,
        ),
        "e": UserAssessment(user_id="e", status=UserStatus.NO_ACCESS),
        "f": UserAssessment(
            user_id="f", status=UserStatus.UNKNOWN, reason=ReasonCode.POLICY_UNREADABLE
        ),
    }

    cov = Coverage.from_assessments(assessments)
    assert cov.total_evaluated == 6
    assert cov.enforceable == 2
    assert cov.not_enforceable == 2
    assert cov.no_access == 1
    assert cov.unknown == 1
    assert cov.not_enforceable_by_reason == {
        "GROUP_GRANT_PRESENT": 1,
        "PRIVILEGED_ROLE": 1,
    }
    assert cov.coverage_ratio == round(2 / 6, 4)


def test_coverage_of_empty_population():
    cov = Coverage.from_assessments({})
    assert cov.total_evaluated == 0
    assert cov.coverage_ratio == 0.0


def test_action_outcome_tracks_refusals():
    outcome = ActionOutcome(
        applied=["a@corp.com"],
        no_op=["b@corp.com"],
        refused=[
            RefusedAction(
                user_id="c@corp.com",
                status=UserStatus.NOT_ENFORCEABLE,
                reason=ReasonCode.GROUP_GRANT_PRESENT,
                detail="group binding",
            )
        ],
    )
    assert outcome.has_refusals is True
    assert ActionOutcome().has_refusals is False


def test_enforce_result_counts_separate_enforced_from_detected():
    enforced = CapViolation(
        user_id="a@corp.com",
        period="daily",
        metric_type="tokens",
        limit=1,
        actual=2,
        overage=1,
        enforced=True,
    )
    blocked_nowhere = CapViolation(
        user_id="b@corp.com",
        period="daily",
        metric_type="tokens",
        limit=1,
        actual=2,
        overage=1,
        status=UserStatus.NOT_ENFORCEABLE,
        reason=ReasonCode.PRIVILEGED_ROLE,
    )
    result = EnforceResult(
        period="daily",
        violations=[enforced, blocked_nowhere],
        unenforceable_violations=[blocked_nowhere],
        disallowed_users=["a@corp.com"],
    )

    assert result.violations_total == 2
    assert result.violations_enforced == 1
    assert result.violations_unenforceable == 1

    report = result.to_report_dict()
    assert report["violations_total"] == 2
    assert report["violations_enforced"] == 1
    assert report["violations_unenforceable"] == 1
