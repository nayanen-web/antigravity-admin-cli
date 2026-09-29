"""Unit tests for output formatters (Text, JSON, CSV)."""

import json

from agy_admin.formatter import format_enforce_result, format_user_metrics
from agy_admin.models import (
    CapViolation,
    Coverage,
    EnforceResult,
    GateId,
    GateResult,
    OutputFormat,
    ReasonCode,
    UserMetric,
    UserStatus,
)


def test_format_user_metrics_renders_state_and_reason():
    metrics = [
        UserMetric(
            user_id="u1@corp.com",
            status=UserStatus.ENFORCEABLE_ALLOWED,
            total_requests=10,
            total_tokens=1000,
        ),
        UserMetric(
            user_id="u2@corp.com",
            status=UserStatus.NOT_ENFORCEABLE,
            reason=ReasonCode.PRIVILEGED_ROLE,
            total_requests=5,
            total_tokens=500,
        ),
        UserMetric(
            user_id="u3@corp.com",
            status=UserStatus.CAPPED_BY_TOOL,
            total_requests=100,
            total_tokens=50000,
        ),
        UserMetric(user_id="u4@corp.com", status=UserStatus.NO_ACCESS),
    ]

    text_out = format_user_metrics(metrics, OutputFormat.TEXT)
    assert "ENFORCEABLE_ALLOWED" in text_out
    assert "NOT_ENFORCEABLE" in text_out
    assert "PRIVILEGED_ROLE" in text_out
    assert "CAPPED_BY_TOOL" in text_out
    assert "NO_ACCESS" in text_out

    data = json.loads(format_user_metrics(metrics, OutputFormat.JSON))
    assert len(data) == 4
    assert data[1]["reason"] == "PRIVILEGED_ROLE"

    csv_out = format_user_metrics(metrics, OutputFormat.CSV)
    assert "user_id,status,reason,total_requests,total_tokens" in csv_out
    assert "u1@corp.com,ENFORCEABLE_ALLOWED,-,10,1000" in csv_out


def _violation(user_id, enforced, status, reason=None):
    return CapViolation(
        user_id=user_id,
        period="daily",
        metric_type="tokens",
        limit=1000000,
        actual=1500000,
        overage=500000,
        status=status,
        reason=reason,
        enforced=enforced,
    )


def _result() -> EnforceResult:
    unenforceable = _violation(
        "boss@corp.com",
        False,
        UserStatus.NOT_ENFORCEABLE,
        ReasonCode.PRIVILEGED_ROLE,
    )
    return EnforceResult(
        period="daily",
        evaluated_users_count=4,
        coverage=Coverage(
            total_evaluated=4,
            enforceable=2,
            not_enforceable=1,
            not_enforceable_by_reason={"PRIVILEGED_ROLE": 1},
            no_access=1,
            coverage_ratio=0.5,
        ),
        violations=[
            _violation("heavy@corp.com", True, UserStatus.ENFORCEABLE_ALLOWED),
            unenforceable,
        ],
        unenforceable_violations=[unenforceable],
        disallowed_users=["heavy@corp.com"],
        allowed_users=["restored@corp.com"],
        reallowed_metrics=[UserMetric(user_id="restored@corp.com")],
        gates=[
            GateResult(
                gate=GateId.G5_NON_USER_GRANT_ABSENT,
                passed=False,
                detail="A group/domain binding exists on an access-granting role.",
            )
        ],
    )


def test_enforce_result_text_never_claims_a_block_that_did_not_happen():
    text_out = format_enforce_result(_result(), OutputFormat.TEXT)

    assert "Cap Enforcement Summary" in text_out
    assert "coverage 50.0%" in text_out
    assert "blocked 1" in text_out
    assert "not enforceable 1" in text_out
    assert "DISALLOWED" in text_out
    assert "NOT ENFORCEABLE" in text_out
    # v0.1.0 printed ALREADY BLOCKED for users it had never blocked.
    assert "ALREADY BLOCKED" not in text_out
    assert "Manual Action Required" in text_out
    assert "RE-ALLOWED" in text_out
    assert "WARNING" in text_out


def test_enforce_result_json_includes_coverage_and_manual_list():
    data = json.loads(format_enforce_result(_result(), OutputFormat.JSON))

    assert data["period"] == "daily"
    assert data["disallowed_users"] == ["heavy@corp.com"]
    assert data["violations_total"] == 2
    assert data["violations_enforced"] == 1
    assert data["violations_unenforceable"] == 1
    assert data["coverage"]["coverage_ratio"] == 0.5
    assert data["unenforceable_violations"][0]["user_id"] == "boss@corp.com"
    assert data["unenforceable_violations"][0]["reason"] == "PRIVILEGED_ROLE"


def test_enforce_result_csv_reports_action_per_violation():
    csv_out = format_enforce_result(_result(), OutputFormat.CSV)

    assert "user_id,period,metric_type,limit,actual,overage,status,reason,action" in csv_out
    assert (
        "heavy@corp.com,daily,tokens,1000000,1500000,500000,ENFORCEABLE_ALLOWED,,DISALLOWED"
        in csv_out
    )
    assert (
        "boss@corp.com,daily,tokens,1000000,1500000,500000,NOT_ENFORCEABLE,"
        "PRIVILEGED_ROLE,NOT_ENFORCEABLE" in csv_out
    )


def test_aborted_result_is_reported_as_such():
    result = EnforceResult(
        period="daily",
        aborted=True,
        abort_reason="Could not read the project IAM policy: permission denied",
        gates=[
            GateResult(
                gate=GateId.G1_POLICY_READABLE,
                passed=False,
                detail="Could not read the project IAM policy: permission denied",
            )
        ],
    )
    text_out = format_enforce_result(result, OutputFormat.TEXT)
    assert "ABORTED" in text_out
    assert "No IAM changes were applied" in text_out
