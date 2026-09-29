"""Unit tests for the batch job: exit codes, alert content, env parsing."""

import json
import urllib.error
from unittest.mock import MagicMock

import pytest

from agy_admin.batch_job import (
    EXIT_ABORTED,
    EXIT_CONFIG,
    build_alert_lines,
    main,
    run_enforcement_cycle,
    send_webhook_alert,
)
from agy_admin.config import DEFAULT_ALLOWED_ROLE, DEFAULT_CAP_ROLE_ID
from agy_admin.iam_manager import IAMManager
from agy_admin.logging_client import LoggingMetricsClient, MetricsFetchResult
from agy_admin.models import (
    CapViolation,
    Coverage,
    DisallowMode,
    EnforceResult,
    GateId,
    GateResult,
    PeriodType,
    ReasonCode,
    UserMetric,
    UserStatus,
    WindowType,
)

PROJECT = "test-batch-proj"


@pytest.fixture(autouse=True)
def no_network_audit(monkeypatch):
    monkeypatch.setattr(
        LoggingMetricsClient, "write_audit_log", lambda self, **kw: {"written": False}
    )


def install_iam(monkeypatch, bindings) -> IAMManager:
    iam = IAMManager(PROJECT, mock_bindings=bindings)
    monkeypatch.setattr("agy_admin.batch_job.build_iam_manager", lambda settings: iam)
    return iam


def install_metrics(monkeypatch, metrics, entry_count=1):
    def fake_fetch(self, period=None, window_type=None, user_ids=None, mock_entries=None, now=None):
        return MetricsFetchResult(
            metrics={k: v.model_copy(deep=True) for k, v in metrics.items()},
            entry_count=entry_count,
        )

    monkeypatch.setattr(LoggingMetricsClient, "fetch_metrics", fake_fetch)


# ---------------------------------------------------------------------------
# Cycle
# ---------------------------------------------------------------------------


def test_cycle_dry_run(monkeypatch):
    bindings = {
        DEFAULT_ALLOWED_ROLE: ["user:heavy@corp.com", "user:light@corp.com"]
    }
    install_iam(monkeypatch, bindings)
    install_metrics(
        monkeypatch,
        {
            "heavy@corp.com": UserMetric(
                user_id="heavy@corp.com", total_requests=500, total_tokens=2000000
            ),
            "light@corp.com": UserMetric(
                user_id="light@corp.com", total_requests=10, total_tokens=10000
            ),
        },
    )

    result = run_enforcement_cycle(
        project_id=PROJECT,
        period=PeriodType.DAILY,
        window_type=WindowType.CALENDAR,
        cap_requests=100,
        cap_tokens=1000000,
        disallow_mode=DisallowMode.REVOKE,
        dry_run=True,
        webhook_url=None,
    )

    assert result.dry_run is True
    assert result.evaluated_users_count == 2
    assert len(result.violations) == 2
    assert result.disallowed_users == ["heavy@corp.com"]
    assert bindings[DEFAULT_ALLOWED_ROLE] == [
        "user:heavy@corp.com",
        "user:light@corp.com",
    ]


# ---------------------------------------------------------------------------
# Alert content
# ---------------------------------------------------------------------------


def _violation(user_id, enforced, status=UserStatus.ENFORCEABLE_ALLOWED, reason=None):
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


def test_alert_lists_manual_action_users():
    """v0.1.0 alerted only on successful blocks, hiding the ones that failed."""
    result = EnforceResult(
        period="daily",
        evaluated_users_count=5,
        coverage=Coverage(total_evaluated=5, enforceable=3, not_enforceable=2, coverage_ratio=0.6),
        violations=[
            _violation("user1@corp.com", True),
            _violation(
                "boss@corp.com",
                False,
                status=UserStatus.NOT_ENFORCEABLE,
                reason=ReasonCode.PRIVILEGED_ROLE,
            ),
        ],
        unenforceable_violations=[
            _violation(
                "boss@corp.com",
                False,
                status=UserStatus.NOT_ENFORCEABLE,
                reason=ReasonCode.PRIVILEGED_ROLE,
            )
        ],
        disallowed_users=["user1@corp.com"],
        allowed_users=["user2@corp.com"],
    )

    text = "\n".join(build_alert_lines(result, "test-proj"))
    assert "coverage 60.0%" in text
    assert "Disallowed (1): user1@corp.com" in text
    assert "`user1@corp.com`: tokens actual=1,500,000 > limit=1,000,000" in text
    assert "MANUAL ACTION REQUIRED (1)" in text
    assert "PRIVILEGED_ROLE" in text
    assert "Re-allowed (1): user2@corp.com" in text


def test_alert_reports_abort():
    result = EnforceResult(
        period="daily", aborted=True, abort_reason="Could not read the project IAM policy"
    )
    text = "\n".join(build_alert_lines(result, "test-proj"))
    assert "ABORTED" in text
    assert "Could not read the project IAM policy" in text
    assert "No IAM changes were applied" in text


def test_alert_includes_gate_warnings():
    result = EnforceResult(
        period="daily",
        disallowed_users=["a@corp.com"],
        gates=[
            GateResult(
                gate=GateId.G5_NON_USER_GRANT_ABSENT,
                passed=False,
                detail="A group/domain binding exists",
            ),
            GateResult(
                gate=GateId.G3_TELEMETRY_HEALTHY, passed=False, detail="0 log entries"
            ),
        ],
    )
    text = "\n".join(build_alert_lines(result, "p"))
    assert "WARNING: A group/domain binding exists" in text
    assert "WARNING: 0 log entries" in text


def test_send_webhook_alert_posts_json(monkeypatch):
    mock_urlopen = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_urlopen.return_value.__enter__.return_value = mock_resp
    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

    result = EnforceResult(period="daily", disallowed_users=["user1@corp.com"])
    send_webhook_alert("https://example.com/webhook", result, "test-proj")

    mock_urlopen.assert_called_once()
    req = mock_urlopen.call_args[0][0]
    assert req.full_url == "https://example.com/webhook"
    assert req.headers["Content-type"] == "application/json"
    data = json.loads(req.data.decode("utf-8"))
    assert "Antigravity Usage Cap Enforced" in data["text"]


def test_send_webhook_alert_skips_quiet_cycles(monkeypatch):
    mock_urlopen = MagicMock()
    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

    quiet = EnforceResult(period="daily", evaluated_users_count=3)
    send_webhook_alert("https://example.com/webhook", quiet, "test-proj")
    mock_urlopen.assert_not_called()

    quiet.disallowed_users = ["user1@corp.com"]
    send_webhook_alert("", quiet, "test-proj")
    mock_urlopen.assert_not_called()


def test_send_webhook_alert_notifies_on_unenforceable_only(monkeypatch):
    mock_urlopen = MagicMock()
    mock_urlopen.return_value.__enter__.return_value = MagicMock(status=200)
    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

    result = EnforceResult(
        period="daily",
        unenforceable_violations=[
            _violation(
                "boss@corp.com",
                False,
                status=UserStatus.NOT_ENFORCEABLE,
                reason=ReasonCode.PRIVILEGED_ROLE,
            )
        ],
    )
    send_webhook_alert("https://example.com/webhook", result, "p")
    mock_urlopen.assert_called_once()


def test_send_webhook_alert_survives_network_failure(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        MagicMock(side_effect=urllib.error.URLError("Connection refused")),
    )
    send_webhook_alert(
        "https://fail.example.com/hook",
        EnforceResult(period="daily", disallowed_users=["bad@corp.com"]),
        "my-proj",
    )


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def _clear_env(monkeypatch):
    for key in (
        "CAP_PERIOD",
        "WINDOW_TYPE",
        "CAP_REQUESTS",
        "CAP_TOKENS",
        "IAM_DISALLOW_MODE",
        "DRY_RUN",
        "ALERT_WEBHOOK_URL",
        "SLACK_WEBHOOK_URL",
        "INTERVAL_MINUTES",
    ):
        monkeypatch.delenv(key, raising=False)


def test_main_single_shot_parses_env(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("GCP_PROJECT", "env-test-proj")
    monkeypatch.setenv("CAP_PERIOD", "weekly")
    monkeypatch.setenv("WINDOW_TYPE", "rolling")
    monkeypatch.setenv("CAP_REQUESTS", "500")
    monkeypatch.setenv("CAP_TOKENS", "750000")
    monkeypatch.setenv("IAM_DISALLOW_MODE", "revoke")
    monkeypatch.setenv("DRY_RUN", "true")
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://chat.example.com/webhook")
    monkeypatch.setenv("INTERVAL_MINUTES", "0")

    calls = []

    def mock_cycle(**kwargs):
        calls.append(kwargs)
        return EnforceResult(period="weekly", dry_run=True)

    monkeypatch.setattr("agy_admin.batch_job.run_enforcement_cycle", mock_cycle)

    main()

    assert len(calls) == 1
    args = calls[0]
    assert args["project_id"] == "env-test-proj"
    assert args["period"] == PeriodType.WEEKLY
    assert args["window_type"] == WindowType.ROLLING
    assert args["cap_requests"] == 500
    assert args["cap_tokens"] == 750000
    assert args["disallow_mode"] == DisallowMode.REVOKE
    assert args["dry_run"] is True
    assert args["webhook_url"] == "https://chat.example.com/webhook"


def test_main_exits_nonzero_when_cycle_aborts(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("GCP_PROJECT", "env-test-proj")
    monkeypatch.setenv("CAP_TOKENS", "1000")
    monkeypatch.setattr(
        "agy_admin.batch_job.run_enforcement_cycle",
        lambda **kw: EnforceResult(period="daily", aborted=True, abort_reason="G1"),
    )

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == EXIT_ABORTED


def test_main_refuses_to_run_without_thresholds(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("GCP_PROJECT", "env-test-proj")
    monkeypatch.setattr(
        "agy_admin.batch_job.run_enforcement_cycle",
        lambda **kw: EnforceResult(period="daily"),
    )

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == EXIT_CONFIG


def test_main_rejects_period_all(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("GCP_PROJECT", "env-test-proj")
    monkeypatch.setenv("CAP_PERIOD", "all")
    monkeypatch.setenv("CAP_TOKENS", "1000")

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == EXIT_CONFIG


def test_cycle_uses_cap_marker_so_users_can_recover(monkeypatch):
    bindings = {DEFAULT_ALLOWED_ROLE: ["user:heavy@corp.com"]}
    install_iam(monkeypatch, bindings)
    install_metrics(
        monkeypatch,
        {"heavy@corp.com": UserMetric(user_id="heavy@corp.com", total_tokens=2000000)},
    )

    run_enforcement_cycle(
        project_id=PROJECT,
        period=PeriodType.DAILY,
        window_type=WindowType.CALENDAR,
        cap_requests=None,
        cap_tokens=1000,
        disallow_mode=DisallowMode.CUSTOM_ROLE,
        dry_run=False,
        webhook_url=None,
    )

    cap_role = f"projects/{PROJECT}/roles/{DEFAULT_CAP_ROLE_ID}"
    assert "user:heavy@corp.com" in bindings[cap_role]
