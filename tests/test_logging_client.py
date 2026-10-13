"""Unit tests for Cloud Logging metrics client."""

from datetime import datetime, timezone
from agy_admin.logging_client import LoggingMetricsClient, calculate_time_range
from agy_admin.models import PeriodType, WindowType


def test_calculate_time_range():
    ref_time = datetime(2026, 9, 8, 15, 30, 0, tzinfo=timezone.utc)

    # Calendar daily: start is 2026-09-08 00:00:00
    start, end = calculate_time_range(PeriodType.DAILY, WindowType.CALENDAR, now=ref_time)
    assert start == datetime(2026, 9, 8, 0, 0, 0, tzinfo=timezone.utc)
    assert end == ref_time

    # Rolling daily: start is 2026-09-07 15:30:00
    start_r, end_r = calculate_time_range(PeriodType.DAILY, WindowType.ROLLING, now=ref_time)
    assert start_r == datetime(2026, 9, 7, 15, 30, 0, tzinfo=timezone.utc)
    assert end_r == ref_time

    # Calendar monthly: start is 2026-09-01 00:00:00
    start_m, _ = calculate_time_range(PeriodType.MONTHLY, WindowType.CALENDAR, now=ref_time)
    assert start_m == datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)


def test_fetch_user_metrics_mock():
    ref_time = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)

    mock_entries = [
        {
            "timestamp": "2026-09-08T05:00:00Z",
            "labels": {
                "user_id": "alice@company.com",
                "client_name": "antigravity_hub",
                "model": "gemini-3.7-flash",
            },
            "jsonPayload": {
                "metadata": {
                    "totalTokenCount": "12000",
                    "promptTokenCount": "10000",
                    "candidatesTokenCount": "2000",
                }
            },
        },
        {
            "timestamp": "2026-09-08T07:30:00Z",
            "labels": {
                "user_id": "alice@company.com",
                "client_name": "antigravity_cli",
                "model": "gemini-3.7-flash",
            },
            "jsonPayload": {
                "metadata": {
                    "totalTokenCount": "8000",
                    "promptTokenCount": "6000",
                    "candidatesTokenCount": "2000",
                }
            },
        },
        {
            "timestamp": "2026-09-08T08:00:00Z",
            "labels": {
                "user_id": "bob@company.com",
                "client_name": "antigravity_hub",
                "model": "gemini-3.6-flash",
            },
            "jsonPayload": {
                "metadata": {
                    "totalTokenCount": "50000",
                    "promptTokenCount": "45000",
                    "candidatesTokenCount": "5000",
                }
            },
        },
        # Out of range entry (yesterday)
        {
            "timestamp": "2026-09-07T08:00:00Z",
            "labels": {
                "user_id": "charlie@company.com",
                "client_name": "antigravity_hub",
                "model": "gemini-3.7-flash",
            },
            "jsonPayload": {
                "metadata": {
                    "totalTokenCount": "99999",
                }
            },
        },
    ]

    client = LoggingMetricsClient(project_id="test-proj")
    metrics = client.fetch_user_metrics(
        period=PeriodType.DAILY,
        window_type=WindowType.CALENDAR,
        mock_entries=mock_entries,
        now=ref_time,
    )

    # Charlie is out of range
    assert "charlie@company.com" not in metrics
    assert "alice@company.com" in metrics
    assert "bob@company.com" in metrics

    alice = metrics["alice@company.com"]
    assert alice.total_requests == 2
    assert alice.total_tokens == 20000
    assert alice.prompt_tokens == 16000
    assert alice.candidates_tokens == 4000
    assert set(alice.clients) == {"antigravity_hub", "antigravity_cli"}
    assert alice.models == ["gemini-3.7-flash"]

    bob = metrics["bob@company.com"]
    assert bob.total_requests == 1
    assert bob.total_tokens == 50000


def test_write_audit_log():
    """Verify write_audit_log logs structured payload with reason and details to agy-admin/admin_actions."""
    from unittest.mock import MagicMock

    mock_client = MagicMock()
    mock_logger = MagicMock()
    mock_client.logger.return_value = mock_logger

    logging_client = LoggingMetricsClient(project_id="test-proj", client=mock_client)

    payload = logging_client.write_audit_log(
        user_id="devuser01@company.com",
        action="disallow",
        reason="Tokens (850,000) exceeded limit (800,000) in daily rolling window",
        details={
            "period": "daily",
            "window_type": "rolling",
            "actual_tokens": 850000,
            "cap_tokens": 800000,
        },
        dry_run=False,
    )

    mock_client.logger.assert_called_with("agy-admin%2Fadmin_actions")
    mock_logger.log_struct.assert_called_once()

    call_args = mock_logger.log_struct.call_args
    logged_payload = call_args[0][0]
    logged_severity = call_args[1].get("severity")

    assert logged_payload["user_id"] == "devuser01@company.com"
    assert logged_payload["action"] == "disallow"
    assert "exceeded limit (800,000)" in logged_payload["reason"]
    assert logged_payload["details"]["actual_tokens"] == 850000
    assert logged_payload["details"]["cap_tokens"] == 800000
    assert logged_payload["dry_run"] is False
    assert logged_severity == "NOTICE"


def test_build_filter():
    from datetime import datetime, timezone
    logging_client = LoggingMetricsClient(project_id="my-test-proj")

    start = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 9, 8, 0, 0, 0, tzinfo=timezone.utc)

    # 1. No user filter
    f_all = logging_client._build_filter(start, end)
    assert 'logName="projects/my-test-proj/logs/businessaicode.googleapis.com%2Finference_response"' in f_all
    assert 'timestamp >= "2026-09-01T00:00:00Z"' in f_all
    assert 'timestamp <= "2026-09-08T00:00:00Z"' in f_all
    assert "labels.user_id" not in f_all

    # 2. Single user
    f_single = logging_client._build_filter(start, end, user_ids=["u1@corp.com"])
    assert 'labels.user_id = "u1@corp.com"' in f_single

    # 3. Multiple users
    f_multi = logging_client._build_filter(start, end, user_ids=["u1@corp.com", "u2@corp.com"])
    assert '(labels.user_id = "u1@corp.com" OR labels.user_id = "u2@corp.com")' in f_multi


def test_write_audit_log_error_handling():
    """Verify write_audit_log catches exceptions without crashing."""
    from unittest.mock import MagicMock

    mock_client = MagicMock()
    mock_client.logger.side_effect = RuntimeError("Logging API offline")

    logging_client = LoggingMetricsClient(project_id="test-proj", client=mock_client)
    payload = logging_client.write_audit_log(
        user_id="devuser01@company.com",
        action="disallow",
        reason="test error handling",
    )
    assert payload["user_id"] == "devuser01@company.com"
    assert payload["action"] == "disallow"


def test_calculate_time_range_all_and_naive():
    from datetime import datetime
    now_naive = datetime(2026, 9, 8, 12, 0, 0)
    start, end = calculate_time_range(PeriodType.ALL, now=now_naive)
    assert (end - start).days == 90
    assert start.tzinfo is not None


# ---------------------------------------------------------------------------
# v0.2.0 additions
# ---------------------------------------------------------------------------


def test_fetch_result_distinguishes_no_usage_from_no_telemetry():
    """Gate G3 depends on this distinction; v0.1.0 collapsed both into {}."""
    client = LoggingMetricsClient(project_id="test-proj")

    empty = client.fetch_metrics(mock_entries=[])
    assert empty.query_ok is True
    assert empty.entry_count == 0
    assert empty.healthy is False

    populated = client.fetch_metrics(
        mock_entries=[
            {
                "labels": {"user_id": "a@corp.com"},
                "jsonPayload": {"metadata": {"totalTokenCount": 5}},
            }
        ]
    )
    assert populated.entry_count == 1
    assert populated.healthy is True


def test_query_failure_is_not_reported_as_zero_usage(monkeypatch):
    client = LoggingMetricsClient(project_id="test-proj")

    def boom():
        raise RuntimeError("PERMISSION_DENIED")

    monkeypatch.setattr(client, "_get_client", boom)

    result = client.fetch_metrics(period=PeriodType.DAILY)
    assert result.query_ok is False
    assert "PERMISSION_DENIED" in result.error
    assert result.healthy is False
    assert result.metrics == {}


def test_model_label_prefers_documented_model_id_key():
    """The docs say labels.model_id; v0.1.0 only read labels.model."""
    client = LoggingMetricsClient(project_id="test-proj")
    result = client.fetch_metrics(
        mock_entries=[
            {
                "labels": {"user_id": "a@corp.com", "model_id": "gemini-3.7-flash"},
                "jsonPayload": {"metadata": {"totalTokenCount": 1}},
            },
            {
                "labels": {"user_id": "b@corp.com", "model": "gemini-3.6-flash"},
                "jsonPayload": {"metadata": {"totalTokenCount": 1}},
            },
        ]
    )
    assert result.metrics["a@corp.com"].models == ["gemini-3.7-flash"]
    assert result.metrics["b@corp.com"].models == ["gemini-3.6-flash"]


def test_requests_without_token_metadata_are_still_counted():
    """v0.1.0's filter required totalTokenCount, undercounting request volume."""
    client = LoggingMetricsClient(project_id="test-proj")
    result = client.fetch_metrics(
        mock_entries=[
            {"labels": {"user_id": "a@corp.com"}, "jsonPayload": {}},
            {"labels": {"user_id": "a@corp.com"}, "jsonPayload": {"metadata": {}}},
        ]
    )
    assert result.metrics["a@corp.com"].total_requests == 2
    assert result.metrics["a@corp.com"].total_tokens == 0


def test_build_filter_has_no_token_precondition():
    from datetime import datetime, timezone

    client = LoggingMetricsClient(project_id="p")
    f = client._build_filter(
        datetime(2026, 9, 1, tzinfo=timezone.utc),
        datetime(2026, 9, 8, tzinfo=timezone.utc),
    )
    assert "totalTokenCount" not in f


def test_build_filter_rejects_unsafe_user_ids():
    from datetime import datetime, timezone

    client = LoggingMetricsClient(project_id="p")
    f = client._build_filter(
        datetime(2026, 9, 1, tzinfo=timezone.utc),
        datetime(2026, 9, 8, tzinfo=timezone.utc),
        user_ids=['ok@corp.com', 'evil" OR severity>="DEFAULT'],
    )
    assert 'labels.user_id = "ok@corp.com"' in f
    assert "evil" not in f
    assert 'severity' not in f


def test_audit_payload_reports_whether_it_was_written():
    from unittest.mock import MagicMock

    ok_client = MagicMock()
    payload = LoggingMetricsClient("p", client=ok_client).write_audit_log(
        user_id="a@corp.com", action="disallow", reason="r"
    )
    assert payload["written"] is True

    failing = MagicMock()
    failing.logger.side_effect = RuntimeError("no logging.logWriter")
    payload_err = LoggingMetricsClient("p", client=failing).write_audit_log(
        user_id="a@corp.com", action="disallow", reason="r"
    )
    # The caller can now surface a degraded audit trail instead of assuming
    # the record exists.
    assert payload_err["written"] is False
    assert "no logging.logWriter" in payload_err["write_error"]


def test_audit_payload_carries_state_and_reason():
    from unittest.mock import MagicMock

    from agy_admin.models import AuditAction, ReasonCode, UserStatus

    client = MagicMock()
    payload = LoggingMetricsClient("p", client=client).write_audit_log(
        user_id="a@corp.com",
        action=AuditAction.DISALLOW_NOT_ENFORCEABLE,
        reason="cap exceeded but not enforceable",
        status=UserStatus.NOT_ENFORCEABLE.value,
        reason_code=ReasonCode.PRIVILEGED_ROLE.value,
    )
    assert payload["action"] == "disallow_not_enforceable"
    assert payload["status"] == "NOT_ENFORCEABLE"
    assert payload["reason_code"] == "PRIVILEGED_ROLE"
    # The forced flag was removed along with the --force escape hatch.
    assert "forced" not in payload


