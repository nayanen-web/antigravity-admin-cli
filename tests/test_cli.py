"""Unit tests for CLI commands under the v0.2.0 enforcement model."""

import pytest
import typer
from typer.testing import CliRunner

from agy_admin.cli import (
    EXIT_ABORTED,
    EXIT_REFUSED,
    _filter_and_sort_metrics,
    _read_users_from_file,
    _validate_filter_status,
    app,
)
from agy_admin.config import DEFAULT_ALLOWED_ROLE, DEFAULT_CAP_ROLE_ID
from agy_admin.iam_manager import IAMManager
from agy_admin.logging_client import LoggingMetricsClient, MetricsFetchResult
from agy_admin.models import (
    OrderByField,
    OrderDirection,
    UserMetric,
    UserStatus,
)

runner = CliRunner()

PROJECT = "mock-proj"
CAP_ROLE = f"projects/{PROJECT}/roles/{DEFAULT_CAP_ROLE_ID}"


@pytest.fixture(autouse=True)
def no_network_audit(monkeypatch):
    """Never let a CLI test try to reach Cloud Logging."""
    monkeypatch.setattr(
        LoggingMetricsClient, "write_audit_log", lambda self, **kw: {"written": False}
    )


def install_iam(monkeypatch, bindings, **kwargs) -> IAMManager:
    iam = IAMManager(PROJECT, mock_bindings=bindings, **kwargs)
    monkeypatch.setattr("agy_admin.cli.build_iam_manager", lambda settings: iam)
    return iam


def install_metrics(monkeypatch, metrics, entry_count=1, query_ok=True):
    def fake_fetch(self, period=None, window_type=None, user_ids=None, mock_entries=None, now=None):
        return MetricsFetchResult(
            metrics={k: v.model_copy(deep=True) for k, v in metrics.items()},
            entry_count=entry_count,
            query_ok=query_ok,
        )

    monkeypatch.setattr(LoggingMetricsClient, "fetch_metrics", fake_fetch)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_filter_and_sort_metrics():
    metrics = [
        UserMetric(
            user_id="devuser01@corp.com",
            status=UserStatus.ENFORCEABLE_ALLOWED,
            total_requests=10,
            total_tokens=1000,
        ),
        UserMetric(
            user_id="bob@corp.com",
            status=UserStatus.CAPPED_BY_TOOL,
            total_requests=25,
            total_tokens=5000,
        ),
        UserMetric(
            user_id="charlie@corp.com",
            status=UserStatus.ENFORCEABLE_ALLOWED,
            total_requests=5,
            total_tokens=2000,
        ),
    ]

    assert [m.user_id for m in _filter_and_sort_metrics(metrics, filter_user="devuser01")] == [
        "devuser01@corp.com"
    ]

    allowed = _filter_and_sort_metrics(metrics, filter_status="ENFORCEABLE_ALLOWED")
    assert len(allowed) == 2

    sorted_tok = _filter_and_sort_metrics(
        metrics, order_by=OrderByField.TOKENS, direction=OrderDirection.DESC
    )
    assert sorted_tok[0].user_id == "bob@corp.com"
    assert sorted_tok[-1].user_id == "devuser01@corp.com"

    sorted_req = _filter_and_sort_metrics(
        metrics, order_by=OrderByField.REQUESTS, direction=OrderDirection.ASC
    )
    assert sorted_req[0].user_id == "charlie@corp.com"


def test_validate_filter_status():
    assert _validate_filter_status(None) == "all"
    assert _validate_filter_status("capped_by_tool") == "CAPPED_BY_TOOL"
    with pytest.raises(typer.BadParameter):
        # v0.1.0 silently returned an empty table for a mistyped status.
        _validate_filter_status("allowed")


def test_read_users_from_file_accepts_separators(tmp_path):
    user_file = tmp_path / "users.txt"
    user_file.write_text(
        "# Header comment\n"
        "u1@corp.com, u2@corp.com; u3@corp.com\n"
        "u4@corp.com\n"
        "U1@CORP.COM\n"
    )
    assert _read_users_from_file(user_file) == [
        "u1@corp.com",
        "u2@corp.com",
        "u3@corp.com",
        "u4@corp.com",
    ]


def test_read_users_from_file_rejects_non_emails(tmp_path):
    csv_file = tmp_path / "users.csv"
    csv_file.write_text("email\nu1@corp.com\n")
    with pytest.raises(typer.BadParameter, match="not a valid email"):
        _read_users_from_file(csv_file)

    with pytest.raises(typer.BadParameter, match="File not found"):
        _read_users_from_file(tmp_path / "missing.txt")


# ---------------------------------------------------------------------------
# list / user
# ---------------------------------------------------------------------------


def test_list_reports_enforcement_state(monkeypatch):
    install_iam(monkeypatch, {DEFAULT_ALLOWED_ROLE: ["user:dev1@corp.com"]})
    install_metrics(
        monkeypatch,
        {
            "dev1@corp.com": UserMetric(user_id="dev1@corp.com", total_tokens=100000),
            "dev2@corp.com": UserMetric(user_id="dev2@corp.com", total_tokens=50000),
        },
    )

    res = runner.invoke(app, ["list", "--project", PROJECT, "--format", "json"])
    assert res.exit_code == 0
    assert '"status": "ENFORCEABLE_ALLOWED"' in res.output
    # A user with no binding is NO_ACCESS, not "disallowed".
    assert '"status": "NO_ACCESS"' in res.output


def test_user_command_json(monkeypatch):
    install_iam(monkeypatch, {DEFAULT_ALLOWED_ROLE: ["user:dev1@corp.com"]})
    install_metrics(
        monkeypatch,
        {"dev1@corp.com": UserMetric(user_id="dev1@corp.com", total_requests=15, total_tokens=75000)},
    )

    res = runner.invoke(
        app, ["user", "dev1@corp.com", "--project", PROJECT, "--format", "json"]
    )
    assert res.exit_code == 0
    assert '"user_id": "dev1@corp.com"' in res.output
    assert '"total_tokens": 75000' in res.output


# ---------------------------------------------------------------------------
# allow / disallow
# ---------------------------------------------------------------------------


def test_disallow_dry_run(monkeypatch):
    install_iam(monkeypatch, {DEFAULT_ALLOWED_ROLE: ["user:dev1@corp.com"]})
    res = runner.invoke(
        app, ["disallow", "dev1@corp.com", "--dry-run", "--project", PROJECT]
    )
    assert res.exit_code == 0
    assert "DRY-RUN" in res.output
    assert "Disallow operation completed" in res.output
    assert "dev1@corp.com" in res.output


def test_disallow_uses_admin_marker_so_cycle_never_restores(monkeypatch):
    bindings = {DEFAULT_ALLOWED_ROLE: ["user:dev1@corp.com"]}
    iam = install_iam(monkeypatch, bindings)
    res = runner.invoke(app, ["disallow", "dev1@corp.com", "--project", PROJECT])

    assert res.exit_code == 0
    assert "user:dev1@corp.com" in bindings[iam.admin_role]
    assert CAP_ROLE not in bindings


def test_disallow_refusal_exits_with_code_2(monkeypatch):
    bindings = {
        DEFAULT_ALLOWED_ROLE: ["group:team@corp.com", "user:dev1@corp.com"],
    }
    install_iam(monkeypatch, bindings)
    res = runner.invoke(app, ["disallow", "dev1@corp.com", "--project", PROJECT])

    assert res.exit_code == EXIT_REFUSED
    assert "Manual Action Required" in res.output
    assert "GROUP_GRANT_PRESENT" in res.output
    assert "user:dev1@corp.com" in bindings[DEFAULT_ALLOWED_ROLE]


def test_force_flag_is_rejected(monkeypatch):
    """--force was removed: a block the tool cannot deliver is never applied."""
    bindings = {
        DEFAULT_ALLOWED_ROLE: ["group:team@corp.com", "user:dev1@corp.com"],
    }
    install_iam(monkeypatch, bindings)
    res = runner.invoke(
        app, ["disallow", "dev1@corp.com", "--force", "--project", PROJECT]
    )

    assert res.exit_code != 0
    assert "user:dev1@corp.com" in bindings[DEFAULT_ALLOWED_ROLE]


def test_refusal_output_names_the_manual_remediation(monkeypatch):
    bindings = {DEFAULT_ALLOWED_ROLE: ["group:team@corp.com", "user:dev1@corp.com"]}
    install_iam(monkeypatch, bindings)
    res = runner.invoke(app, ["disallow", "dev1@corp.com", "--project", PROJECT])

    assert "Remove the user" in res.output or "group" in res.output.lower()


def test_allow_from_file_dry_run(monkeypatch, tmp_path):
    install_iam(monkeypatch, {CAP_ROLE: ["user:dev1@corp.com", "user:dev2@corp.com"]})
    user_file = tmp_path / "users.txt"
    user_file.write_text("dev1@corp.com\ndev2@corp.com\n")

    res = runner.invoke(
        app, ["allow", "--file", str(user_file), "--dry-run", "--project", PROJECT]
    )
    assert res.exit_code == 0
    assert "DRY-RUN" in res.output
    assert "Allow operation completed" in res.output


def test_allow_and_disallow_require_targets():
    for cmd in ("allow", "disallow"):
        res = runner.invoke(app, [cmd, "--project", PROJECT])
        assert res.exit_code == 1
        assert "Please specify at least one user ID or --file" in res.output


# ---------------------------------------------------------------------------
# cap apply
# ---------------------------------------------------------------------------


def test_cap_apply_dry_run(monkeypatch):
    install_iam(monkeypatch, {DEFAULT_ALLOWED_ROLE: ["user:dev1@corp.com"]})
    install_metrics(
        monkeypatch,
        {"dev1@corp.com": UserMetric(user_id="dev1@corp.com", total_tokens=600000)},
    )

    res = runner.invoke(
        app,
        [
            "cap",
            "apply",
            "--period",
            "daily",
            "--tokens",
            "500000",
            "--dry-run",
            "--project",
            PROJECT,
        ],
    )
    assert res.exit_code == 0
    assert "Cap Enforcement Summary" in res.output
    assert "dev1@corp.com" in res.output
    assert "coverage 100.0%" in res.output


def test_cap_apply_argument_validation():
    res = runner.invoke(app, ["cap", "apply", "--period", "daily", "--project", PROJECT])
    assert res.exit_code == 1
    assert "Please specify at least --requests, --tokens limit, or --config-file" in res.output

    res_all = runner.invoke(
        app, ["cap", "apply", "--period", "all", "--tokens", "1", "--project", PROJECT]
    )
    assert res_all.exit_code == 1
    assert "Cap period cannot be 'all'" in res_all.output


def test_cap_apply_exits_3_when_cycle_aborts(monkeypatch):
    install_iam(monkeypatch, {DEFAULT_ALLOWED_ROLE: [f"user:u{i}@corp.com" for i in range(40)]})
    install_metrics(
        monkeypatch,
        {
            f"u{i}@corp.com": UserMetric(user_id=f"u{i}@corp.com", total_tokens=999999)
            for i in range(40)
        },
    )

    res = runner.invoke(
        app,
        ["cap", "apply", "--period", "daily", "--tokens", "10", "--project", PROJECT],
    )
    assert res.exit_code == EXIT_ABORTED
    assert "ABORTED" in res.output
