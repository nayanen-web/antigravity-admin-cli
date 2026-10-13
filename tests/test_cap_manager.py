"""Unit tests for CapManager enforcement gates and whitelist semantics."""

from datetime import datetime, timezone

from agy_admin.cap_manager import CapManager
from agy_admin.config import (
    DEFAULT_ADMIN_ROLE_ID,
    DEFAULT_ALLOWED_ROLE,
    DEFAULT_CAP_ROLE_ID,
    Settings,
)
from agy_admin.iam_manager import IAMManager
from agy_admin.logging_client import LoggingMetricsClient
from agy_admin.models import (
    AuditAction,
    CapRule,
    DisallowMode,
    GateId,
    PeriodType,
    ReasonCode,
    UserMetric,
    UserStatus,
    WindowType,
)

PROJECT = "test-proj"
CAP_ROLE = f"projects/{PROJECT}/roles/{DEFAULT_CAP_ROLE_ID}"
ADMIN_ROLE = f"projects/{PROJECT}/roles/{DEFAULT_ADMIN_ROLE_ID}"


def entry(user_id: str, tokens: int, client_name: str = "antigravity_hub") -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "labels": {"user_id": user_id, "client_name": client_name},
        "jsonPayload": {"metadata": {"totalTokenCount": tokens}},
    }


def make_manager(bindings, settings=None, iam_kwargs=None):
    iam = IAMManager(PROJECT, mock_bindings=bindings, **(iam_kwargs or {}))
    # A sentinel client short-circuits _get_client(); it has no .logger attribute
    # so write_audit_log records the entry locally without any network call.
    return CapManager(
        project_id=PROJECT,
        logging_client=LoggingMetricsClient(PROJECT, client=object()),
        iam_manager=iam,
        settings=settings or Settings(project_id=PROJECT),
    ), iam


# ---------------------------------------------------------------------------
# Violation detection
# ---------------------------------------------------------------------------


def test_evaluate_violations_emits_one_row_per_breached_metric():
    cap_mgr, _ = make_manager({DEFAULT_ALLOWED_ROLE: ["user:heavy@corp.com"]})
    rule = CapRule(period=PeriodType.DAILY, max_requests=100, max_tokens=500000)

    metrics = {
        "heavy@corp.com": UserMetric(
            user_id="heavy@corp.com",
            status=UserStatus.ENFORCEABLE_ALLOWED,
            total_requests=120,
            total_tokens=600000,
        ),
        "light@corp.com": UserMetric(
            user_id="light@corp.com",
            status=UserStatus.ENFORCEABLE_ALLOWED,
            total_requests=10,
            total_tokens=20000,
        ),
    }

    violations = cap_mgr.evaluate_violations(metrics, rule)
    assert len(violations) == 2
    assert {v.user_id for v in violations} == {"heavy@corp.com"}
    assert {v.metric_type for v in violations} == {"requests", "tokens"}


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_enforce_blocks_only_enforceable_users():
    bindings = {
        DEFAULT_ALLOWED_ROLE: ["user:heavy@corp.com", "user:light@corp.com"]
    }
    cap_mgr, iam = make_manager(bindings)

    result = cap_mgr.enforce_caps(
        period=PeriodType.DAILY,
        max_tokens=100000,
        mock_entries=[entry("heavy@corp.com", 150000), entry("light@corp.com", 50000)],
    )

    assert result.aborted is False
    assert result.disallowed_users == ["heavy@corp.com"]
    assert "user:heavy@corp.com" not in bindings[DEFAULT_ALLOWED_ROLE]
    assert "user:light@corp.com" in bindings[DEFAULT_ALLOWED_ROLE]
    # The cap marker (not the admin marker) is applied so the block is reversible.
    assert "user:heavy@corp.com" in bindings[CAP_ROLE]
    assert result.violations[0].enforced is True


def test_enforce_reallows_only_tool_capped_users():
    """An administrator block must survive a cycle in which usage is low again."""
    bindings = {
        DEFAULT_ALLOWED_ROLE: [],
        CAP_ROLE: ["user:recovering@corp.com"],
        ADMIN_ROLE: ["user:offboarded@corp.com"],
    }
    cap_mgr, _ = make_manager(bindings)

    result = cap_mgr.enforce_caps(
        period=PeriodType.DAILY,
        max_tokens=100000,
        mock_entries=[entry("someone@corp.com", 10)],
    )

    assert result.allowed_users == ["recovering@corp.com"]
    assert "user:recovering@corp.com" in bindings[DEFAULT_ALLOWED_ROLE]
    # v0.1.0 restored this user because "not allowed" implied "capped".
    assert "user:offboarded@corp.com" in bindings[ADMIN_ROLE]
    assert "user:offboarded@corp.com" not in bindings[DEFAULT_ALLOWED_ROLE]


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def test_g3_withholds_reallow_when_telemetry_is_empty():
    """Zero log entries means "we cannot see usage", not "usage is zero"."""
    bindings = {CAP_ROLE: ["user:recovering@corp.com"]}
    cap_mgr, _ = make_manager(bindings)

    result = cap_mgr.enforce_caps(
        period=PeriodType.DAILY, max_tokens=100000, mock_entries=[]
    )

    g3 = result.gate(GateId.G3_TELEMETRY_HEALTHY)
    assert g3 is not None and g3.passed is False
    assert result.allowed_users == []
    assert "user:recovering@corp.com" in bindings[CAP_ROLE]
    assert DEFAULT_ALLOWED_ROLE not in bindings


def test_g1_aborts_when_policy_is_unreadable(monkeypatch):
    iam = IAMManager(PROJECT)
    monkeypatch.setattr(iam, "_get_resourcemanager_client", lambda: None)
    monkeypatch.setattr(
        "subprocess.run",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("permission denied")),
    )
    cap_mgr = CapManager(
        PROJECT,
        logging_client=LoggingMetricsClient(PROJECT, client=object()),
        iam_manager=iam,
        settings=Settings(project_id=PROJECT),
    )

    result = cap_mgr.enforce_caps(
        period=PeriodType.DAILY,
        max_tokens=1,
        mock_entries=[entry("someone@corp.com", 999999)],
    )

    assert result.aborted is True
    assert result.gate(GateId.G1_POLICY_READABLE).passed is False
    assert result.disallowed_users == []
    assert result.allowed_users == []


def test_g4_circuit_breaker_aborts_oversized_cycle():
    bindings = {
        DEFAULT_ALLOWED_ROLE: [f"user:u{i}@corp.com" for i in range(12)]
    }
    settings = Settings(project_id=PROJECT)
    settings.max_changes_abs = 3
    settings.max_changes_ratio = 0.0
    cap_mgr, _ = make_manager(bindings, settings=settings)

    result = cap_mgr.enforce_caps(
        period=PeriodType.DAILY,
        max_tokens=10,
        mock_entries=[entry(f"u{i}@corp.com", 1000) for i in range(12)],
    )

    assert result.aborted is True
    assert result.gate(GateId.G4_CHANGE_BUDGET).passed is False
    # Nothing was applied.
    assert len(bindings[DEFAULT_ALLOWED_ROLE]) == 12


def test_g5_flags_group_grants_without_aborting():
    bindings = {
        DEFAULT_ALLOWED_ROLE: ["group:ai-users@corp.com", "user:heavy@corp.com"]
    }
    cap_mgr, _ = make_manager(bindings)

    result = cap_mgr.enforce_caps(
        period=PeriodType.DAILY,
        max_tokens=100,
        mock_entries=[entry("heavy@corp.com", 999999)],
    )

    assert result.aborted is False
    assert result.gate(GateId.G5_NON_USER_GRANT_ABSENT).passed is False
    # The violation is reported honestly instead of being claimed as blocked.
    assert result.disallowed_users == []
    assert result.violations_unenforceable == 1
    assert result.unenforceable_violations[0].reason == ReasonCode.GROUP_GRANT_PRESENT
    assert "user:heavy@corp.com" in bindings[DEFAULT_ALLOWED_ROLE]


# ---------------------------------------------------------------------------
# Honest reporting of unenforceable violations
# ---------------------------------------------------------------------------


def test_overcap_but_unenforceable_users_are_listed_for_manual_action():
    bindings = {
        DEFAULT_ALLOWED_ROLE: ["user:normal@corp.com"],
        "roles/owner": ["user:boss@corp.com"],
        "roles/discoveryengine.admin": ["user:deadmin@corp.com"],
    }
    cap_mgr, _ = make_manager(bindings)

    result = cap_mgr.enforce_caps(
        period=PeriodType.DAILY,
        max_tokens=100000,
        mock_entries=[
            entry("normal@corp.com", 200000),
            entry("boss@corp.com", 300000),
            entry("deadmin@corp.com", 400000),
        ],
    )

    assert result.violations_total == 3
    assert result.disallowed_users == ["normal@corp.com"]
    assert result.violations_enforced == 1
    assert result.violations_unenforceable == 2

    manual = {v.user_id: v for v in result.unenforceable_violations}
    assert set(manual) == {"boss@corp.com", "deadmin@corp.com"}
    assert manual["boss@corp.com"].reason == ReasonCode.PRIVILEGED_ROLE
    assert manual["deadmin@corp.com"].reason == ReasonCode.OTHER_ACCESS_ROLE
    # And they are never mislabelled as already blocked.
    for v in result.violations:
        if v.user_id != "normal@corp.com":
            assert v.enforced is False

    assert "user:boss@corp.com" in bindings["roles/owner"]


def test_coverage_reports_controllable_share_of_population():
    bindings = {
        DEFAULT_ALLOWED_ROLE: ["user:a@corp.com", "user:b@corp.com"],
        "roles/owner": ["user:boss@corp.com"],
    }
    cap_mgr, _ = make_manager(bindings)

    result = cap_mgr.enforce_caps(
        period=PeriodType.DAILY,
        max_tokens=1000000,
        mock_entries=[
            entry("a@corp.com", 1),
            entry("b@corp.com", 1),
            entry("boss@corp.com", 1),
            entry("stranger@corp.com", 1),
        ],
    )

    cov = result.coverage
    assert cov.total_evaluated == 4
    assert cov.enforceable == 2
    assert cov.not_enforceable == 1
    assert cov.no_access == 1
    assert cov.not_enforceable_by_reason == {ReasonCode.PRIVILEGED_ROLE.value: 1}
    assert cov.coverage_ratio == 0.5


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


def test_audit_log_records_actions_and_refusals(monkeypatch):
    bindings = {
        DEFAULT_ALLOWED_ROLE: ["user:heavy@corp.com"],
        CAP_ROLE: ["user:recovering@corp.com"],
        "roles/owner": ["user:boss@corp.com"],
    }
    cap_mgr, _ = make_manager(bindings)

    calls = []
    monkeypatch.setattr(
        cap_mgr.logging_client,
        "write_audit_log",
        lambda **kw: calls.append(kw) or {},
    )

    cap_mgr.enforce_caps(
        period=PeriodType.DAILY,
        window_type=WindowType.ROLLING,
        max_tokens=100000,
        mock_entries=[entry("heavy@corp.com", 250000), entry("boss@corp.com", 250000)],
    )

    by_action = {}
    for c in calls:
        by_action.setdefault(c["action"], []).append(c)

    disallow = by_action[AuditAction.DISALLOW][0]
    assert disallow["user_id"] == "heavy@corp.com"
    assert "Tokens (250,000) exceeded limit (100,000)" in disallow["reason"]
    assert "in daily rolling window" in disallow["reason"]
    assert disallow["details"]["actual_tokens"] == 250000
    assert disallow["details"]["cap_tokens"] == 100000

    allow = by_action[AuditAction.ALLOW][0]
    assert allow["user_id"] == "recovering@corp.com"

    refused = by_action[AuditAction.DISALLOW_NOT_ENFORCEABLE][0]
    assert refused["user_id"] == "boss@corp.com"
    assert refused["reason_code"] == ReasonCode.PRIVILEGED_ROLE.value


def test_audit_log_records_withheld_reallow(monkeypatch):
    bindings = {CAP_ROLE: ["user:recovering@corp.com"]}
    cap_mgr, _ = make_manager(bindings)

    calls = []
    monkeypatch.setattr(
        cap_mgr.logging_client,
        "write_audit_log",
        lambda **kw: calls.append(kw) or {},
    )

    cap_mgr.enforce_caps(
        period=PeriodType.DAILY, max_tokens=100000, mock_entries=[]
    )

    actions = [c["action"] for c in calls]
    assert AuditAction.ALLOW_WITHHELD in actions
    assert AuditAction.ALLOW not in actions


def test_dry_run_leaves_policy_untouched():
    bindings = {DEFAULT_ALLOWED_ROLE: ["user:heavy@corp.com"]}
    cap_mgr, _ = make_manager(bindings)

    result = cap_mgr.enforce_caps(
        period=PeriodType.DAILY,
        max_tokens=1000,
        mock_entries=[entry("heavy@corp.com", 999999)],
        dry_run=True,
    )

    assert result.dry_run is True
    assert result.disallowed_users == ["heavy@corp.com"]
    assert bindings == {DEFAULT_ALLOWED_ROLE: ["user:heavy@corp.com"]}


def test_no_thresholds_is_a_noop():
    cap_mgr, _ = make_manager({DEFAULT_ALLOWED_ROLE: ["user:a@corp.com"]})
    result = cap_mgr.enforce_caps(period=PeriodType.DAILY)
    assert result.violations == []
    assert result.disallowed_users == []
    assert result.gates == []


def test_g4_circuit_breaker_exempts_restores_on_monthly_reset():
    """Bug 4 reproduction:
    Target scale is 300+ concurrent users.
    At monthly reset, >60 capped users (70) are restore candidates.
    G4 budget is max(10, 60) = 60. Restores must be exempt from G4 budget,
    and all 70 users must be restored in one run without aborting.
    """
    capped_users = [f"user:capped{i}@corp.com" for i in range(70)]
    allowed_users = [f"user:active{i}@corp.com" for i in range(230)]
    bindings = {
        CAP_ROLE: list(capped_users),
        DEFAULT_ALLOWED_ROLE: list(allowed_users),
    }
    cap_mgr, iam = make_manager(bindings)

    # Monthly reset: minimal usage so G3 passes
    mock_entries = [entry("active0@corp.com", 10)]

    result = cap_mgr.enforce_caps(
        period=PeriodType.MONTHLY,
        max_tokens=5000000,
        mock_entries=mock_entries,
        disallow_mode=DisallowMode.CUSTOM_ROLE,
        dry_run=False,
    )

    assert result.aborted is False
    assert result.gate(GateId.G4_CHANGE_BUDGET).passed is True
    assert len(result.allowed_users) == 70
    assert len(result.disallowed_users) == 0

    snap = iam.get_policy_snapshot()
    assert len(snap.members(CAP_ROLE)) == 0
    for u in capped_users:
        assert u in snap.members(DEFAULT_ALLOWED_ROLE)

