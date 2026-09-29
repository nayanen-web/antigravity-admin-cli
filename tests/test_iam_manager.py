"""Unit tests for the v0.2.0 IAM state model and enforcement guards."""

import subprocess

import pytest

from agy_admin.config import (
    DEFAULT_ADMIN_ROLE_ID,
    DEFAULT_ALLOWED_ROLE,
    DEFAULT_CAP_ROLE_ID,
    LEGACY_RESTRICTED_ROLE_ID,
)
from agy_admin.iam_manager import (
    IAMManager,
    is_collective_member,
    is_individual_member,
    normalize_email,
)
from agy_admin.models import DisallowMode, ReasonCode, UserStatus

PROJECT = "test-proj"
CAP_ROLE = f"projects/{PROJECT}/roles/{DEFAULT_CAP_ROLE_ID}"
ADMIN_ROLE = f"projects/{PROJECT}/roles/{DEFAULT_ADMIN_ROLE_ID}"
LEGACY_ROLE = f"projects/{PROJECT}/roles/{LEGACY_RESTRICTED_ROLE_ID}"


def make_iam(bindings, **kwargs) -> IAMManager:
    return IAMManager(project_id=PROJECT, mock_bindings=bindings, **kwargs)


# ---------------------------------------------------------------------------
# Member helpers
# ---------------------------------------------------------------------------


def test_normalize_email_strips_prefix_and_case():
    assert normalize_email("user:Alice.Kim@Corp.com") == "alice.kim@corp.com"
    assert normalize_email("deleted:user:bob@corp.com?uid=123") == "bob@corp.com"
    assert normalize_email("bare@corp.com") == "bare@corp.com"


def test_member_classification():
    assert is_individual_member("user:a@corp.com")
    assert is_individual_member("a@corp.com")
    assert not is_individual_member("group:team@corp.com")
    assert not is_individual_member("serviceAccount:sa@p.iam.gserviceaccount.com")
    assert is_collective_member("group:team@corp.com")
    assert is_collective_member("domain:corp.com")
    assert is_collective_member("allAuthenticatedUsers")
    assert not is_collective_member("user:a@corp.com")


# ---------------------------------------------------------------------------
# State classification
# ---------------------------------------------------------------------------


def test_state_classification_basic():
    iam = make_iam(
        {
            DEFAULT_ALLOWED_ROLE: ["user:alice@corp.com"],
            CAP_ROLE: ["user:capped@corp.com"],
            ADMIN_ROLE: ["user:blocked@corp.com"],
            "roles/owner": ["user:boss@corp.com"],
            "roles/discoveryengine.admin": ["user:deadmin@corp.com"],
        }
    )
    a = iam.evaluate_users(
        [
            "alice@corp.com",
            "capped@corp.com",
            "blocked@corp.com",
            "boss@corp.com",
            "deadmin@corp.com",
            "nobody@corp.com",
        ]
    )

    assert a["alice@corp.com"].status == UserStatus.ENFORCEABLE_ALLOWED
    assert a["capped@corp.com"].status == UserStatus.CAPPED_BY_TOOL
    assert a["blocked@corp.com"].status == UserStatus.BLOCKED_BY_ADMIN
    assert a["boss@corp.com"].status == UserStatus.NOT_ENFORCEABLE
    assert a["boss@corp.com"].reason == ReasonCode.PRIVILEGED_ROLE
    assert a["deadmin@corp.com"].status == UserStatus.NOT_ENFORCEABLE
    assert a["deadmin@corp.com"].reason == ReasonCode.OTHER_ACCESS_ROLE
    # A user with no binding at all is NOT_ACCESS, never "disallowed".
    assert a["nobody@corp.com"].status == UserStatus.NO_ACCESS


def test_legacy_marker_is_treated_as_admin_block():
    """v0.1.0 marker holders cannot be reclassified, so they are never auto-restored."""
    iam = make_iam({LEGACY_ROLE: ["user:legacy@corp.com"]})
    a = iam.evaluate_users(["legacy@corp.com"])
    assert a["legacy@corp.com"].status == UserStatus.BLOCKED_BY_ADMIN


def test_email_comparison_is_case_insensitive():
    iam = make_iam({DEFAULT_ALLOWED_ROLE: ["user:Alice.Kim@Corp.com"]})
    a = iam.evaluate_users(["alice.kim@corp.com"])
    assert a["alice.kim@corp.com"].status == UserStatus.ENFORCEABLE_ALLOWED


def test_conflicting_bindings_are_not_enforceable():
    iam = make_iam(
        {
            DEFAULT_ALLOWED_ROLE: ["user:dual@corp.com"],
            CAP_ROLE: ["user:dual@corp.com"],
        }
    )
    a = iam.evaluate_users(["dual@corp.com"])
    assert a["dual@corp.com"].status == UserStatus.NOT_ENFORCEABLE
    assert a["dual@corp.com"].reason == ReasonCode.CONFLICTING_BINDINGS


def test_conditional_grant_is_not_enforceable():
    iam = IAMManager(project_id=PROJECT)
    snap = iam._snapshot_from_json(
        {
            "bindings": [
                {
                    "role": DEFAULT_ALLOWED_ROLE,
                    "members": ["user:cond@corp.com"],
                    "condition": {"title": "biz-hours", "expression": "true"},
                }
            ]
        }
    )
    iam._snapshot = snap
    a = iam.evaluate_users(["cond@corp.com"])
    assert a["cond@corp.com"].status == UserStatus.NOT_ENFORCEABLE
    assert a["cond@corp.com"].reason == ReasonCode.CONFLICTING_BINDINGS


def test_duplicate_role_bindings_are_merged_not_overwritten():
    """One unconditional plus one conditional binding for the same role is legal."""
    iam = IAMManager(project_id=PROJECT)
    snap = iam._snapshot_from_json(
        {
            "bindings": [
                {"role": DEFAULT_ALLOWED_ROLE, "members": ["user:a@corp.com"]},
                {
                    "role": DEFAULT_ALLOWED_ROLE,
                    "members": ["user:b@corp.com"],
                    "condition": {"title": "t", "expression": "true"},
                },
            ]
        }
    )
    assert snap.members(DEFAULT_ALLOWED_ROLE) == {
        "user:a@corp.com",
        "user:b@corp.com",
    }
    assert snap.conditional_members[DEFAULT_ALLOWED_ROLE] == {"user:b@corp.com"}


# ---------------------------------------------------------------------------
# Group / domain grants (v0.1.0 reported these as successfully blocked)
# ---------------------------------------------------------------------------


def test_group_grant_makes_every_user_not_enforceable():
    iam = make_iam(
        {
            DEFAULT_ALLOWED_ROLE: [
                "group:ai-users@corp.com",
                "user:alice@corp.com",
            ]
        }
    )
    a = iam.evaluate_users(["alice@corp.com", "grouponly@corp.com"])
    for uid in ("alice@corp.com", "grouponly@corp.com"):
        assert a[uid].status == UserStatus.NOT_ENFORCEABLE
        assert a[uid].reason == ReasonCode.GROUP_GRANT_PRESENT
    assert iam.has_collective_grant() is True


def test_group_grant_refuses_disallow_and_leaves_policy_untouched():
    bindings = {
        DEFAULT_ALLOWED_ROLE: ["group:ai-users@corp.com", "user:alice@corp.com"]
    }
    iam = make_iam(bindings)
    outcome = iam.disallow_users(["alice@corp.com"])

    assert outcome.applied == []
    assert [r.user_id for r in outcome.refused] == ["alice@corp.com"]
    assert outcome.refused[0].reason == ReasonCode.GROUP_GRANT_PRESENT
    # No marker role was created and the individual binding is intact.
    assert CAP_ROLE not in bindings and ADMIN_ROLE not in bindings
    assert "user:alice@corp.com" in bindings[DEFAULT_ALLOWED_ROLE]


def test_group_coexistence_optout_restores_enforcement():
    iam = make_iam(
        {DEFAULT_ALLOWED_ROLE: ["group:ai-users@corp.com", "user:alice@corp.com"]},
        allow_group_coexistence=True,
    )
    a = iam.evaluate_users(["alice@corp.com"])
    assert a["alice@corp.com"].status == UserStatus.ENFORCEABLE_ALLOWED


# ---------------------------------------------------------------------------
# Unreadable policy must never look like "nobody has access"
# ---------------------------------------------------------------------------


def test_unreadable_policy_yields_unknown(monkeypatch):
    iam = IAMManager(project_id=PROJECT)
    monkeypatch.setattr(iam, "_get_resourcemanager_client", lambda: None)

    def boom(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ["gcloud"], stderr="Permission denied")

    monkeypatch.setattr("subprocess.run", boom)

    snap = iam.get_policy_snapshot()
    assert snap.readable is False
    assert snap.bindings == {}

    a = iam.evaluate_users(["alice@corp.com"])
    assert a["alice@corp.com"].status == UserStatus.UNKNOWN
    assert a["alice@corp.com"].reason == ReasonCode.POLICY_UNREADABLE


def test_unreadable_policy_refuses_all_manual_actions(monkeypatch):
    iam = IAMManager(project_id=PROJECT)
    monkeypatch.setattr(iam, "_get_resourcemanager_client", lambda: None)
    monkeypatch.setattr(
        "subprocess.run",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no gcloud")),
    )

    out = iam.allow_users(["alice@corp.com"], dry_run=True)
    assert out.applied == []
    assert out.refused[0].reason == ReasonCode.POLICY_UNREADABLE


# ---------------------------------------------------------------------------
# Disallow
# ---------------------------------------------------------------------------


def test_disallow_custom_role_applies_admin_marker_by_default():
    bindings = {DEFAULT_ALLOWED_ROLE: ["user:alice@corp.com"]}
    iam = make_iam(bindings)
    outcome = iam.disallow_users(["alice@corp.com"], mode=DisallowMode.CUSTOM_ROLE)

    assert outcome.applied == ["alice@corp.com"]
    assert "user:alice@corp.com" not in bindings[DEFAULT_ALLOWED_ROLE]
    assert "user:alice@corp.com" in bindings[ADMIN_ROLE]


def test_disallow_with_cap_marker_is_auto_restorable():
    bindings = {DEFAULT_ALLOWED_ROLE: ["user:alice@corp.com"]}
    iam = make_iam(bindings)
    iam.disallow_users(["alice@corp.com"], marker_role=iam.cap_role)

    assert "user:alice@corp.com" in bindings[CAP_ROLE]
    assert iam.evaluate_users(["alice@corp.com"])["alice@corp.com"].status == (
        UserStatus.CAPPED_BY_TOOL
    )


def test_disallow_revoke_mode_leaves_no_marker():
    bindings = {DEFAULT_ALLOWED_ROLE: ["user:alice@corp.com", "user:bob@corp.com"]}
    iam = make_iam(bindings)
    outcome = iam.disallow_users(["alice@corp.com"], mode=DisallowMode.REVOKE)

    assert outcome.applied == ["alice@corp.com"]
    assert "user:alice@corp.com" not in bindings[DEFAULT_ALLOWED_ROLE]
    assert "user:bob@corp.com" in bindings[DEFAULT_ALLOWED_ROLE]
    assert CAP_ROLE not in bindings
    assert ADMIN_ROLE not in bindings


def test_disallow_noop_for_users_without_access():
    bindings = {DEFAULT_ALLOWED_ROLE: ["user:alice@corp.com"]}
    iam = make_iam(bindings)
    outcome = iam.disallow_users(["ghost@corp.com"])
    assert outcome.applied == []
    assert outcome.no_op == ["ghost@corp.com"]
    assert outcome.refused == []


def test_disallow_refuses_privileged_user():
    bindings = {
        "roles/owner": ["user:boss@corp.com"],
        DEFAULT_ALLOWED_ROLE: ["user:dev@corp.com"],
    }
    iam = make_iam(bindings)
    outcome = iam.disallow_users(["boss@corp.com", "dev@corp.com"])

    assert outcome.applied == ["dev@corp.com"]
    assert [r.user_id for r in outcome.refused] == ["boss@corp.com"]
    assert "user:boss@corp.com" in bindings["roles/owner"]


def test_disallow_never_acts_on_uncontrollable_user():
    """Regression: there is no escape hatch that mutates IAM for these users.

    Previously ``--force`` removed the base binding and added a marker role.
    For a group-granted user that removed nothing and granted a new role,
    while still reporting a successful block.
    """
    bindings = {
        "roles/owner": ["user:boss@corp.com"],
        DEFAULT_ALLOWED_ROLE: ["user:boss@corp.com"],
    }
    iam = make_iam(bindings)
    outcome = iam.disallow_users(["boss@corp.com"])

    assert outcome.applied == []
    assert [r.user_id for r in outcome.refused] == ["boss@corp.com"]
    # Nothing was touched: no binding removed, no marker granted.
    assert "user:boss@corp.com" in bindings[DEFAULT_ALLOWED_ROLE]
    assert "user:boss@corp.com" in bindings["roles/owner"]
    assert "user:boss@corp.com" not in bindings.get(ADMIN_ROLE, [])


def test_disallow_on_group_granted_user_grants_no_marker_role():
    """A block we cannot deliver must not add permissions to the account."""
    bindings = {DEFAULT_ALLOWED_ROLE: ["group:team@corp.com"]}
    iam = make_iam(bindings)
    outcome = iam.disallow_users(["alice@corp.com"])

    assert outcome.applied == []
    assert outcome.refused[0].reason == ReasonCode.GROUP_GRANT_PRESENT
    # The account must not end up holding the admin marker role.
    assert "user:alice@corp.com" not in bindings.get(ADMIN_ROLE, [])


def test_refusal_detail_tells_operator_what_to_do():
    bindings = {DEFAULT_ALLOWED_ROLE: ["group:team@corp.com"]}
    iam = make_iam(bindings)
    outcome = iam.disallow_users(["alice@corp.com"])

    assert "group" in outcome.refused[0].detail.lower()


def test_dry_run_makes_no_change():
    bindings = {DEFAULT_ALLOWED_ROLE: ["user:alice@corp.com"]}
    iam = make_iam(bindings)
    outcome = iam.disallow_users(["alice@corp.com"], dry_run=True)

    assert outcome.applied == ["alice@corp.com"]
    assert bindings == {DEFAULT_ALLOWED_ROLE: ["user:alice@corp.com"]}


# ---------------------------------------------------------------------------
# Allow
# ---------------------------------------------------------------------------


def test_allow_restores_capped_user_and_clears_markers():
    bindings = {CAP_ROLE: ["user:alice@corp.com"]}
    iam = make_iam(bindings)
    outcome = iam.allow_users(["alice@corp.com"])

    assert outcome.applied == ["alice@corp.com"]
    assert "user:alice@corp.com" in bindings[DEFAULT_ALLOWED_ROLE]
    assert "user:alice@corp.com" not in bindings[CAP_ROLE]


def test_allow_is_noop_for_already_allowed_user():
    bindings = {DEFAULT_ALLOWED_ROLE: ["user:alice@corp.com"]}
    iam = make_iam(bindings)
    outcome = iam.allow_users(["alice@corp.com"])
    assert outcome.applied == []
    assert outcome.no_op == ["alice@corp.com"]


def test_allow_always_refuses_not_enforceable():
    bindings = {
        DEFAULT_ALLOWED_ROLE: ["group:team@corp.com"],
    }
    iam = make_iam(bindings)
    outcome = iam.allow_users(["alice@corp.com"])
    assert outcome.applied == []
    assert outcome.refused[0].reason == ReasonCode.GROUP_GRANT_PRESENT
    # No individual binding is created for an account we cannot classify.
    assert bindings[DEFAULT_ALLOWED_ROLE] == ["group:team@corp.com"]


def test_round_trip_disallow_then_allow_returns_to_start():
    bindings = {DEFAULT_ALLOWED_ROLE: ["user:alice@corp.com"]}
    iam = make_iam(bindings)

    iam.disallow_users(["alice@corp.com"], marker_role=iam.cap_role)
    assert bindings.get(DEFAULT_ALLOWED_ROLE) == []
    iam.allow_users(["alice@corp.com"])

    assert bindings[DEFAULT_ALLOWED_ROLE] == ["user:alice@corp.com"]
    assert bindings[CAP_ROLE] == []
    assert iam.evaluate_users(["alice@corp.com"])["alice@corp.com"].status == (
        UserStatus.ENFORCEABLE_ALLOWED
    )


# ---------------------------------------------------------------------------
# Role listings
# ---------------------------------------------------------------------------


def test_role_listings_exclude_groups_and_service_accounts():
    iam = make_iam(
        {
            CAP_ROLE: [
                "user:charlie@corp.com",
                "user:alice@corp.com",
                "serviceAccount:sa@test-proj.iam.gserviceaccount.com",
                "group:team@corp.com",
                "bob@corp.com",
            ],
            ADMIN_ROLE: ["user:zed@corp.com"],
            LEGACY_ROLE: ["user:legacy@corp.com"],
        }
    )
    assert iam.get_capped_users() == [
        "alice@corp.com",
        "bob@corp.com",
        "charlie@corp.com",
    ]
    assert iam.get_admin_blocked_users() == ["legacy@corp.com", "zed@corp.com"]


# ---------------------------------------------------------------------------
# Policy I/O
# ---------------------------------------------------------------------------


def test_policy_is_read_at_version_3_and_written_once(monkeypatch):
    from unittest.mock import create_autospec

    from google.cloud import resourcemanager_v3
    from google.iam.v1 import iam_policy_pb2, policy_pb2

    mock_client = create_autospec(resourcemanager_v3.ProjectsClient, instance=True)
    policy = policy_pb2.Policy(version=3, etag=b"test-etag")
    b1 = policy.bindings.add()
    b1.role = DEFAULT_ALLOWED_ROLE
    b1.members.append("user:existing@corp.com")
    mock_client.get_iam_policy.return_value = policy

    iam = IAMManager(project_id=PROJECT)
    monkeypatch.setattr(iam, "_get_resourcemanager_client", lambda: mock_client)

    from agy_admin.iam_manager import BindingOp

    iam.apply_ops(
        [
            BindingOp("remove", "user:existing@corp.com", DEFAULT_ALLOWED_ROLE),
            BindingOp("add", "user:newbie@corp.com", CAP_ROLE),
        ]
    )

    # Reading at version 1 would strip conditional bindings on write.
    read_req = mock_client.get_iam_policy.call_args[1]["request"]
    assert isinstance(read_req, iam_policy_pb2.GetIamPolicyRequest)
    assert read_req.options.requested_policy_version == 3

    # Both ops land in a single setIamPolicy call.
    mock_client.set_iam_policy.assert_called_once()
    req = mock_client.set_iam_policy.call_args[1]["request"]
    assert isinstance(req, iam_policy_pb2.SetIamPolicyRequest)
    assert req.policy.version == 3
    roles = {b.role: list(b.members) for b in req.policy.bindings}
    # The emptied binding is pruned; setIamPolicy rejects memberless bindings.
    assert DEFAULT_ALLOWED_ROLE not in roles
    assert roles[CAP_ROLE] == ["user:newbie@corp.com"]


def test_conditional_bindings_are_not_edited_in_place(monkeypatch):
    from unittest.mock import create_autospec

    from google.cloud import resourcemanager_v3
    from google.iam.v1 import policy_pb2

    mock_client = create_autospec(resourcemanager_v3.ProjectsClient, instance=True)
    policy = policy_pb2.Policy(version=3)
    cond = policy.bindings.add()
    cond.role = DEFAULT_ALLOWED_ROLE
    cond.members.append("user:cond@corp.com")
    cond.condition.title = "biz-hours"
    cond.condition.expression = "true"
    mock_client.get_iam_policy.return_value = policy

    iam = IAMManager(project_id=PROJECT)
    monkeypatch.setattr(iam, "_get_resourcemanager_client", lambda: mock_client)

    from agy_admin.iam_manager import BindingOp

    iam.apply_ops([BindingOp("add", "user:new@corp.com", DEFAULT_ALLOWED_ROLE)])

    req = mock_client.set_iam_policy.call_args[1]["request"]
    conditional = [b for b in req.policy.bindings if b.condition.title]
    unconditional = [b for b in req.policy.bindings if not b.condition.title]
    assert list(conditional[0].members) == ["user:cond@corp.com"]
    assert list(unconditional[0].members) == ["user:new@corp.com"]


def test_gcloud_fallback_failure_propagates(monkeypatch):
    from unittest.mock import MagicMock

    from agy_admin.iam_manager import BindingOp

    mock_client = MagicMock()
    mock_client.get_iam_policy.side_effect = RuntimeError("SDK network error")

    def missing_gcloud(*args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory: 'gcloud'")

    monkeypatch.setattr("subprocess.run", missing_gcloud)

    iam = IAMManager(project_id=PROJECT)
    monkeypatch.setattr(iam, "_get_resourcemanager_client", lambda: mock_client)

    with pytest.raises(FileNotFoundError):
        iam.apply_ops([BindingOp("remove", "user:dummy@corp.com", DEFAULT_ALLOWED_ROLE)])
