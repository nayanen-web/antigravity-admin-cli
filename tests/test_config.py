"""Unit tests for config module."""

import subprocess
from agy_admin.config import Settings, get_default_project, get_settings


def test_get_default_project_from_env(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "proj-from-gcp-project")
    assert get_default_project() == "proj-from-gcp-project"

    monkeypatch.delenv("GCP_PROJECT")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "proj-from-google-cloud-project")
    assert get_default_project() == "proj-from-google-cloud-project"


def test_get_default_project_from_gcloud(monkeypatch):
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)

    class MockProc:
        stdout = "proj-from-gcloud\n"

    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: MockProc())
    assert get_default_project() == "proj-from-gcloud"


def test_get_default_project_gcloud_unset_or_error(monkeypatch):
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)

    class MockUnsetProc:
        stdout = "(unset)\n"

    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: MockUnsetProc())
    assert get_default_project() is None

    def mock_raise(*args, **kwargs):
        raise FileNotFoundError("gcloud missing")

    monkeypatch.setattr(subprocess, "run", mock_raise)
    assert get_default_project() is None


def _clear(monkeypatch):
    for key in (
        "GCP_PROJECT",
        "GOOGLE_CLOUD_PROJECT",
        "AGY_LOG_ID",
        "AGY_ALLOWED_ROLE",
        "AGY_CAP_ROLE_ID",
        "AGY_ADMIN_ROLE_ID",
        "AGY_CUSTOM_RESTRICTED_ROLE_ID",
        "AGY_EXTRA_ACCESS_ROLES",
        "AGY_REQUIRE_ANCESTOR_CHECK",
        "AGY_ALLOW_GROUP_COEXISTENCE",
        "AGY_MAX_CHANGES_ABS",
        "AGY_MAX_CHANGES_RATIO",
    ):
        monkeypatch.delenv(key, raising=False)


def test_settings_defaults(monkeypatch):
    _clear(monkeypatch)

    s = Settings(project_id="explicit-proj")
    assert s.project_id == "explicit-proj"
    assert s.log_id == "businessaicode.googleapis.com/inference_response"
    assert s.allowed_role == "roles/discoveryengine.agentspaceUser"

    # Cap blocks and administrator blocks use distinct marker roles so the
    # automatic cycle can tell which of them it is allowed to undo.
    assert s.cap_role_id == "CustomAntigravityCapBlocked"
    assert s.admin_role_id == "CustomAntigravityAdminBlocked"
    assert s.legacy_role_id == "CustomAntigravityRestrictedUser"
    assert s.cap_role_id != s.admin_role_id

    assert "roles/owner" in s.privileged_roles
    assert "roles/discoveryengine.admin" in s.other_access_roles

    # Both opt-in behaviours default to the safe setting.
    assert s.require_ancestor_check is False
    assert s.allow_group_coexistence is False


def test_settings_env_overrides(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("AGY_LOG_ID", "custom/log/stream")
    monkeypatch.setenv("AGY_ALLOWED_ROLE", "roles/custom.allowed")
    monkeypatch.setenv("AGY_CAP_ROLE_ID", "MyCapRole")
    monkeypatch.setenv("AGY_ADMIN_ROLE_ID", "MyAdminRole")
    monkeypatch.setenv("AGY_CUSTOM_RESTRICTED_ROLE_ID", "MyLegacyRole")
    monkeypatch.setenv("AGY_EXTRA_ACCESS_ROLES", "roles/a.b, roles/c.d")
    monkeypatch.setenv("AGY_ALLOW_GROUP_COEXISTENCE", "true")
    monkeypatch.setenv("AGY_REQUIRE_ANCESTOR_CHECK", "yes")

    s = get_settings(project_id="test-proj-2")
    assert s.log_id == "custom/log/stream"
    assert s.allowed_role == "roles/custom.allowed"
    assert s.cap_role_id == "MyCapRole"
    assert s.admin_role_id == "MyAdminRole"
    assert s.legacy_role_id == "MyLegacyRole"
    assert "roles/a.b" in s.other_access_roles
    assert "roles/c.d" in s.other_access_roles
    assert s.allow_group_coexistence is True
    assert s.require_ancestor_check is True


def test_change_budget_is_the_larger_of_absolute_and_ratio(monkeypatch):
    _clear(monkeypatch)
    s = Settings(project_id="p")
    assert s.max_changes_abs == 10
    assert s.max_changes_ratio == 0.2

    # Small populations keep the absolute floor so routine work is not blocked.
    assert s.change_budget(10) == 10
    # Large populations scale with the ratio so a mass change trips the breaker.
    assert s.change_budget(200) == 40


def test_change_budget_env_overrides(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("AGY_MAX_CHANGES_ABS", "2")
    monkeypatch.setenv("AGY_MAX_CHANGES_RATIO", "0.5")
    s = Settings(project_id="p")
    assert s.change_budget(100) == 50
    assert s.change_budget(1) == 2


def test_invalid_numeric_env_falls_back_to_default(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("AGY_MAX_CHANGES_ABS", "not-a-number")
    monkeypatch.setenv("AGY_MAX_CHANGES_RATIO", "junk")
    s = Settings(project_id="p")
    assert s.max_changes_abs == 10
    assert s.max_changes_ratio == 0.2
