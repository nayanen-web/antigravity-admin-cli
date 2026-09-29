"""Configuration settings for agy-admin."""

import os
import subprocess
from typing import List, Optional, Tuple

#: Base role that grants Antigravity / AI developer tools access.
DEFAULT_ALLOWED_ROLE = "roles/discoveryengine.agentspaceUser"

#: Marker role applied when this tool blocks a user for exceeding a cap.
#: Eligible for automatic restoration.
DEFAULT_CAP_ROLE_ID = "CustomAntigravityCapBlocked"

#: Marker role applied when an administrator blocks a user manually.
#: Never restored automatically.
DEFAULT_ADMIN_ROLE_ID = "CustomAntigravityAdminBlocked"

#: v0.1.0 single marker role. Its holders cannot be classified retroactively,
#: so they are treated conservatively as administrator blocks.
LEGACY_RESTRICTED_ROLE_ID = "CustomAntigravityRestrictedUser"

#: Roles that grant broad project control. Users holding them are never
#: modified by this tool.
DEFAULT_PRIVILEGED_ROLES: Tuple[str, ...] = (
    "roles/owner",
    "roles/editor",
)

#: Additional roles that can grant Antigravity access independently of the
#: base role. Users holding them cannot be blocked by removing the base role.
DEFAULT_OTHER_ACCESS_ROLES: Tuple[str, ...] = (
    "roles/discoveryengine.admin",
    "roles/discoveryengine.editor",
    "roles/discoveryengine.agentspaceAdmin",
)


def _split_roles(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [r.strip() for r in value.replace(";", ",").split(",") if r.strip()]


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("true", "1", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def get_default_project() -> Optional[str]:
    """Detect default GCP project from environment or gcloud config."""
    project = os.environ.get("GCP_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
    if project:
        return project.strip()
    try:
        proc = subprocess.run(
            ["gcloud", "config", "get-value", "project"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        val = proc.stdout.strip()
        if val and val != "(unset)":
            return val
    except Exception:
        pass
    return None


class Settings:
    def __init__(self, project_id: Optional[str] = None):
        self.project_id = project_id or get_default_project() or "default-project"
        self.log_id = os.environ.get(
            "AGY_LOG_ID", "businessaicode.googleapis.com/inference_response"
        )
        self.allowed_role = os.environ.get("AGY_ALLOWED_ROLE", DEFAULT_ALLOWED_ROLE)

        self.cap_role_id = os.environ.get("AGY_CAP_ROLE_ID", DEFAULT_CAP_ROLE_ID)
        self.admin_role_id = os.environ.get("AGY_ADMIN_ROLE_ID", DEFAULT_ADMIN_ROLE_ID)
        self.legacy_role_id = os.environ.get(
            "AGY_CUSTOM_RESTRICTED_ROLE_ID", LEGACY_RESTRICTED_ROLE_ID
        )

        self.privileged_roles = list(DEFAULT_PRIVILEGED_ROLES)
        self.other_access_roles = list(DEFAULT_OTHER_ACCESS_ROLES) + _split_roles(
            os.environ.get("AGY_EXTRA_ACCESS_ROLES")
        )

        # Q3: ancestor (organization/folder) policy inspection is opt-in because
        # it requires additional permissions the batch SA may not hold.
        self.require_ancestor_check = _env_bool("AGY_REQUIRE_ANCESTOR_CHECK", False)

        # Q1: treat individually-bound users as enforceable even when the
        # allowed role also has group/domain members. Off by default.
        self.allow_group_coexistence = _env_bool("AGY_ALLOW_GROUP_COEXISTENCE", False)

        # Q5: circuit breaker. A cycle aborts if it would change more than
        # max(abs, ratio * population) bindings.
        self.max_changes_abs = _env_int("AGY_MAX_CHANGES_ABS", 10)
        self.max_changes_ratio = _env_float("AGY_MAX_CHANGES_RATIO", 0.2)

    def change_budget(self, population: int) -> int:
        return max(self.max_changes_abs, int(population * self.max_changes_ratio))


def get_settings(project_id: Optional[str] = None) -> Settings:
    return Settings(project_id=project_id)
