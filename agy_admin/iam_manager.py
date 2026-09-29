"""Google Cloud IAM access management for Gemini Enterprise / Antigravity users.

v0.2.0 decision rules
---------------------
The previous implementation answered a single question ("does this user hold a
``user:`` binding of the allowed role?") and acted on the answer unconditionally.
That silently mislabelled every user whose access came from a group, a domain
binding, an inherited binding, or another access-granting role, and reported
failed enforcement as success.

This module now answers a different question: *can this tool actually control
this user's access, and how do we know?* When the answer is "no" or "cannot
tell", no mutation is performed and the reason is recorded.
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Set

from agy_admin.config import (
    DEFAULT_ADMIN_ROLE_ID,
    DEFAULT_ALLOWED_ROLE,
    DEFAULT_CAP_ROLE_ID,
    DEFAULT_OTHER_ACCESS_ROLES,
    DEFAULT_PRIVILEGED_ROLES,
    LEGACY_RESTRICTED_ROLE_ID,
)
from agy_admin.models import (
    ActionOutcome,
    DisallowMode,
    MANUAL_ALLOW_STATES,
    MANUAL_DISALLOW_STATES,
    ReasonCode,
    RefusedAction,
    UserAssessment,
    UserStatus,
)

logger = logging.getLogger(__name__)

#: Member prefixes that identify a principal this tool can address individually.
_INDIVIDUAL_PREFIX = "user:"

#: Prefixes that represent an access path this tool cannot revoke per-user.
_COLLECTIVE_PREFIXES = ("group:", "domain:", "principalSet:", "allUsers", "allAuthenticatedUsers")


def normalize_email(value: str) -> str:
    """Lower-cases and strips a principal, dropping a leading type prefix.

    IAM stores member emails case-insensitively; the previous implementation
    compared raw strings and therefore missed ``user:Alice.Kim@corp.com``.
    """
    v = (value or "").strip()
    for prefix in ("user:", "serviceAccount:", "group:", "domain:", "deleted:user:"):
        if v.lower().startswith(prefix.lower()):
            v = v[len(prefix) :]
            break
    # deleted principals carry a ?uid= suffix
    if "?uid=" in v:
        v = v.split("?uid=", 1)[0]
    return v.lower()


def is_individual_member(member: str) -> bool:
    """True when the member is an individually addressable human principal."""
    m = (member or "").strip()
    if m.lower().startswith(_INDIVIDUAL_PREFIX):
        return True
    # Tolerate bare emails (used by fixtures and some exports).
    return "@" in m and ":" not in m


def is_collective_member(member: str) -> bool:
    m = (member or "").strip().lower()
    return any(m.startswith(p.lower()) for p in _COLLECTIVE_PREFIXES)


class BindingOp(NamedTuple):
    """A single additive or subtractive IAM binding change."""

    action: str  # "add" | "remove"
    member: str
    role: str


@dataclass
class PolicySnapshot:
    """One consistent read of the project's IAM policy.

    ``readable`` is false when the policy could not be retrieved. Callers must
    treat that as "unknown", never as "no bindings" - the previous code
    returned an empty dict on failure, which classified every user as blocked
    and made the next cycle grant access to all of them.
    """

    bindings: Dict[str, Set[str]] = field(default_factory=dict)
    conditional_members: Dict[str, Set[str]] = field(default_factory=dict)
    readable: bool = True
    error: str = ""
    ancestor_checked: bool = True
    ancestor_grant_present: bool = False

    def members(self, role: str) -> Set[str]:
        return self.bindings.get(role, set())


class IAMManager:
    def __init__(
        self,
        project_id: str,
        allowed_role: str = DEFAULT_ALLOWED_ROLE,
        cap_role_id: str = DEFAULT_CAP_ROLE_ID,
        admin_role_id: str = DEFAULT_ADMIN_ROLE_ID,
        legacy_role_id: str = LEGACY_RESTRICTED_ROLE_ID,
        privileged_roles: Optional[Sequence[str]] = None,
        other_access_roles: Optional[Sequence[str]] = None,
        require_ancestor_check: bool = False,
        allow_group_coexistence: bool = False,
        mock_bindings: Optional[Dict[str, List[str]]] = None,
    ):
        self.project_id = project_id
        self.allowed_role = allowed_role
        self.cap_role = self._qualify(cap_role_id)
        self.admin_role = self._qualify(admin_role_id)
        self.legacy_role = self._qualify(legacy_role_id)
        self.privileged_roles = list(privileged_roles or DEFAULT_PRIVILEGED_ROLES)
        self.other_access_roles = list(other_access_roles or DEFAULT_OTHER_ACCESS_ROLES)
        self.require_ancestor_check = require_ancestor_check
        self.allow_group_coexistence = allow_group_coexistence
        self._mock_bindings = mock_bindings
        self._snapshot: Optional[PolicySnapshot] = None

    # ------------------------------------------------------------------
    # Role helpers
    # ------------------------------------------------------------------

    def _qualify(self, role_id: str) -> str:
        if role_id.startswith("projects/") or role_id.startswith("roles/") or role_id.startswith(
            "organizations/"
        ):
            return role_id
        return f"projects/{self.project_id}/roles/{role_id}"

    @property
    def marker_roles(self) -> List[str]:
        return [self.cap_role, self.admin_role, self.legacy_role]

    @property
    def access_granting_roles(self) -> List[str]:
        roles = [self.allowed_role] + self.privileged_roles + self.other_access_roles
        # de-duplicate, preserve order
        seen, out = set(), []
        for r in roles:
            if r not in seen:
                seen.add(r)
                out.append(r)
        return out

    # ------------------------------------------------------------------
    # Policy retrieval
    # ------------------------------------------------------------------

    def get_policy_snapshot(self, refresh: bool = False) -> PolicySnapshot:
        """Reads the project IAM policy once and caches it for the cycle."""
        if self._snapshot is not None and not refresh:
            return self._snapshot

        if self._mock_bindings is not None:
            snap = PolicySnapshot(
                bindings={r: set(m) for r, m in self._mock_bindings.items()},
                readable=True,
            )
            snap.ancestor_checked = not self.require_ancestor_check
            self._snapshot = snap
            return snap

        snap = self._read_policy()
        if snap.readable and self.require_ancestor_check:
            self._check_ancestors(snap)
        elif snap.readable:
            snap.ancestor_checked = True
        self._snapshot = snap
        return snap

    def _read_policy(self) -> PolicySnapshot:
        try:
            policy = self._get_policy_proto()
            if policy is not None:
                return self._snapshot_from_proto(policy)
        except Exception as e:  # noqa: BLE001 - fall through to CLI
            logger.debug("SDK get_iam_policy failed (%s), trying gcloud CLI", e)

        try:
            cmd = [
                "gcloud",
                "projects",
                "get-iam-policy",
                self.project_id,
                "--format=json",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return self._snapshot_from_json(json.loads(proc.stdout))
        except Exception as e:  # noqa: BLE001
            logger.error("Failed to retrieve IAM policy for %s: %s", self.project_id, e)
            return PolicySnapshot(readable=False, error=str(e))

    def _snapshot_from_proto(self, policy) -> PolicySnapshot:
        snap = PolicySnapshot()
        for b in policy.bindings:
            # Duplicate role entries are legal (one unconditional plus one or
            # more conditional). The previous code overwrote the dict entry and
            # silently dropped members.
            bucket = snap.bindings.setdefault(b.role, set())
            bucket.update(b.members)
            if b.condition.expression or b.condition.title:
                snap.conditional_members.setdefault(b.role, set()).update(b.members)
        return snap

    def _snapshot_from_json(self, data: dict) -> PolicySnapshot:
        snap = PolicySnapshot()
        for b in data.get("bindings", []):
            role = b.get("role")
            if not role:
                continue
            bucket = snap.bindings.setdefault(role, set())
            bucket.update(b.get("members", []))
            if b.get("condition"):
                snap.conditional_members.setdefault(role, set()).update(
                    b.get("members", [])
                )
        return snap

    def _get_resourcemanager_client(self):
        try:
            from google.cloud import resourcemanager_v3

            return resourcemanager_v3.ProjectsClient()
        except Exception as e:  # noqa: BLE001
            logger.debug("ProjectsClient initialization failed: %s", e)
            return None

    def _get_policy_proto(self, client=None):
        """Fetches the policy with requested_policy_version=3.

        Reading at version 1 masks conditional bindings; writing that masked
        policy back would delete every condition on the project.
        """
        client = client or self._get_resourcemanager_client()
        if client is None:
            return None
        from google.iam.v1 import iam_policy_pb2, options_pb2

        req = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{self.project_id}",
            options=options_pb2.GetPolicyOptions(requested_policy_version=3),
        )
        return client.get_iam_policy(request=req)

    def _check_ancestors(self, snap: PolicySnapshot) -> None:
        """Looks for access-granting bindings on parent folders/organizations."""
        try:
            from google.cloud import resourcemanager_v3

            projects = resourcemanager_v3.ProjectsClient()
            project = projects.get_project(name=f"projects/{self.project_id}")
            parent = project.parent
            watched = set(self.access_granting_roles)
            while parent:
                if parent.startswith("folders/"):
                    client = resourcemanager_v3.FoldersClient()
                    policy = client.get_iam_policy(resource=parent)
                    nxt = client.get_folder(name=parent).parent
                elif parent.startswith("organizations/"):
                    client = resourcemanager_v3.OrganizationsClient()
                    policy = client.get_iam_policy(resource=parent)
                    nxt = ""
                else:
                    break
                for b in policy.bindings:
                    if b.role in watched and b.members:
                        snap.ancestor_grant_present = True
                parent = nxt
            snap.ancestor_checked = True
        except Exception as e:  # noqa: BLE001
            logger.warning("Ancestor policy check failed: %s", e)
            snap.ancestor_checked = False

    # ------------------------------------------------------------------
    # State decision rules (R1..R9)
    # ------------------------------------------------------------------

    def _individual_emails(self, snap: PolicySnapshot, role: str) -> Set[str]:
        return {
            normalize_email(m)
            for m in snap.members(role)
            if is_individual_member(m)
        }

    def _has_collective_grant(self, snap: PolicySnapshot) -> bool:
        for role in self.access_granting_roles:
            for m in snap.members(role):
                if is_collective_member(m):
                    return True
        return False

    def has_collective_grant(self, snap: Optional[PolicySnapshot] = None) -> bool:
        """True when any access-granting role has a group/domain/allUsers member.

        In that situation removing a user's individual binding does not prove
        that access was revoked, so enforcement claims must be suppressed.
        """
        return self._has_collective_grant(snap or self.get_policy_snapshot())

    def evaluate_users(self, user_ids: Iterable[str]) -> Dict[str, UserAssessment]:
        """Classifies each user according to the v0.2.0 decision rules."""
        snap = self.get_policy_snapshot()
        result: Dict[str, UserAssessment] = {}

        # R1 - the policy could not be read: nothing is knowable.
        if not snap.readable:
            for uid in user_ids:
                result[uid] = UserAssessment(
                    user_id=uid,
                    status=UserStatus.UNKNOWN,
                    reason=ReasonCode.POLICY_UNREADABLE,
                )
            return result

        # R2 - inherited bindings could not be ruled out.
        if not snap.ancestor_checked:
            for uid in user_ids:
                result[uid] = UserAssessment(
                    user_id=uid,
                    status=UserStatus.UNKNOWN,
                    reason=ReasonCode.ANCESTOR_UNCHECKED,
                )
            return result

        allowed = self._individual_emails(snap, self.allowed_role)
        capped = self._individual_emails(snap, self.cap_role)
        admin_blocked = self._individual_emails(snap, self.admin_role)
        legacy_blocked = self._individual_emails(snap, self.legacy_role)
        privileged = set()
        for r in self.privileged_roles:
            privileged |= self._individual_emails(snap, r)
        other_access = set()
        for r in self.other_access_roles:
            other_access |= self._individual_emails(snap, r)
        conditional_allowed = {
            normalize_email(m)
            for m in snap.conditional_members.get(self.allowed_role, set())
        }

        collective_grant = self._has_collective_grant(snap)
        inherited_grant = snap.ancestor_grant_present

        for uid in user_ids:
            email = normalize_email(uid)

            # R3 - privileged or other access-granting roles.
            if email in privileged:
                result[uid] = UserAssessment(
                    user_id=uid,
                    status=UserStatus.NOT_ENFORCEABLE,
                    reason=ReasonCode.PRIVILEGED_ROLE,
                )
                continue
            if email in other_access:
                result[uid] = UserAssessment(
                    user_id=uid,
                    status=UserStatus.NOT_ENFORCEABLE,
                    reason=ReasonCode.OTHER_ACCESS_ROLE,
                )
                continue

            is_allowed = email in allowed
            is_capped = email in capped
            is_admin_blocked = email in admin_blocked or email in legacy_blocked

            # R4 - allowed and blocked at the same time: ambiguous, do not act.
            if is_allowed and (is_capped or is_admin_blocked):
                result[uid] = UserAssessment(
                    user_id=uid,
                    status=UserStatus.NOT_ENFORCEABLE,
                    reason=ReasonCode.CONFLICTING_BINDINGS,
                )
                continue

            # A conditional grant of the base role cannot be revoked by editing
            # the unconditional binding.
            if email in conditional_allowed:
                result[uid] = UserAssessment(
                    user_id=uid,
                    status=UserStatus.NOT_ENFORCEABLE,
                    reason=ReasonCode.CONFLICTING_BINDINGS,
                )
                continue

            # R2b - an ancestor grant may cover this user; membership is not
            # verifiable from the project policy alone.
            if inherited_grant:
                result[uid] = UserAssessment(
                    user_id=uid,
                    status=UserStatus.NOT_ENFORCEABLE,
                    reason=ReasonCode.INHERITED_BINDING,
                )
                continue

            # R5 - a group/domain grant exists on an access-granting role.
            # Removing an individual binding does not guarantee revocation, so
            # unless the operator opted out we refuse to claim enforcement.
            if collective_grant and not self.allow_group_coexistence:
                result[uid] = UserAssessment(
                    user_id=uid,
                    status=UserStatus.NOT_ENFORCEABLE,
                    reason=ReasonCode.GROUP_GRANT_PRESENT,
                )
                continue

            # R6..R9
            if is_allowed:
                result[uid] = UserAssessment(
                    user_id=uid, status=UserStatus.ENFORCEABLE_ALLOWED
                )
            elif is_admin_blocked:
                result[uid] = UserAssessment(
                    user_id=uid, status=UserStatus.BLOCKED_BY_ADMIN
                )
            elif is_capped:
                result[uid] = UserAssessment(
                    user_id=uid, status=UserStatus.CAPPED_BY_TOOL
                )
            else:
                result[uid] = UserAssessment(user_id=uid, status=UserStatus.NO_ACCESS)

        return result

    def get_users_status(self, user_ids: Iterable[str]) -> Dict[str, UserStatus]:
        return {u: a.status for u, a in self.evaluate_users(user_ids).items()}

    def list_role_users(self, role: str) -> List[str]:
        snap = self.get_policy_snapshot()
        if not snap.readable:
            return []
        return sorted(self._individual_emails(snap, role))

    def get_capped_users(self) -> List[str]:
        """Users blocked by this tool for exceeding a cap."""
        return self.list_role_users(self.cap_role)

    def get_admin_blocked_users(self) -> List[str]:
        """Users blocked manually, including legacy v0.1.0 marker holders."""
        return sorted(
            set(self.list_role_users(self.admin_role))
            | set(self.list_role_users(self.legacy_role))
        )

    # ------------------------------------------------------------------
    # Change planning and application
    # ------------------------------------------------------------------

    def build_disallow_ops(
        self, user_id: str, marker_role: Optional[str]
    ) -> List[BindingOp]:
        """Ops that revoke the base role and optionally apply a marker role."""
        snap = self.get_policy_snapshot()
        email = normalize_email(user_id)
        ops: List[BindingOp] = []
        for m in snap.members(self.allowed_role):
            if is_individual_member(m) and normalize_email(m) == email:
                ops.append(BindingOp("remove", m, self.allowed_role))
        if marker_role and email not in self._individual_emails(snap, marker_role):
            ops.append(BindingOp("add", f"user:{email}", marker_role))
        return ops

    def build_allow_ops(self, user_id: str) -> List[BindingOp]:
        """Ops that clear every marker role and grant the base role."""
        snap = self.get_policy_snapshot()
        email = normalize_email(user_id)
        ops: List[BindingOp] = []
        for role in self.marker_roles:
            for m in snap.members(role):
                if is_individual_member(m) and normalize_email(m) == email:
                    ops.append(BindingOp("remove", m, role))
        if email not in self._individual_emails(snap, self.allowed_role):
            ops.append(BindingOp("add", f"user:{email}", self.allowed_role))
        return ops

    def apply_ops(self, ops: Sequence[BindingOp], dry_run: bool = False) -> None:
        """Applies all binding changes in a single read-modify-write.

        The previous implementation issued one full policy read and write per
        user, multiplying quota consumption and widening the window for lost
        updates.
        """
        if not ops or dry_run:
            return

        if self._mock_bindings is not None:
            for op in ops:
                members = set(self._mock_bindings.get(op.role, []))
                if op.action == "add":
                    members.add(op.member)
                else:
                    members.discard(op.member)
                self._mock_bindings[op.role] = sorted(members)
            self._snapshot = None
            return

        client = self._get_resourcemanager_client()
        if client is not None:
            try:
                self._apply_ops_sdk(client, ops)
                self._snapshot = None
                return
            except Exception as e:  # noqa: BLE001
                logger.warning("SDK policy update failed (%s), trying gcloud CLI", e)

        self._apply_ops_gcloud(ops)
        self._snapshot = None

    def _apply_ops_sdk(self, client, ops: Sequence[BindingOp]) -> None:
        from google.iam.v1 import iam_policy_pb2

        resource = f"projects/{self.project_id}"
        policy = self._get_policy_proto(client)
        if policy is None:
            raise RuntimeError("policy unavailable")

        for op in ops:
            target = None
            for b in policy.bindings:
                # Only unconditional bindings are safe to edit in place.
                if b.role == op.role and not (b.condition.expression or b.condition.title):
                    target = b
                    break
            if op.action == "add":
                if target is None:
                    target = policy.bindings.add()
                    target.role = op.role
                if op.member not in target.members:
                    target.members.append(op.member)
            else:
                if target is not None and op.member in target.members:
                    target.members.remove(op.member)

        # setIamPolicy rejects bindings with no members.
        kept = [b for b in policy.bindings if b.members]
        if len(kept) != len(policy.bindings):
            del policy.bindings[:]
            policy.bindings.extend(kept)

        policy.version = 3
        logger.info(
            "Applying %d IAM binding change(s) on %s", len(ops), self.project_id
        )
        client.set_iam_policy(
            request=iam_policy_pb2.SetIamPolicyRequest(resource=resource, policy=policy)
        )

    def _apply_ops_gcloud(self, ops: Sequence[BindingOp]) -> None:
        for op in ops:
            verb = "add-iam-policy-binding" if op.action == "add" else "remove-iam-policy-binding"
            cmd = [
                "gcloud",
                "projects",
                verb,
                self.project_id,
                f"--member={op.member}",
                f"--role={op.role}",
                "--condition=None",
                "--quiet",
            ]
            try:
                logger.info("gcloud %s: %s -> %s", verb, op.member, op.role)
                subprocess.run(cmd, capture_output=True, text=True, check=True)
            except FileNotFoundError:
                logger.error(
                    "gcloud CLI is not available and the SDK update failed; "
                    "no IAM change was applied for %s",
                    op.member,
                )
                raise
            except subprocess.CalledProcessError as e:
                logger.error(
                    "Failed to %s %s on %s: %s", verb, op.member, op.role, e.stderr
                )
                raise

    # Backwards-compatible single-binding helpers.
    def add_member_to_role(self, member: str, role: str) -> None:
        self.apply_ops([BindingOp("add", member, role)])

    def remove_member_from_role(self, member: str, role: str) -> None:
        self.apply_ops([BindingOp("remove", member, role)])

    # ------------------------------------------------------------------
    # Manual operations
    # ------------------------------------------------------------------

    def allow_users(
        self,
        user_ids: Sequence[str],
        dry_run: bool = False,
    ) -> ActionOutcome:
        """Grants base access. Only permitted from a known, controlled state."""
        outcome = ActionOutcome()
        assessments = self.evaluate_users(user_ids)
        ops: List[BindingOp] = []

        for uid in user_ids:
            a = assessments[uid]
            if a.status == UserStatus.ENFORCEABLE_ALLOWED:
                outcome.no_op.append(uid)
                continue
            if a.status in MANUAL_ALLOW_STATES:
                ops.extend(self.build_allow_ops(uid))
                outcome.applied.append(uid)
                continue
            outcome.refused.append(
                RefusedAction(
                    user_id=uid,
                    status=a.status,
                    reason=a.reason,
                    detail=self._refusal_detail(a),
                )
            )

        self.apply_ops(ops, dry_run=dry_run)
        return outcome

    def disallow_users(
        self,
        user_ids: Sequence[str],
        mode: DisallowMode = DisallowMode.CUSTOM_ROLE,
        dry_run: bool = False,
        marker_role: Optional[str] = None,
    ) -> ActionOutcome:
        """Revokes base access. Refuses whenever revocation is not provable."""
        outcome = ActionOutcome()
        assessments = self.evaluate_users(user_ids)
        marker = marker_role or self.admin_role
        if mode == DisallowMode.REVOKE:
            marker = None
        ops: List[BindingOp] = []

        for uid in user_ids:
            a = assessments[uid]
            if a.status in (UserStatus.CAPPED_BY_TOOL, UserStatus.BLOCKED_BY_ADMIN):
                outcome.no_op.append(uid)
                continue
            if a.status == UserStatus.NO_ACCESS:
                outcome.no_op.append(uid)
                continue
            if a.status in MANUAL_DISALLOW_STATES:
                ops.extend(self.build_disallow_ops(uid, marker))
                outcome.applied.append(uid)
                continue
            outcome.refused.append(
                RefusedAction(
                    user_id=uid,
                    status=a.status,
                    reason=a.reason,
                    detail=self._refusal_detail(a),
                )
            )

        self.apply_ops(ops, dry_run=dry_run)
        return outcome

    @staticmethod
    def _refusal_detail(a: UserAssessment) -> str:
        messages = {
            ReasonCode.PRIVILEGED_ROLE: (
                "User holds roles/owner or roles/editor; this tool cannot control "
                "their access. Revoke the privileged role in the IAM console first."
            ),
            ReasonCode.OTHER_ACCESS_ROLE: (
                "User holds another access-granting role, so removing the base role "
                "would not revoke access. Revoke that role in the IAM console first."
            ),
            ReasonCode.GROUP_GRANT_PRESENT: (
                "A group/domain binding exists on an access-granting role; removing an "
                "individual binding does not guarantee revocation. Remove the user "
                "from the group, or convert the group grant to individual bindings."
            ),
            ReasonCode.INHERITED_BINDING: (
                "An access-granting binding is inherited from a parent folder or "
                "organization. Revoke it at the folder or organization level."
            ),
            ReasonCode.CONFLICTING_BINDINGS: (
                "The allowed role and a block marker coexist, or the grant is "
                "conditional. Resolve the binding conflict in the IAM console first."
            ),
            ReasonCode.POLICY_UNREADABLE: (
                "The project IAM policy could not be read. Verify permissions and "
                "retry; no action is taken while the state is unknown."
            ),
            ReasonCode.ANCESTOR_UNCHECKED: (
                "Parent resource policies could not be inspected, so the state is "
                "undecidable. Grant read access to the parent policy, or set "
                "AGY_REQUIRE_ANCESTOR_CHECK=false to skip the check."
            ),
        }
        if a.reason and a.reason in messages:
            return messages[a.reason]
        return f"Action is not permitted from state {a.status.value}."


def build_iam_manager(settings) -> IAMManager:
    """Constructs an IAMManager from a Settings object.

    Kept here so the CLI and the batch job cannot drift apart in how the
    enforcement options (marker roles, access-granting roles, gates) are wired.
    """
    return IAMManager(
        settings.project_id,
        allowed_role=settings.allowed_role,
        cap_role_id=settings.cap_role_id,
        admin_role_id=settings.admin_role_id,
        legacy_role_id=settings.legacy_role_id,
        privileged_roles=settings.privileged_roles,
        other_access_roles=settings.other_access_roles,
        require_ancestor_check=settings.require_ancestor_check,
        allow_group_coexistence=settings.allow_group_coexistence,
    )
