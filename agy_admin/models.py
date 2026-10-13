"""Data models for agy-admin."""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Union
from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class UserStatus(str, Enum):
    """Enforcement-oriented user state.

    v0.2.0 replaces the previous 4-tier model. The old ``DISALLOWED`` value
    conflated four distinct situations (capped by this tool, blocked by an
    admin, never onboarded, and undeterminable), which caused the tool to
    restore access for users it had never blocked.
    """

    # Access granted through a direct ``user:`` binding of the allowed role and
    # no other access path. Only state the tool may disallow.
    ENFORCEABLE_ALLOWED = "ENFORCEABLE_ALLOWED"
    # Blocked by this tool because a usage cap was exceeded. Only state that is
    # eligible for automatic re-allow.
    CAPPED_BY_TOOL = "CAPPED_BY_TOOL"
    # Blocked manually by an administrator. Never restored automatically.
    BLOCKED_BY_ADMIN = "BLOCKED_BY_ADMIN"
    # Access exists but cannot be controlled by this tool (group/domain grants,
    # inherited bindings, privileged or other access-granting roles).
    NOT_ENFORCEABLE = "NOT_ENFORCEABLE"
    # No access path found. Not onboarded. Never granted automatically.
    NO_ACCESS = "NO_ACCESS"
    # Not enough information to decide. The tool takes no action.
    UNKNOWN = "UNKNOWN"


class ReasonCode(str, Enum):
    """Why a user is NOT_ENFORCEABLE or UNKNOWN."""

    PRIVILEGED_ROLE = "PRIVILEGED_ROLE"
    OTHER_ACCESS_ROLE = "OTHER_ACCESS_ROLE"
    GROUP_GRANT_PRESENT = "GROUP_GRANT_PRESENT"
    INHERITED_BINDING = "INHERITED_BINDING"
    CONFLICTING_BINDINGS = "CONFLICTING_BINDINGS"
    POLICY_UNREADABLE = "POLICY_UNREADABLE"
    ANCESTOR_UNCHECKED = "ANCESTOR_UNCHECKED"


#: States in which the tool has positive control over the user's access.
CONTROLLED_STATES = frozenset(
    {
        UserStatus.ENFORCEABLE_ALLOWED,
        UserStatus.CAPPED_BY_TOOL,
        UserStatus.BLOCKED_BY_ADMIN,
    }
)

#: Only state the automatic cycle may disallow.
AUTO_DISALLOW_STATES = frozenset({UserStatus.ENFORCEABLE_ALLOWED})

#: Only state the automatic cycle may re-allow (whitelist, never a negation).
AUTO_ALLOW_STATES = frozenset({UserStatus.CAPPED_BY_TOOL})

#: States a human operator may explicitly grant access to.
MANUAL_ALLOW_STATES = frozenset(
    {
        UserStatus.CAPPED_BY_TOOL,
        UserStatus.BLOCKED_BY_ADMIN,
        UserStatus.NO_ACCESS,
    }
)

#: States a human operator may explicitly block.
MANUAL_DISALLOW_STATES = frozenset({UserStatus.ENFORCEABLE_ALLOWED})

#: States no CLI action may act upon. The tool cannot prove it controls these
#: accounts, so removing the base-role binding would not revoke access. Acting
#: here would report a block that did not happen, so the action is refused and
#: the account is routed to an administrator instead.
UNCONTROLLABLE_STATES = frozenset({UserStatus.NOT_ENFORCEABLE, UserStatus.UNKNOWN})


class GateId(str, Enum):
    """Global safety gates evaluated before any IAM mutation."""

    G1_POLICY_READABLE = "G1_POLICY_READABLE"
    G2_ANY_DETERMINATE = "G2_ANY_DETERMINATE"
    G3_TELEMETRY_HEALTHY = "G3_TELEMETRY_HEALTHY"
    G4_CHANGE_BUDGET = "G4_CHANGE_BUDGET"
    G5_NON_USER_GRANT_ABSENT = "G5_NON_USER_GRANT_ABSENT"


class AuditAction(str, Enum):
    DISALLOW = "disallow"
    ALLOW = "allow"
    DISALLOW_NOT_ENFORCEABLE = "disallow_not_enforceable"
    ALLOW_WITHHELD = "allow_withheld"
    CYCLE_ABORTED = "cycle_aborted"


class PeriodType(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    ALL = "all"


class WindowType(str, Enum):
    CALENDAR = "calendar"
    ROLLING = "rolling"


class DisallowMode(str, Enum):
    REVOKE = "revoke"
    CUSTOM_ROLE = "custom_role"


class OutputFormat(str, Enum):
    TEXT = "text"
    JSON = "json"
    CSV = "csv"


class OrderByField(str, Enum):
    TOKENS = "tokens"
    REQUESTS = "requests"
    USER = "user"
    LAST_ACTIVE = "last_active"
    COST = "cost"


class OrderDirection(str, Enum):
    ASC = "asc"
    DESC = "desc"


class UserAssessment(BaseModel):
    """Outcome of the state decision rules (R1..R9) for a single user."""

    user_id: str
    status: UserStatus
    reason: Optional[ReasonCode] = None

    @property
    def is_controlled(self) -> bool:
        return self.status in CONTROLLED_STATES


class UserMetric(BaseModel):
    user_id: str
    # Defaults to UNKNOWN so an unassessed metric never implies access.
    status: UserStatus = UserStatus.UNKNOWN
    reason: Optional[ReasonCode] = None
    total_requests: int = 0
    total_tokens: int = 0
    prompt_tokens: int = 0
    candidates_tokens: int = 0
    cached_tokens: int = 0
    thoughts_tokens: int = 0
    estimated_cost_usd: float = 0.0
    clients: List[str] = Field(default_factory=list)
    models: List[str] = Field(default_factory=list)
    unpriced_models: List[str] = Field(default_factory=list)
    first_active: Optional[datetime] = None
    last_active: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "status": self.status.value,
            "reason": self.reason.value if self.reason else "-",
            "total_requests": self.total_requests,
            "total_tokens": self.total_tokens,
            "prompt_tokens": self.prompt_tokens,
            "candidates_tokens": self.candidates_tokens,
            "cached_tokens": self.cached_tokens,
            "thoughts_tokens": self.thoughts_tokens,
            "estimated_cost_usd": self.estimated_cost_usd,
            "clients": ", ".join(self.clients) if self.clients else "-",
            "models": ", ".join(self.models) if self.models else "-",
            "unpriced_models": ", ".join(self.unpriced_models) if self.unpriced_models else "-",
            "first_active": self.first_active.isoformat() if self.first_active else "-",
            "last_active": self.last_active.isoformat() if self.last_active else "-",
        }


class CapRule(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    period: PeriodType
    max_requests: Optional[int] = None
    max_tokens: Optional[int] = None
    max_cost_usd: Optional[float] = Field(
        None, ge=0, validation_alias=AliasChoices("max_cost_usd", "max_usd")
    )


class UserCapLimit(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    max_tokens: Optional[int] = None
    max_requests: Optional[int] = None
    max_cost_usd: Optional[float] = Field(
        None, ge=0, validation_alias=AliasChoices("max_cost_usd", "max_usd")
    )


class CapConfigFile(BaseModel):
    default: UserCapLimit = Field(default_factory=UserCapLimit)
    overrides: Dict[str, UserCapLimit] = Field(default_factory=dict)


class CapViolation(BaseModel):
    user_id: str
    period: str
    metric_type: str
    limit: Union[int, float]
    actual: Union[int, float]
    overage: Union[int, float]
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Populated during enforcement so reports can distinguish "blocked" from
    # "detected but could not be blocked".
    status: UserStatus = UserStatus.UNKNOWN
    reason: Optional[ReasonCode] = None
    enforced: bool = False
    is_override: bool = False


class RefusedAction(BaseModel):
    """A requested action the tool declined to perform, with justification."""

    user_id: str
    status: UserStatus
    reason: Optional[ReasonCode] = None
    detail: str = ""


class ActionOutcome(BaseModel):
    """Result of a manual allow/disallow invocation."""

    applied: List[str] = Field(default_factory=list)
    no_op: List[str] = Field(default_factory=list)
    refused: List[RefusedAction] = Field(default_factory=list)

    @property
    def has_refusals(self) -> bool:
        return bool(self.refused)


class Coverage(BaseModel):
    """How much of the evaluated population this tool can actually control."""

    total_evaluated: int = 0
    enforceable: int = 0
    not_enforceable: int = 0
    not_enforceable_by_reason: Dict[str, int] = Field(default_factory=dict)
    no_access: int = 0
    unknown: int = 0
    coverage_ratio: float = 0.0

    @classmethod
    def from_assessments(cls, assessments: Dict[str, UserAssessment]) -> "Coverage":
        cov = cls(total_evaluated=len(assessments))
        for a in assessments.values():
            if a.status in CONTROLLED_STATES:
                cov.enforceable += 1
            elif a.status == UserStatus.NOT_ENFORCEABLE:
                cov.not_enforceable += 1
                key = a.reason.value if a.reason else "UNSPECIFIED"
                cov.not_enforceable_by_reason[key] = (
                    cov.not_enforceable_by_reason.get(key, 0) + 1
                )
            elif a.status == UserStatus.NO_ACCESS:
                cov.no_access += 1
            else:
                cov.unknown += 1
        if cov.total_evaluated:
            cov.coverage_ratio = round(cov.enforceable / cov.total_evaluated, 4)
        return cov


class GateResult(BaseModel):
    gate: GateId
    passed: bool
    detail: str = ""


class EnforceResult(BaseModel):
    period: str
    evaluated_users_count: int = 0
    violations: List[CapViolation] = Field(default_factory=list)
    disallowed_users: List[str] = Field(default_factory=list)
    allowed_users: List[str] = Field(default_factory=list)
    reallowed_metrics: List[UserMetric] = Field(default_factory=list)
    # Cap violators the tool could not act on. This is the administrator's
    # manual action list and the honest counterpart of disallowed_users.
    unenforceable_violations: List[CapViolation] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    gates: List[GateResult] = Field(default_factory=list)
    aborted: bool = False
    abort_reason: str = ""
    dry_run: bool = False
    warnings: List[str] = Field(default_factory=list)

    @property
    def violations_total(self) -> int:
        return len(self.violations)

    @property
    def violations_enforced(self) -> int:
        return len([v for v in self.violations if v.enforced])

    @property
    def violations_unenforceable(self) -> int:
        return len(self.unenforceable_violations)

    def gate(self, gate_id: GateId) -> Optional[GateResult]:
        for g in self.gates:
            if g.gate == gate_id:
                return g
        return None

    def to_report_dict(self) -> dict:
        data = self.model_dump(mode="json")
        data["violations_total"] = self.violations_total
        data["violations_enforced"] = self.violations_enforced
        data["violations_unenforceable"] = self.violations_unenforceable
        return data
