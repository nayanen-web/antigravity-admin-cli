"""Cap management and policy enforcement for Antigravity users.

Enforcement is whitelist-driven: the automatic cycle may only block users in
``ENFORCEABLE_ALLOWED`` and may only restore users in ``CAPPED_BY_TOOL``. Every
other state results in no IAM mutation and an explicit record of why.
"""

import logging
from typing import Dict, List, Optional, Sequence, Set

from agy_admin.config import Settings, get_settings
from agy_admin.iam_manager import BindingOp, IAMManager
from agy_admin.logging_client import LoggingMetricsClient, MetricsFetchResult
from agy_admin.models import (
    AuditAction,
    CapRule,
    CapViolation,
    Coverage,
    DisallowMode,
    EnforceResult,
    GateId,
    GateResult,
    PeriodType,
    ReasonCode,
    UserAssessment,
    UserMetric,
    UserStatus,
    WindowType,
)

logger = logging.getLogger(__name__)


class CapManager:
    def __init__(
        self,
        project_id: str,
        logging_client: Optional[LoggingMetricsClient] = None,
        iam_manager: Optional[IAMManager] = None,
        settings: Optional[Settings] = None,
    ):
        self.project_id = project_id
        self.settings = settings or get_settings(project_id)
        self.logging_client = logging_client or LoggingMetricsClient(project_id)
        self.iam_manager = iam_manager or IAMManager(project_id)

    # ------------------------------------------------------------------
    # Violation detection
    # ------------------------------------------------------------------

    def evaluate_violations(
        self,
        metrics: Dict[str, UserMetric],
        rule: CapRule,
    ) -> List[CapViolation]:
        """Detects which users exceeded the given CapRule."""
        violations: List[CapViolation] = []

        for user_id, m in metrics.items():
            if rule.max_requests is not None and m.total_requests > rule.max_requests:
                violations.append(
                    CapViolation(
                        user_id=user_id,
                        period=rule.period.value,
                        metric_type="requests",
                        limit=rule.max_requests,
                        actual=m.total_requests,
                        overage=m.total_requests - rule.max_requests,
                        status=m.status,
                        reason=m.reason,
                    )
                )
            if rule.max_tokens is not None and m.total_tokens > rule.max_tokens:
                violations.append(
                    CapViolation(
                        user_id=user_id,
                        period=rule.period.value,
                        metric_type="tokens",
                        limit=rule.max_tokens,
                        actual=m.total_tokens,
                        overage=m.total_tokens - rule.max_tokens,
                        status=m.status,
                        reason=m.reason,
                    )
                )

        return violations

    # ------------------------------------------------------------------
    # Enforcement cycle
    # ------------------------------------------------------------------

    def enforce_caps(
        self,
        period: PeriodType = PeriodType.DAILY,
        max_requests: Optional[int] = None,
        max_tokens: Optional[int] = None,
        window_type: WindowType = WindowType.CALENDAR,
        disallow_mode: DisallowMode = DisallowMode.CUSTOM_ROLE,
        dry_run: bool = False,
        mock_entries: Optional[List[dict]] = None,
    ) -> EnforceResult:
        result = EnforceResult(period=period.value, dry_run=dry_run)

        if max_requests is None and max_tokens is None:
            logger.info("No cap thresholds specified; nothing to enforce.")
            return result

        rule = CapRule(period=period, max_requests=max_requests, max_tokens=max_tokens)

        # --- G1: the policy must be readable before anything else -------
        snapshot = self.iam_manager.get_policy_snapshot()
        if not snapshot.readable:
            return self._abort(
                result,
                GateId.G1_POLICY_READABLE,
                f"Could not read the project IAM policy: {snapshot.error}",
            )
        result.gates.append(
            GateResult(gate=GateId.G1_POLICY_READABLE, passed=True)
        )

        # --- G5: advisory warning about uncontrollable grant paths ------
        non_user_grant = self.iam_manager.has_collective_grant(snapshot)
        result.gates.append(
            GateResult(
                gate=GateId.G5_NON_USER_GRANT_ABSENT,
                passed=not non_user_grant,
                detail=(
                    "A group/domain binding exists on an access-granting role. "
                    "Per-user blocking is not guaranteed to be effective in this project."
                    if non_user_grant
                    else ""
                ),
            )
        )

        # --- Collect candidates -----------------------------------------
        fetch: MetricsFetchResult = self.logging_client.fetch_metrics(
            period=period,
            window_type=window_type,
            mock_entries=mock_entries,
        )
        metrics = fetch.metrics

        for uid in self.iam_manager.get_capped_users():
            metrics.setdefault(uid, UserMetric(user_id=uid))
        for uid in self.iam_manager.get_admin_blocked_users():
            metrics.setdefault(uid, UserMetric(user_id=uid))

        assessments = self.iam_manager.evaluate_users(list(metrics.keys()))
        for uid, a in assessments.items():
            if uid in metrics:
                metrics[uid].status = a.status
                metrics[uid].reason = a.reason

        result.evaluated_users_count = len(metrics)
        result.coverage = Coverage.from_assessments(assessments)

        # --- G2: at least one determinate assessment --------------------
        determinate = [
            a for a in assessments.values() if a.status != UserStatus.UNKNOWN
        ]
        if assessments and not determinate:
            return self._abort(
                result,
                GateId.G2_ANY_DETERMINATE,
                "No user state could be determined; refusing to act on guesses.",
            )
        result.gates.append(GateResult(gate=GateId.G2_ANY_DETERMINATE, passed=True))

        # --- G3: telemetry health decides whether re-allow is safe ------
        telemetry_healthy = fetch.healthy
        result.gates.append(
            GateResult(
                gate=GateId.G3_TELEMETRY_HEALTHY,
                passed=telemetry_healthy,
                detail=(
                    ""
                    if telemetry_healthy
                    else (
                        f"{fetch.entry_count} log entries in the window"
                        f"{'; query failed: ' + fetch.error if not fetch.query_ok else ''}. "
                        "Usage is unverified, so automatic re-allow is withheld."
                    )
                ),
            )
        )

        # --- Decide actions ---------------------------------------------
        violations = self.evaluate_violations(metrics, rule)
        result.violations = violations
        violating_uids: Set[str] = {v.user_id for v in violations}

        to_disallow: Set[str] = set()
        unenforceable: List[CapViolation] = []

        for v in violations:
            status = assessments[v.user_id].status if v.user_id in assessments else UserStatus.UNKNOWN
            if status == UserStatus.ENFORCEABLE_ALLOWED:
                to_disallow.add(v.user_id)
            elif status in (UserStatus.CAPPED_BY_TOOL, UserStatus.BLOCKED_BY_ADMIN):
                # Already blocked; nothing to do and nothing to claim.
                continue
            else:
                unenforceable.append(v)
                logger.warning(
                    "User %s exceeded the %s cap (limit=%s, actual=%s) but is %s (%s). "
                    "No IAM change was made; manual action is required.",
                    v.user_id,
                    v.metric_type,
                    v.limit,
                    v.actual,
                    status.value,
                    v.reason.value if v.reason else "-",
                )

        to_allow: Set[str] = set()
        if telemetry_healthy:
            for uid, a in assessments.items():
                if a.status == UserStatus.CAPPED_BY_TOOL and uid not in violating_uids:
                    to_allow.add(uid)
        else:
            withheld = [
                uid
                for uid, a in assessments.items()
                if a.status == UserStatus.CAPPED_BY_TOOL and uid not in violating_uids
            ]
            for uid in withheld:
                self._audit(
                    uid,
                    AuditAction.ALLOW_WITHHELD,
                    "Telemetry health could not be confirmed; re-allow withheld.",
                    {"entry_count": fetch.entry_count, "query_ok": fetch.query_ok},
                    dry_run=dry_run,
                    status=UserStatus.CAPPED_BY_TOOL.value,
                )

        # --- G4: circuit breaker ----------------------------------------
        change_count = len(to_disallow) + len(to_allow)
        budget = self.settings.change_budget(len(metrics))
        if change_count > budget:
            return self._abort(
                result,
                GateId.G4_CHANGE_BUDGET,
                f"This cycle would change {change_count} binding(s), exceeding the "
                f"safety budget of {budget}.",
                unenforceable=unenforceable,
            )
        result.gates.append(
            GateResult(
                gate=GateId.G4_CHANGE_BUDGET,
                passed=True,
                detail=f"{change_count}/{budget}",
            )
        )

        # --- Apply --------------------------------------------------------
        marker = None if disallow_mode == DisallowMode.REVOKE else self.iam_manager.cap_role
        if disallow_mode == DisallowMode.REVOKE and to_disallow:
            logger.warning(
                "disallow_mode=revoke leaves no marker role; affected users will "
                "not be restored automatically when their usage resets."
            )

        ops: List[BindingOp] = []
        for uid in sorted(to_disallow):
            ops.extend(self.iam_manager.build_disallow_ops(uid, marker))
        for uid in sorted(to_allow):
            ops.extend(self.iam_manager.build_allow_ops(uid))

        self.iam_manager.apply_ops(ops, dry_run=dry_run)

        result.disallowed_users = sorted(to_disallow)
        result.allowed_users = sorted(to_allow)
        result.unenforceable_violations = unenforceable
        result.reallowed_metrics = [
            metrics[u] for u in result.allowed_users if u in metrics
        ]
        for v in result.violations:
            v.enforced = v.user_id in to_disallow

        # --- Audit --------------------------------------------------------
        self._write_cycle_audit(
            result, metrics, period, window_type, max_requests, max_tokens, dry_run
        )
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _abort(
        self,
        result: EnforceResult,
        gate: GateId,
        detail: str,
        unenforceable: Optional[List[CapViolation]] = None,
    ) -> EnforceResult:
        result.aborted = True
        result.abort_reason = detail
        result.gates.append(GateResult(gate=gate, passed=False, detail=detail))
        if unenforceable:
            result.unenforceable_violations = unenforceable
        logger.error("Enforcement cycle aborted by %s: %s", gate.value, detail)
        self._audit(
            user_id="-",
            action=AuditAction.CYCLE_ABORTED,
            reason=detail,
            details={"gate": gate.value},
            dry_run=result.dry_run,
        )
        return result

    def _audit(
        self,
        user_id: str,
        action: AuditAction,
        reason: str,
        details: Optional[dict] = None,
        dry_run: bool = False,
        status: Optional[str] = None,
        reason_code: Optional[str] = None,
    ) -> None:
        if not self.logging_client:
            return
        self.logging_client.write_audit_log(
            user_id=user_id,
            action=action,
            reason=reason,
            details=details,
            dry_run=dry_run,
            status=status,
            reason_code=reason_code,
        )

    def _write_cycle_audit(
        self,
        result: EnforceResult,
        metrics: Dict[str, UserMetric],
        period: PeriodType,
        window_type: WindowType,
        max_requests: Optional[int],
        max_tokens: Optional[int],
        dry_run: bool,
    ) -> None:
        base = {
            "period": period.value,
            "window_type": window_type.value,
            "cap_tokens": max_tokens,
            "cap_requests": max_requests,
        }

        for uid in result.disallowed_users:
            reasons = [
                f"{v.metric_type.capitalize()} ({v.actual:,}) exceeded limit ({v.limit:,})"
                for v in result.violations
                if v.user_id == uid
            ]
            m = metrics.get(uid)
            self._audit(
                uid,
                AuditAction.DISALLOW,
                f"{'; '.join(reasons)} in {period.value} {window_type.value} window",
                {
                    **base,
                    "actual_tokens": m.total_tokens if m else 0,
                    "actual_requests": m.total_requests if m else 0,
                },
                dry_run=dry_run,
                status=UserStatus.ENFORCEABLE_ALLOWED.value,
            )

        for uid in result.allowed_users:
            m = metrics.get(uid)
            self._audit(
                uid,
                AuditAction.ALLOW,
                f"Usage within limit in {period.value} {window_type.value} window (access restored)",
                {
                    **base,
                    "actual_tokens": m.total_tokens if m else 0,
                    "actual_requests": m.total_requests if m else 0,
                },
                dry_run=dry_run,
                status=UserStatus.CAPPED_BY_TOOL.value,
            )

        # The honest counterpart: record every violation we could not act on.
        for v in result.unenforceable_violations:
            self._audit(
                v.user_id,
                AuditAction.DISALLOW_NOT_ENFORCEABLE,
                (
                    f"{v.metric_type.capitalize()} ({v.actual:,}) exceeded limit "
                    f"({v.limit:,}) but access could not be revoked by this tool"
                ),
                {**base, "actual": v.actual, "limit": v.limit},
                dry_run=dry_run,
                status=v.status.value,
                reason_code=v.reason.value if v.reason else None,
            )
