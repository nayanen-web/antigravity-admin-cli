"""Cap management and policy enforcement for Antigravity users.

Enforcement is whitelist-driven: the automatic cycle may only block users in
``ENFORCEABLE_ALLOWED`` and may only restore users in ``CAPPED_BY_TOOL``. Every
other state results in no IAM mutation and an explicit record of why.
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Union

from agy_admin.config import Settings, get_settings
from agy_admin.iam_manager import BindingOp, IAMManager, normalize_email
from agy_admin.logging_client import LoggingMetricsClient, MetricsFetchResult
from agy_admin.models import (
    AuditAction,
    CapConfigFile,
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
    UserCapLimit,
    UserMetric,
    UserStatus,
    WindowType,
)

logger = logging.getLogger(__name__)


def load_cap_config(config_path: Union[str, Path]) -> CapConfigFile:
    """Loads and validates cap configuration with defaults and per-user overrides."""
    path = Path(config_path)
    if not path.is_file():
        raise FileNotFoundError(f"Cap config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return CapConfigFile.model_validate(data)


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
        user_overrides: Optional[Dict[str, Union[dict, UserCapLimit]]] = None,
    ) -> List[CapViolation]:
        """Detects which users exceeded their respective caps (default or user overrides)."""
        violations: List[CapViolation] = []
        normalized_overrides: Dict[str, dict] = {}
        if user_overrides:
            for k, v in user_overrides.items():
                canon_k = normalize_email(k)
                if isinstance(v, UserCapLimit):
                    normalized_overrides[canon_k] = v.model_dump(exclude_unset=True)
                elif isinstance(v, dict):
                    try:
                        normalized_overrides[canon_k] = UserCapLimit.model_validate(v).model_dump(exclude_unset=True)
                    except Exception:
                        normalized_overrides[canon_k] = v

        for user_id, m in metrics.items():
            user_key = normalize_email(user_id or m.user_id)
            override_cfg = normalized_overrides.get(user_key)
            is_override = override_cfg is not None

            eff_requests = (
                override_cfg.get("max_requests")
                if is_override and override_cfg.get("max_requests") is not None
                else rule.max_requests
            )
            eff_tokens = (
                override_cfg.get("max_tokens")
                if is_override and override_cfg.get("max_tokens") is not None
                else rule.max_tokens
            )
            eff_cost = (
                override_cfg.get("max_cost_usd")
                if is_override and override_cfg.get("max_cost_usd") is not None
                else (override_cfg.get("max_usd") if is_override and override_cfg.get("max_usd") is not None else rule.max_cost_usd)
            )

            if eff_requests is not None and m.total_requests > eff_requests:
                violations.append(
                    CapViolation(
                        user_id=user_key,
                        period=rule.period.value,
                        metric_type="requests",
                        limit=eff_requests,
                        actual=m.total_requests,
                        overage=m.total_requests - eff_requests,
                        status=m.status,
                        reason=m.reason,
                        is_override=is_override and override_cfg.get("max_requests") is not None,
                    )
                )
            if eff_tokens is not None and m.total_tokens > eff_tokens:
                violations.append(
                    CapViolation(
                        user_id=user_key,
                        period=rule.period.value,
                        metric_type="tokens",
                        limit=eff_tokens,
                        actual=m.total_tokens,
                        overage=m.total_tokens - eff_tokens,
                        status=m.status,
                        reason=m.reason,
                        is_override=is_override and override_cfg.get("max_tokens") is not None,
                    )
                )
            if eff_cost is not None and m.estimated_cost_usd > eff_cost:
                violations.append(
                    CapViolation(
                        user_id=user_key,
                        period=rule.period.value,
                        metric_type="cost_usd",
                        limit=eff_cost,
                        actual=round(m.estimated_cost_usd, 4),
                        overage=round(m.estimated_cost_usd - eff_cost, 4),
                        status=m.status,
                        reason=m.reason,
                        is_override=is_override and (
                            override_cfg.get("max_cost_usd") is not None
                            or override_cfg.get("max_usd") is not None
                        ),
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
        max_cost_usd: Optional[float] = None,
        window_type: WindowType = WindowType.CALENDAR,
        disallow_mode: DisallowMode = DisallowMode.CUSTOM_ROLE,
        dry_run: bool = False,
        mock_entries: Optional[List[dict]] = None,
        config_file: Optional[Union[str, Path]] = None,
        price_file: Optional[Union[str, Path]] = None,
    ) -> EnforceResult:
        result = EnforceResult(period=period.value, dry_run=dry_run)

        target_price_file = price_file or os.environ.get("CAP_PRICE_FILE")
        if target_price_file and self.logging_client:
            from agy_admin.pricing import load_price_table
            self.logging_client.price_table = load_price_table(target_price_file)

        cap_config = None
        target_config_file = config_file or os.environ.get("CAP_CONFIG_FILE")
        if target_config_file:
            cap_config = load_cap_config(target_config_file)
            if cap_config.default.max_requests is not None:
                max_requests = cap_config.default.max_requests
            if cap_config.default.max_tokens is not None:
                max_tokens = cap_config.default.max_tokens
            if cap_config.default.max_cost_usd is not None:
                max_cost_usd = cap_config.default.max_cost_usd

        if (
            max_requests is None
            and max_tokens is None
            and max_cost_usd is None
            and (not cap_config or not cap_config.overrides)
        ):
            logger.info("No cap thresholds specified; nothing to enforce.")
            return result

        rule = CapRule(
            period=period,
            max_requests=max_requests,
            max_tokens=max_tokens,
            max_cost_usd=max_cost_usd,
        )

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
        canonical_metrics: Dict[str, UserMetric] = {}
        for k, m in fetch.metrics.items():
            canon_k = normalize_email(k or m.user_id)
            if canon_k in canonical_metrics:
                existing = canonical_metrics[canon_k]
                existing.total_tokens += m.total_tokens
                existing.total_requests += m.total_requests
                existing.prompt_tokens += m.prompt_tokens
                existing.cached_tokens += m.cached_tokens
                existing.candidates_tokens += m.candidates_tokens
                existing.thoughts_tokens += m.thoughts_tokens
                existing.estimated_cost_usd += m.estimated_cost_usd
                for um in m.unpriced_models:
                    if um not in existing.unpriced_models:
                        existing.unpriced_models.append(um)
                for c in m.clients:
                    if c not in existing.clients:
                        existing.clients.append(c)
                for mdl in m.models:
                    if mdl not in existing.models:
                        existing.models.append(mdl)
                if m.first_active and (existing.first_active is None or m.first_active < existing.first_active):
                    existing.first_active = m.first_active
                if m.last_active and (existing.last_active is None or m.last_active > existing.last_active):
                    existing.last_active = m.last_active
            else:
                m.user_id = canon_k
                canonical_metrics[canon_k] = m
        metrics = canonical_metrics

        for uid in self.iam_manager.get_capped_users():
            canon_uid = normalize_email(uid)
            metrics.setdefault(canon_uid, UserMetric(user_id=canon_uid))
        for uid in self.iam_manager.get_admin_blocked_users():
            canon_uid = normalize_email(uid)
            metrics.setdefault(canon_uid, UserMetric(user_id=canon_uid))

        assessments = self.iam_manager.evaluate_users(list(metrics.keys()))
        for uid, a in assessments.items():
            canon_uid = normalize_email(uid)
            if canon_uid in metrics:
                metrics[canon_uid].status = a.status
                metrics[canon_uid].reason = a.reason

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

        # --- Unpriced models warning ------------------------------------
        if fetch.unpriced_model_counts:
            policy = (
                self.logging_client.price_table.unknown_model_policy
                if self.logging_client and getattr(self.logging_client, "price_table", None)
                else "max"
            )
            breakdown = ", ".join(
                f"{mdl} ({cnt} req)"
                for mdl, cnt in sorted(fetch.unpriced_model_counts.items())
            )
            warning_msg = (
                f"Unpriced models detected in window: {breakdown}. "
                f"Unknown model policy '{policy}' applied."
            )
            result.warnings.append(warning_msg)
            logger.warning(warning_msg)

        # --- Decide actions ---------------------------------------------
        violations = self.evaluate_violations(
            metrics,
            rule,
            user_overrides=cap_config.overrides if cap_config else None,
        )
        result.violations = violations
        violating_uids: Set[str] = {normalize_email(v.user_id) for v in violations}

        to_disallow: Set[str] = set()
        unenforceable: List[CapViolation] = []

        for v in violations:
            canon_v_uid = normalize_email(v.user_id)
            status = assessments[canon_v_uid].status if canon_v_uid in assessments else UserStatus.UNKNOWN
            if status == UserStatus.ENFORCEABLE_ALLOWED:
                to_disallow.add(canon_v_uid)
            elif status in (UserStatus.CAPPED_BY_TOOL, UserStatus.BLOCKED_BY_ADMIN):
                # Already blocked; nothing to do and nothing to claim.
                continue
            else:
                unenforceable.append(v)
                limit_str = f"${v.limit:.4f}" if v.metric_type == "cost_usd" else f"{v.limit:,}"
                actual_str = f"${v.actual:.4f}" if v.metric_type == "cost_usd" else f"{v.actual:,}"
                logger.warning(
                    "User %s exceeded the %s cap (limit=%s, actual=%s) but is %s (%s). "
                    "No IAM change was made; manual action is required.",
                    canon_v_uid,
                    v.metric_type,
                    limit_str,
                    actual_str,
                    status.value,
                    v.reason.value if v.reason else "-",
                )

        to_allow: Set[str] = set()
        if telemetry_healthy:
            for uid, a in assessments.items():
                canon_uid = normalize_email(uid)
                if a.status == UserStatus.CAPPED_BY_TOOL and canon_uid not in violating_uids:
                    to_allow.add(canon_uid)
        else:
            withheld = [
                normalize_email(uid)
                for uid, a in assessments.items()
                if a.status == UserStatus.CAPPED_BY_TOOL and normalize_email(uid) not in violating_uids
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
        # Count only new restrictions (to_disallow) against the change budget.
        # Restores (to_allow) reduce access risk and are excluded from the budget.
        disallow_count = len(to_disallow)
        budget = self.settings.change_budget(len(metrics))
        if disallow_count > budget:
            return self._abort(
                result,
                GateId.G4_CHANGE_BUDGET,
                f"This cycle would disallow {disallow_count} user(s), exceeding the "
                f"safety budget of {budget}.",
                unenforceable=unenforceable,
            )
        result.gates.append(
            GateResult(
                gate=GateId.G4_CHANGE_BUDGET,
                passed=True,
                detail=f"{disallow_count}/{budget}",
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
            result, metrics, period, window_type, max_requests, max_tokens, max_cost_usd, dry_run
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
        max_cost_usd: Optional[float],
        dry_run: bool,
    ) -> None:
        base = {
            "period": period.value,
            "window_type": window_type.value,
            "cap_tokens": max_tokens,
            "cap_requests": max_requests,
            "cap_cost_usd": round(max_cost_usd, 4) if max_cost_usd is not None else None,
        }

        for uid in result.disallowed_users:
            reasons = [
                f"Cost (${v.actual:.4f}) exceeded limit (${v.limit:.4f})"
                if v.metric_type == "cost_usd"
                else f"{v.metric_type.capitalize()} ({v.actual:,}) exceeded limit ({v.limit:,})"
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
                    "actual_cost_usd": round(m.estimated_cost_usd, 4) if m else 0.0,
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
                    "actual_cost_usd": round(m.estimated_cost_usd, 4) if m else 0.0,
                },
                dry_run=dry_run,
                status=UserStatus.CAPPED_BY_TOOL.value,
            )

        # The honest counterpart: record every violation we could not act on.
        for v in result.unenforceable_violations:
            if v.metric_type == "cost_usd":
                reason_text = f"Cost (${v.actual:.4f}) exceeded limit (${v.limit:.4f})"
                actual_val = round(v.actual, 4) if isinstance(v.actual, float) else v.actual
                limit_val = round(v.limit, 4) if isinstance(v.limit, float) else v.limit
            else:
                reason_text = f"{v.metric_type.capitalize()} ({v.actual:,}) exceeded limit ({v.limit:,})"
                actual_val = v.actual
                limit_val = v.limit
            self._audit(
                v.user_id,
                AuditAction.DISALLOW_NOT_ENFORCEABLE,
                f"{reason_text} but access could not be revoked by this tool",
                {**base, "actual": actual_val, "limit": limit_val},
                dry_run=dry_run,
                status=v.status.value,
                reason_code=v.reason.value if v.reason else None,
            )
