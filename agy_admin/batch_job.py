"""Cloud Run Batch Job for automated Antigravity Cap Enforcement."""

import json
import logging
import os
import sys
import time
import urllib.request
from typing import List, Optional

from agy_admin.cap_manager import CapManager
from agy_admin.config import get_settings
from agy_admin.formatter import format_enforce_result
from agy_admin.iam_manager import build_iam_manager
from agy_admin.models import (
    DisallowMode,
    EnforceResult,
    GateId,
    OutputFormat,
    PeriodType,
    WindowType,
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("agy_batch_job")

#: Exit code used when a cycle aborted on a safety gate. Cloud Run Jobs treat a
#: non-zero exit as a failed execution, which is what should page an operator.
EXIT_ABORTED = 3
#: Exit code used when the job is misconfigured (no thresholds).
EXIT_CONFIG = 1


def _should_notify(result: EnforceResult) -> bool:
    """Notify on anything an operator must know about, not just successes.

    v0.1.0 only alerted when a binding actually changed, which meant an aborted
    cycle or a cap violation the tool could not act on was silent.
    """
    return bool(
        result.aborted
        or result.disallowed_users
        or result.allowed_users
        or result.unenforceable_violations
        or result.warnings
    )


def build_alert_lines(result: EnforceResult, project_id: str) -> List[str]:
    """Builds the webhook message body. Separated out so it is testable."""
    prefix = "[DRY-RUN] " if result.dry_run else ""

    if result.aborted:
        return [
            f"{prefix}*Antigravity Cap Enforcement ABORTED* (Project: `{project_id}`)",
            f"- Period: `{result.period}`",
            f"- Reason: {result.abort_reason}",
            "- No IAM changes were applied. Operator action required.",
        ]

    cov = result.coverage
    ratio = f"{cov.coverage_ratio * 100:.1f}%" if cov.total_evaluated else "-"
    lines = [
        f"{prefix}*Antigravity Usage Cap Enforced* (Project: `{project_id}`)",
        f"- Period: `{result.period}`",
        f"- Evaluated users: {result.evaluated_users_count} (coverage {ratio}, "
        f"enforceable {cov.enforceable} / not enforceable {cov.not_enforceable})",
        f"- Cap violations: {result.violations_total} "
        f"(blocked {result.violations_enforced} / "
        f"not enforceable {result.violations_unenforceable})",
    ]

    g5 = result.gate(GateId.G5_NON_USER_GRANT_ABSENT)
    if g5 and not g5.passed:
        lines.append(f"- WARNING: {g5.detail}")

    g3 = result.gate(GateId.G3_TELEMETRY_HEALTHY)
    if g3 and not g3.passed:
        lines.append(f"- WARNING: {g3.detail}")

    if result.warnings:
        for w in result.warnings:
            lines.append(f"- WARNING: {w}")

    if result.disallowed_users:
        lines.append(
            f"- Disallowed ({len(result.disallowed_users)}): "
            + ", ".join(result.disallowed_users)
        )
        for v in result.violations:
            if v.enforced:
                if v.metric_type == "cost_usd":
                    lines.append(
                        f"    `{v.user_id}`: {v.metric_type} "
                        f"actual=${v.actual:.2f} > limit=${v.limit:.2f}"
                    )
                else:
                    lines.append(
                        f"    `{v.user_id}`: {v.metric_type} "
                        f"actual={int(v.actual):,} > limit={int(v.limit):,}"
                    )

    if result.unenforceable_violations:
        lines.append(
            f"- MANUAL ACTION REQUIRED ({len(result.unenforceable_violations)}): "
            "cap exceeded but this tool could not revoke access"
        )
        for v in result.unenforceable_violations:
            reason = v.reason.value if v.reason else "-"
            if v.metric_type == "cost_usd":
                lines.append(
                    f"    `{v.user_id}`: {v.metric_type} actual=${v.actual:.2f} > "
                    f"limit=${v.limit:.2f} [{v.status.value}/{reason}]"
                )
            else:
                lines.append(
                    f"    `{v.user_id}`: {v.metric_type} actual={int(v.actual):,} > "
                    f"limit={int(v.limit):,} [{v.status.value}/{reason}]"
                )

    if result.allowed_users:
        lines.append(
            f"- Re-allowed ({len(result.allowed_users)}): "
            + ", ".join(result.allowed_users)
        )

    return lines


def send_webhook_alert(webhook_url: str, result: EnforceResult, project_id: str) -> None:
    """Sends a webhook notification (Slack / Google Chat compatible)."""
    if not webhook_url or not _should_notify(result):
        return

    payload = json.dumps(
        {"text": "\n".join(build_alert_lines(result, project_id))}
    ).encode("utf-8")
    try:
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info("Webhook alert dispatched successfully (status: %d)", resp.status)
    except Exception as e:  # noqa: BLE001 - alerting must never break the job
        logger.error("Failed to send webhook alert: %s", e)


def run_enforcement_cycle(
    project_id: str,
    period: PeriodType,
    window_type: WindowType,
    cap_requests: Optional[int],
    cap_tokens: Optional[int],
    disallow_mode: DisallowMode,
    dry_run: bool,
    webhook_url: Optional[str],
    config_file: Optional[str] = None,
    cap_cost_usd: Optional[float] = None,
    price_file: Optional[str] = None,
) -> EnforceResult:
    """Executes a single cycle of cap enforcement."""
    logger.info(
        "Starting Cap enforcement cycle for project='%s', period='%s', window='%s'",
        project_id,
        period.value,
        window_type.value,
    )
    settings = get_settings(project_id)
    iam_mgr = build_iam_manager(settings)
    cap_mgr = CapManager(project_id, iam_manager=iam_mgr, settings=settings)

    result = cap_mgr.enforce_caps(
        period=period,
        max_requests=cap_requests,
        max_tokens=cap_tokens,
        max_cost_usd=cap_cost_usd,
        price_file=price_file,
        window_type=window_type,
        disallow_mode=disallow_mode,
        dry_run=dry_run,
        config_file=config_file,
    )

    print(format_enforce_result(result, output_format=OutputFormat.TEXT))

    if webhook_url:
        send_webhook_alert(webhook_url, result, project_id)

    if result.aborted:
        logger.error("Cycle aborted: %s", result.abort_reason)
    if result.unenforceable_violations:
        logger.warning(
            "%d cap violation(s) require manual action: %s",
            len(result.unenforceable_violations),
            ", ".join(sorted({v.user_id for v in result.unenforceable_violations})),
        )

    return result


def main() -> None:
    settings = get_settings()
    project_id = (
        os.environ.get("GCP_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or settings.project_id
    )

    period_str = os.environ.get("CAP_PERIOD", "daily").lower()
    try:
        period = PeriodType(period_str)
    except ValueError:
        logger.warning("Unknown CAP_PERIOD '%s', defaulting to 'daily'", period_str)
        period = PeriodType.DAILY

    if period == PeriodType.ALL:
        logger.error("CAP_PERIOD='all' is not a valid enforcement period.")
        sys.exit(EXIT_CONFIG)

    window_str = os.environ.get("WINDOW_TYPE", "calendar").lower()
    window_type = WindowType.ROLLING if window_str == "rolling" else WindowType.CALENDAR

    cap_requests_str = os.environ.get("CAP_REQUESTS")
    cap_requests = (
        int(cap_requests_str) if cap_requests_str and cap_requests_str.isdigit() else None
    )

    cap_tokens_str = os.environ.get("CAP_TOKENS")
    cap_tokens = int(cap_tokens_str) if cap_tokens_str and cap_tokens_str.isdigit() else None

    cap_cost_usd_str = os.environ.get("CAP_COST_USD") or os.environ.get("CAP_USD")
    cap_cost_usd = None
    if cap_cost_usd_str:
        try:
            cap_cost_usd = float(cap_cost_usd_str)
        except ValueError:
            logger.warning("Invalid CAP_COST_USD '%s', ignoring", cap_cost_usd_str)

    price_file = os.environ.get("CAP_PRICE_FILE")

    config_file = os.environ.get("CAP_CONFIG_FILE")

    if cap_requests is None and cap_tokens is None and cap_cost_usd is None and not config_file:
        logger.error(
            "Neither CAP_REQUESTS, CAP_TOKENS, CAP_COST_USD, nor CAP_CONFIG_FILE is set; refusing to run a no-op cycle."
        )
        sys.exit(EXIT_CONFIG)

    mode_str = os.environ.get("IAM_DISALLOW_MODE", "custom_role").lower()
    disallow_mode = DisallowMode.REVOKE if mode_str == "revoke" else DisallowMode.CUSTOM_ROLE
    if disallow_mode == DisallowMode.REVOKE:
        logger.warning(
            "IAM_DISALLOW_MODE=revoke applies no marker role, so blocked users are "
            "never restored automatically when their usage resets."
        )

    dry_run = os.environ.get("DRY_RUN", "false").lower() in ("true", "1", "yes")
    webhook_url = os.environ.get("ALERT_WEBHOOK_URL") or os.environ.get("SLACK_WEBHOOK_URL")

    interval_minutes_str = os.environ.get("INTERVAL_MINUTES", "0")
    interval_minutes = int(interval_minutes_str) if interval_minutes_str.isdigit() else 0

    def _cycle() -> EnforceResult:
        return run_enforcement_cycle(
            project_id=project_id,
            period=period,
            window_type=window_type,
            cap_requests=cap_requests if not config_file else None,
            cap_tokens=cap_tokens if not config_file else None,
            cap_cost_usd=cap_cost_usd if not config_file else None,
            price_file=price_file,
            disallow_mode=disallow_mode,
            dry_run=dry_run,
            webhook_url=webhook_url,
            config_file=config_file,
        )

    if interval_minutes > 0:
        # Daemon mode is intended for long-lived hosts. On Cloud Run Jobs the
        # task timeout will kill the container, so leave INTERVAL_MINUTES unset
        # there and drive the schedule with Cloud Scheduler instead.
        logger.info("Running in daemon mode. Cycle interval: %d minutes", interval_minutes)
        while True:
            try:
                _cycle()
            except Exception as e:  # noqa: BLE001
                logger.exception("Error in enforcement cycle: %s", e)
            logger.info("Sleeping for %d minutes...", interval_minutes)
            time.sleep(interval_minutes * 60)
    else:
        result = _cycle()
        if result.aborted:
            logger.error("Cloud Run batch job finished with an aborted cycle.")
            sys.exit(EXIT_ABORTED)
        logger.info("Cloud Run batch job finished successfully.")


if __name__ == "__main__":
    main()
