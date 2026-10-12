"""Typer-based CLI for Antigravity User Usage Monitoring & Cap Management."""

import re
from pathlib import Path
from typing import Dict, List, Optional

import typer
from rich.console import Console

from agy_admin.cap_manager import CapManager
from agy_admin.config import get_settings
from agy_admin.formatter import (
    format_enforce_result,
    format_user_metrics,
)
from agy_admin.iam_manager import build_iam_manager
from agy_admin.logging_client import LoggingMetricsClient
from agy_admin.models import (
    ActionOutcome,
    AuditAction,
    DisallowMode,
    OrderByField,
    OrderDirection,
    OutputFormat,
    PeriodType,
    UserAssessment,
    UserMetric,
    UserStatus,
    WindowType,
)

#: Exit code returned when one or more requested actions were refused because
#: the target user's state does not permit them.
EXIT_REFUSED = 2
#: Exit code returned when an enforcement cycle aborted on a safety gate.
EXIT_ABORTED = 3

app = typer.Typer(
    name="agy-admin-cli",
    help="Antigravity User Usage Monitoring and Cap Control CLI for Gemini Enterprise",
    no_args_is_help=True,
)

cap_app = typer.Typer(
    name="cap",
    help="Manage usage caps and threshold enforcement",
    no_args_is_help=True,
)
app.add_typer(cap_app, name="cap")

console = Console()

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _read_users_from_file(file_path: Path) -> List[str]:
    """Reads user emails from a text or CSV file.

    Non-email tokens (for example a CSV header row) are rejected instead of
    being silently treated as principals, which in v0.1.0 could produce bogus
    IAM members.
    """
    if not file_path.exists():
        raise typer.BadParameter(f"File not found: {file_path}")

    users: List[str] = []
    invalid: List[str] = []
    seen = set()
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            for part in re.split(r"[,;\s]+", clean):
                if not part:
                    continue
                candidate = part.strip().strip('"').strip("'")
                if not candidate:
                    continue
                if not _EMAIL_RE.match(candidate):
                    invalid.append(candidate)
                    continue
                key = candidate.lower()
                if key in seen:
                    continue
                seen.add(key)
                users.append(candidate)

    if invalid:
        raise typer.BadParameter(
            f"{file_path}: not a valid email address: {', '.join(invalid[:5])}"
            + (" ..." if len(invalid) > 5 else "")
        )
    return users


def _collect_targets(user_ids: Optional[List[str]], file: Optional[Path]) -> List[str]:
    targets = list(user_ids or [])
    if file:
        targets.extend(_read_users_from_file(file))
    if not targets:
        typer.echo("Error: Please specify at least one user ID or --file.", err=True)
        raise typer.Exit(code=1)

    deduped: List[str] = []
    seen = set()
    for t in targets:
        key = t.strip().lower()
        if key and key not in seen:
            seen.add(key)
            deduped.append(t.strip())
    return deduped


def _validate_filter_status(value: Optional[str]) -> str:
    if not value or value.lower() == "all":
        return "all"
    valid = {s.value.lower(): s.value for s in UserStatus}
    key = value.lower()
    if key not in valid:
        raise typer.BadParameter(
            "--filter-status must be 'all' or one of: " + ", ".join(sorted(valid.values()))
        )
    return valid[key]


def _apply_assessments(
    metrics_map: Dict[str, UserMetric],
    assessments: Dict[str, UserAssessment],
) -> None:
    for uid, metric in metrics_map.items():
        a = assessments.get(uid) or assessments.get(uid.lower())
        if a:
            metric.status = a.status
            metric.reason = a.reason


def _filter_and_sort_metrics(
    metrics: List[UserMetric],
    filter_user: Optional[str] = None,
    filter_status: Optional[str] = "all",
    min_requests: Optional[int] = None,
    max_requests: Optional[int] = None,
    min_tokens: Optional[int] = None,
    max_tokens: Optional[int] = None,
    order_by: OrderByField = OrderByField.TOKENS,
    direction: OrderDirection = OrderDirection.DESC,
) -> List[UserMetric]:
    filtered = []
    for m in metrics:
        # User ID filter
        if filter_user and filter_user.lower() not in m.user_id.lower():
            continue

        # Status filter
        if filter_status and filter_status.lower() != "all":
            if m.status.value.lower() != filter_status.lower():
                continue

        # Request filters
        if min_requests is not None and m.total_requests < min_requests:
            continue
        if max_requests is not None and m.total_requests > max_requests:
            continue

        # Token filters
        if min_tokens is not None and m.total_tokens < min_tokens:
            continue
        if max_tokens is not None and m.total_tokens > max_tokens:
            continue

        filtered.append(m)

    # Sort
    reverse = direction == OrderDirection.DESC
    if order_by == OrderByField.TOKENS:
        filtered.sort(key=lambda x: x.total_tokens, reverse=reverse)
    elif order_by == OrderByField.REQUESTS:
        filtered.sort(key=lambda x: x.total_requests, reverse=reverse)
    elif order_by == OrderByField.USER:
        filtered.sort(key=lambda x: x.user_id.lower(), reverse=reverse)
    elif order_by == OrderByField.LAST_ACTIVE:
        filtered.sort(
            key=lambda x: x.last_active.timestamp() if x.last_active else 0,
            reverse=reverse,
        )

    return filtered


def _report_outcome(outcome: ActionOutcome, verb: str, dry_run: bool) -> None:
    prefix = "[DRY-RUN] " if dry_run else ""
    color = "green" if verb == "Allow" else "red"
    console.print(f"\n{prefix}[bold {color}]{verb} operation completed:[/bold {color}]")
    console.print(
        f"- Applied ({len(outcome.applied)}): "
        + (", ".join(outcome.applied) if outcome.applied else "None")
    )
    if outcome.no_op:
        console.print(
            f"- No change needed ({len(outcome.no_op)}): {', '.join(outcome.no_op)}"
        )
    if outcome.refused:
        console.print(
            f"\n- [bold yellow]Manual Action Required ({len(outcome.refused)}):[/bold yellow]"
        )
        console.print(
            "    These accounts were not modified. Their access does not come from an"
        )
        console.print(
            "    individual project binding, so this tool cannot revoke it."
        )
        for r in outcome.refused:
            reason = f"/{r.reason.value}" if r.reason else ""
            console.print(f"    {r.user_id}  [{r.status.value}{reason}]  {r.detail}")


@app.command("list")
def list_users(
    project: Optional[str] = typer.Option(
        None, "--project", "-p", help="Google Cloud Project ID"
    ),
    period: PeriodType = typer.Option(
        PeriodType.MONTHLY, "--period", help="Aggregation period: daily, weekly, monthly, all"
    ),
    window: WindowType = typer.Option(
        WindowType.CALENDAR, "--window", help="Window calculation type: calendar or rolling"
    ),
    filter_user: Optional[str] = typer.Option(
        None, "--filter-user", "-u", help="Filter by user email / ID (case-insensitive substring)"
    ),
    filter_status: str = typer.Option(
        "all",
        "--filter-status",
        "-s",
        help=(
            "Filter by status: all, ENFORCEABLE_ALLOWED, CAPPED_BY_TOOL, "
            "BLOCKED_BY_ADMIN, NOT_ENFORCEABLE, NO_ACCESS, UNKNOWN"
        ),
    ),
    min_requests: Optional[int] = typer.Option(
        None, "--min-requests", help="Filter by minimum request count"
    ),
    max_requests: Optional[int] = typer.Option(
        None, "--max-requests", help="Filter by maximum request count"
    ),
    min_tokens: Optional[int] = typer.Option(
        None, "--min-tokens", help="Filter by minimum token count"
    ),
    max_tokens: Optional[int] = typer.Option(
        None, "--max-tokens", help="Filter by maximum token count"
    ),
    order_by: OrderByField = typer.Option(
        OrderByField.TOKENS, "--order-by", help="Field to sort by: tokens, requests, user, last_active"
    ),
    direction: OrderDirection = typer.Option(
        OrderDirection.DESC, "--direction", help="Sort direction: asc or desc"
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TEXT, "--format", "-f", help="Output format: text, json, csv"
    ),
):
    """List per-user Antigravity usage metrics (requests, tokens, status) from Cloud Logging."""
    filter_status = _validate_filter_status(filter_status)

    settings = get_settings(project)
    logging_client = LoggingMetricsClient(settings.project_id)
    iam_manager = build_iam_manager(settings)

    fetch = logging_client.fetch_metrics(period=period, window_type=window)
    if not fetch.query_ok:
        console.print(
            f"[bold yellow]Warning:[/bold yellow] usage query failed ({fetch.error}). "
            "Counts below are incomplete."
        )

    user_metrics_map = fetch.metrics
    if user_metrics_map:
        assessments = iam_manager.evaluate_users(list(user_metrics_map.keys()))
        _apply_assessments(user_metrics_map, assessments)

    snapshot = iam_manager.get_policy_snapshot()
    if not snapshot.readable:
        console.print(
            "[bold yellow]Warning:[/bold yellow] IAM policy could not be read "
            f"({snapshot.error}). Status column is UNKNOWN and not authoritative."
        )

    metrics_list = list(user_metrics_map.values())
    filtered_list = _filter_and_sort_metrics(
        metrics_list,
        filter_user=filter_user,
        filter_status=filter_status,
        min_requests=min_requests,
        max_requests=max_requests,
        min_tokens=min_tokens,
        max_tokens=max_tokens,
        order_by=order_by,
        direction=direction,
    )

    output = format_user_metrics(filtered_list, output_format=output_format)
    typer.echo(output)


@app.command("user")
def show_user(
    user_ids: Optional[List[str]] = typer.Argument(None, help="User ID(s) to view"),
    file: Optional[Path] = typer.Option(None, "--file", help="File containing list of user emails"),
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Google Cloud Project ID"),
    period: PeriodType = typer.Option(PeriodType.MONTHLY, "--period", help="Aggregation period"),
    window: WindowType = typer.Option(WindowType.CALENDAR, "--window", help="Window calculation type"),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TEXT, "--format", "-f", help="Output format: text, json, csv"
    ),
):
    """View detailed usage metrics and access status for specific user(s)."""
    target_users = _collect_targets(user_ids, file)

    settings = get_settings(project)
    logging_client = LoggingMetricsClient(settings.project_id)
    iam_manager = build_iam_manager(settings)

    fetch = logging_client.fetch_metrics(
        period=period,
        window_type=window,
        user_ids=target_users,
    )
    user_metrics_map = fetch.metrics

    # Ensure all target users exist in the result even if 0 logs
    for uid in target_users:
        if uid not in user_metrics_map:
            user_metrics_map[uid] = UserMetric(user_id=uid)

    assessments = iam_manager.evaluate_users(list(user_metrics_map.keys()))
    _apply_assessments(user_metrics_map, assessments)

    output = format_user_metrics(list(user_metrics_map.values()), output_format=output_format)
    typer.echo(output)


@app.command("allow")
def allow_users(
    user_ids: Optional[List[str]] = typer.Argument(None, help="User ID(s) to allow"),
    file: Optional[Path] = typer.Option(None, "--file", help="File containing list of user emails"),
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Google Cloud Project ID"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate without applying IAM changes"),
):
    """Allow user(s) access to Antigravity by granting the Gemini Enterprise User role."""
    target_users = _collect_targets(user_ids, file)

    settings = get_settings(project)
    iam_manager = build_iam_manager(settings)

    outcome = iam_manager.allow_users(target_users, dry_run=dry_run)

    logging_client = LoggingMetricsClient(settings.project_id)
    assessments = iam_manager.evaluate_users(target_users)
    for u in outcome.applied:
        a = assessments.get(u)
        logging_client.write_audit_log(
            user_id=u,
            action=AuditAction.ALLOW,
            reason="Manual access grant via CLI",
            dry_run=dry_run,
            status=a.status.value if a else None,
            reason_code=a.reason.value if a and a.reason else None,
        )

    _report_outcome(outcome, "Allow", dry_run)
    if outcome.has_refusals:
        raise typer.Exit(code=EXIT_REFUSED)


@app.command("disallow")
def disallow_users(
    user_ids: Optional[List[str]] = typer.Argument(None, help="User ID(s) to disallow"),
    file: Optional[Path] = typer.Option(None, "--file", help="File containing list of user emails"),
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Google Cloud Project ID"),
    mode: DisallowMode = typer.Option(
        DisallowMode.CUSTOM_ROLE,
        "--mode",
        help="Disallow mode: custom_role (apply marker role) or revoke (remove agentspaceUser binding)",
    ),
    reason: Optional[str] = typer.Option(None, "--reason", help="Reason for disallowing user"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate without applying IAM changes"),
):
    """Disallow user(s) from accessing Antigravity (remove agentspaceUser binding or apply admin marker role)."""
    target_users = _collect_targets(user_ids, file)

    settings = get_settings(project)
    iam_manager = build_iam_manager(settings)

    # Manual blocks are attributed to the administrator marker role so the
    # automatic cycle never restores them.
    outcome = iam_manager.disallow_users(
        target_users,
        mode=mode,
        dry_run=dry_run,
        marker_role=iam_manager.admin_role,
    )

    logging_client = LoggingMetricsClient(settings.project_id)
    assessments = iam_manager.evaluate_users(target_users)
    effective_reason = reason or f"Manual disallow via CLI (mode: {mode.value})"
    for u in outcome.applied:
        a = assessments.get(u)
        logging_client.write_audit_log(
            user_id=u,
            action=AuditAction.DISALLOW,
            reason=effective_reason,
            details={"disallow_mode": mode.value, "marker": "admin"},
            dry_run=dry_run,
            status=a.status.value if a else None,
            reason_code=a.reason.value if a and a.reason else None,
        )

    if reason:
        console.print(f"- Reason: {reason}")
    _report_outcome(outcome, "Disallow", dry_run)
    if outcome.has_refusals:
        raise typer.Exit(code=EXIT_REFUSED)


# --- Cap Subcommands ---

@cap_app.command("apply")
def apply_caps(
    period: PeriodType = typer.Option(
        PeriodType.DAILY, "--period", help="Cap period to evaluate: daily, weekly, monthly"
    ),
    requests: Optional[int] = typer.Option(
        None, "--requests", help="Maximum request count threshold"
    ),
    tokens: Optional[int] = typer.Option(
        None, "--tokens", help="Maximum total token count threshold"
    ),
    window: WindowType = typer.Option(
        WindowType.CALENDAR, "--window", help="Window calculation type: calendar or rolling"
    ),
    mode: DisallowMode = typer.Option(
        DisallowMode.CUSTOM_ROLE,
        "--mode",
        "-m",
        help="Disallow mode: custom_role (apply marker role) or revoke (remove agentspaceUser binding)",
    ),
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Google Cloud Project ID"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate without applying IAM disallow actions"),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TEXT, "--format", "-f", help="Output format: text, json, csv"
    ),
    config_file: Optional[Path] = typer.Option(
        None, "--config-file", "-c", help="Path to JSON file with default limits and user overrides"
    ),
):
    """Evaluate usage against thresholds and disallow users exceeding the limits."""
    if period == PeriodType.ALL:
        typer.echo("Error: Cap period cannot be 'all'. Choose daily, weekly, or monthly.", err=True)
        raise typer.Exit(code=1)

    if config_file is not None and not config_file.exists():
        typer.echo(f"Error: Cap config file not found: {config_file}", err=True)
        raise typer.Exit(code=1)

    if requests is None and tokens is None and config_file is None:
        typer.echo("Error: Please specify at least --requests, --tokens limit, or --config-file.", err=True)
        raise typer.Exit(code=1)

    settings = get_settings(project)
    iam_mgr = build_iam_manager(settings)
    cap_mgr = CapManager(settings.project_id, iam_manager=iam_mgr, settings=settings)

    result = cap_mgr.enforce_caps(
        period=period,
        max_requests=requests,
        max_tokens=tokens,
        window_type=window,
        disallow_mode=mode,
        dry_run=dry_run,
        config_file=config_file,
    )

    output = format_enforce_result(result, output_format=output_format)
    typer.echo(output)

    if result.aborted:
        raise typer.Exit(code=EXIT_ABORTED)


if __name__ == "__main__":
    app()

