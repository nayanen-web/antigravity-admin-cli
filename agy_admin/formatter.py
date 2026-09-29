"""Output formatters supporting Text (Rich), JSON, and CSV formats."""

import csv
import io
import json
from typing import List, Optional

from rich.console import Console
from rich.table import Table

from agy_admin.models import (
    EnforceResult,
    GateId,
    OutputFormat,
    UserMetric,
    UserStatus,
)

_STATUS_STYLE = {
    UserStatus.ENFORCEABLE_ALLOWED: "green",
    UserStatus.CAPPED_BY_TOOL: "red",
    UserStatus.BLOCKED_BY_ADMIN: "magenta",
    UserStatus.NOT_ENFORCEABLE: "yellow",
    UserStatus.NO_ACCESS: "dim",
    UserStatus.UNKNOWN: "bright_black",
}


def _render(renderables) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=170)
    for r in renderables:
        console.print(r)
    return buffer.getvalue().strip()


def _status_cell(m: UserMetric) -> str:
    style = _STATUS_STYLE.get(m.status, "white")
    text = m.status.value
    if m.reason:
        text = f"{text} ({m.reason.value})"
    return f"[{style}]{text}[/{style}]"


def format_user_metrics(
    metrics: List[UserMetric],
    output_format: OutputFormat = OutputFormat.TEXT,
    console: Optional[Console] = None,
) -> str:
    """Formats a list of UserMetric objects into Text, JSON, or CSV."""
    if output_format == OutputFormat.JSON:
        return json.dumps([m.to_dict() for m in metrics], indent=2, ensure_ascii=False)

    if output_format == OutputFormat.CSV:
        output = io.StringIO()
        fieldnames = [
            "user_id",
            "status",
            "reason",
            "total_requests",
            "total_tokens",
            "prompt_tokens",
            "candidates_tokens",
            "clients",
            "models",
            "first_active",
            "last_active",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for m in metrics:
            writer.writerow(m.to_dict())
        return output.getvalue().strip()

    table = Table(
        title="Antigravity User Usage & Enforcement State",
        show_header=True,
        header_style="bold cyan",
        show_footer=True,
    )
    table.add_column("User ID", style="bold", footer="Total")
    table.add_column("State", justify="left")
    table.add_column(
        "Requests",
        justify="right",
        footer=f"{sum(m.total_requests for m in metrics):,}",
    )
    table.add_column(
        "Total Tokens",
        justify="right",
        footer=f"{sum(m.total_tokens for m in metrics):,}",
    )
    table.add_column("Clients", justify="left")
    table.add_column("Models", justify="left")
    table.add_column("Last Active", justify="center")

    for m in metrics:
        table.add_row(
            m.user_id,
            _status_cell(m),
            f"{m.total_requests:,}",
            f"{m.total_tokens:,}",
            ", ".join(m.clients) if m.clients else "-",
            ", ".join(m.models) if m.models else "-",
            m.last_active.strftime("%Y-%m-%d %H:%M:%S") if m.last_active else "-",
        )

    return _render([table])


def _action_label(result: EnforceResult, violation) -> str:
    """Action actually taken. Never claims an enforcement that did not happen."""
    if violation.enforced:
        return (
            "[yellow]WOULD DISALLOW[/yellow]"
            if result.dry_run
            else "[red]DISALLOWED[/red]"
        )
    if violation.status in (UserStatus.CAPPED_BY_TOOL, UserStatus.BLOCKED_BY_ADMIN):
        return "[dim]ALREADY CAPPED[/dim]"
    reason = f" ({violation.reason.value})" if violation.reason else ""
    return f"[bold yellow]NOT ENFORCEABLE[/bold yellow]{reason}"


def format_enforce_result(
    result: EnforceResult,
    output_format: OutputFormat = OutputFormat.TEXT,
) -> str:
    """Formats Cap Enforcement Result."""
    if output_format == OutputFormat.JSON:
        return json.dumps(result.to_report_dict(), indent=2, ensure_ascii=False)

    if output_format == OutputFormat.CSV:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "user_id",
                "period",
                "metric_type",
                "limit",
                "actual",
                "overage",
                "status",
                "reason",
                "action",
            ]
        )
        for v in result.violations:
            action = "DISALLOWED" if v.enforced else (
                "ALREADY_CAPPED"
                if v.status in (UserStatus.CAPPED_BY_TOOL, UserStatus.BLOCKED_BY_ADMIN)
                else "NOT_ENFORCEABLE"
            )
            writer.writerow(
                [
                    v.user_id,
                    v.period,
                    v.metric_type,
                    v.limit,
                    v.actual,
                    v.overage,
                    v.status.value,
                    v.reason.value if v.reason else "",
                    action,
                ]
            )
        for m in result.reallowed_metrics:
            writer.writerow(
                [
                    m.user_id,
                    result.period,
                    "usage",
                    "within_limit",
                    m.total_tokens,
                    0,
                    m.status.value,
                    "",
                    "RE-ALLOWED",
                ]
            )
        return output.getvalue().strip()

    renderables = []
    prefix = "[DRY-RUN] " if result.dry_run else ""

    if result.aborted:
        renderables.append(
            f"\n[bold red]{prefix}Cap Enforcement ABORTED[/bold red]\n"
            f"- Reason: {result.abort_reason}\n"
            "- No IAM changes were applied."
        )

    g5 = result.gate(GateId.G5_NON_USER_GRANT_ABSENT)
    if g5 and not g5.passed:
        renderables.append(f"[bold yellow][WARNING][/bold yellow] {g5.detail}")

    g3 = result.gate(GateId.G3_TELEMETRY_HEALTHY)
    if g3 and not g3.passed:
        renderables.append(f"[bold yellow][WARNING][/bold yellow] {g3.detail}")

    cov = result.coverage
    ratio = f"{cov.coverage_ratio * 100:.1f}%" if cov.total_evaluated else "-"
    renderables.append(
        f"\n[bold]{prefix}Cap Enforcement Summary[/bold]\n"
        f"- Evaluated: {cov.total_evaluated} user(s) "
        f"(enforceable {cov.enforceable} / not enforceable {cov.not_enforceable} / "
        f"no access {cov.no_access} / undetermined {cov.unknown})  coverage {ratio}\n"
        f"- Cap violations: {result.violations_total} "
        f"(blocked {result.violations_enforced} / not enforceable "
        f"{result.violations_unenforceable})\n"
        f"- Re-allowed: {len(result.allowed_users)} user(s)"
    )

    if cov.not_enforceable_by_reason:
        detail = ", ".join(
            f"{k} {v}" for k, v in sorted(cov.not_enforceable_by_reason.items())
        )
        renderables.append(f"- Not-enforceable reasons: {detail}")

    if result.violations:
        table = Table(title="Cap Violations", header_style="bold red")
        table.add_column("User ID", style="bold")
        table.add_column("Period")
        table.add_column("Metric")
        table.add_column("Limit", justify="right")
        table.add_column("Actual", justify="right")
        table.add_column("Overage", justify="right")
        table.add_column("Action Taken", justify="left")
        for v in result.violations:
            table.add_row(
                v.user_id,
                v.period,
                v.metric_type,
                f"{v.limit:,}",
                f"{v.actual:,}",
                f"{v.overage:,}",
                _action_label(result, v),
            )
        renderables.append(table)

    if result.unenforceable_violations:
        table = Table(
            title="Manual Action Required (cap exceeded but not enforceable)",
            header_style="bold yellow",
        )
        table.add_column("User ID", style="bold")
        table.add_column("Metric")
        table.add_column("Actual", justify="right")
        table.add_column("Limit", justify="right")
        table.add_column("State")
        table.add_column("Reason")
        for v in result.unenforceable_violations:
            table.add_row(
                v.user_id,
                v.metric_type,
                f"{v.actual:,}",
                f"{v.limit:,}",
                v.status.value,
                v.reason.value if v.reason else "-",
            )
        renderables.append(table)

    if result.reallowed_metrics:
        table = Table(title="Re-allowed (Unblocked) Users", header_style="bold green")
        table.add_column("User ID", style="bold")
        table.add_column("Period")
        table.add_column("Current Tokens", justify="right")
        table.add_column("Current Requests", justify="right")
        table.add_column("Action Taken", justify="center")
        label = (
            "[yellow]WOULD RE-ALLOW[/yellow]"
            if result.dry_run
            else "[green]RE-ALLOWED[/green]"
        )
        for m in result.reallowed_metrics:
            table.add_row(
                m.user_id,
                result.period,
                f"{m.total_tokens:,}",
                f"{m.total_requests:,}",
                label,
            )
        renderables.append(table)

    return _render(renderables)
