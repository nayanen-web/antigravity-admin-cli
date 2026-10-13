"""Cloud Logging client for Antigravity telemetry metrics collection."""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from agy_admin.iam_manager import normalize_email
from agy_admin.models import AuditAction, PeriodType, UserMetric, WindowType

logger = logging.getLogger(__name__)

#: Conservative principal pattern. IDs that do not match are never interpolated
#: into a log filter.
_SAFE_USER_ID = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

#: Log labels that may carry the model identifier. v0.1.0 documented
#: ``labels.model_id`` but only read ``labels.model``, so the column was always
#: empty.
_MODEL_LABELS = ("model_id", "model")


def calculate_time_range(
    period: PeriodType,
    window_type: WindowType = WindowType.CALENDAR,
    now: Optional[datetime] = None,
) -> tuple[datetime, datetime]:
    """Calculates start and end datetime for the given period and window type."""
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    end_time = now

    if period == PeriodType.DAILY:
        if window_type == WindowType.CALENDAR:
            start_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            start_time = now - timedelta(days=1)
    elif period == PeriodType.WEEKLY:
        if window_type == WindowType.CALENDAR:
            start_time = (now - timedelta(days=now.weekday())).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
        else:
            start_time = now - timedelta(days=7)
    elif period == PeriodType.MONTHLY:
        if window_type == WindowType.CALENDAR:
            start_time = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            start_time = now - timedelta(days=30)
    elif period == PeriodType.ALL:
        # Bounded at 90 days; "all" is a misnomer kept for CLI compatibility.
        start_time = now - timedelta(days=90)
    else:
        start_time = now - timedelta(days=1)

    return start_time, end_time


@dataclass
class MetricsFetchResult:
    """Metrics plus the observability health signal used by gate G3.

    Distinguishing "zero usage" from "no telemetry" is what stops the tool from
    restoring access to everyone when logging breaks.
    """

    metrics: Dict[str, UserMetric] = field(default_factory=dict)
    entry_count: int = 0
    query_ok: bool = True
    error: str = ""

    @property
    def healthy(self) -> bool:
        return self.query_ok and self.entry_count > 0


def _label_model(labels: dict) -> str:
    for key in _MODEL_LABELS:
        value = labels.get(key)
        if value:
            return value
    return "unknown_model"


def _to_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class LoggingMetricsClient:
    def __init__(self, project_id: str, client=None):
        self.project_id = project_id
        self._client = client

    def _get_client(self):
        if self._client is None:
            from google.cloud import logging as cloud_logging

            self._client = cloud_logging.Client(project=self.project_id)
        return self._client

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def fetch_metrics(
        self,
        period: PeriodType = PeriodType.DAILY,
        window_type: WindowType = WindowType.CALENDAR,
        user_ids: Optional[List[str]] = None,
        mock_entries: Optional[List[dict]] = None,
        now: Optional[datetime] = None,
    ) -> MetricsFetchResult:
        """Queries Cloud Logging and returns metrics plus a health signal."""
        start_time, end_time = calculate_time_range(period, window_type, now=now)

        if mock_entries is not None:
            metrics = self._aggregate_from_entries(
                mock_entries, start_time, end_time, user_ids
            )
            return MetricsFetchResult(
                metrics=metrics, entry_count=len(mock_entries), query_ok=True
            )

        return self._query_cloud_logging(start_time, end_time, user_ids)

    def fetch_user_metrics(
        self,
        period: PeriodType = PeriodType.DAILY,
        window_type: WindowType = WindowType.CALENDAR,
        user_ids: Optional[List[str]] = None,
        mock_entries: Optional[List[dict]] = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, UserMetric]:
        """Convenience wrapper returning only the aggregated metrics."""
        return self.fetch_metrics(
            period=period,
            window_type=window_type,
            user_ids=user_ids,
            mock_entries=mock_entries,
            now=now,
        ).metrics

    def _build_filter(
        self,
        start_time: datetime,
        end_time: datetime,
        user_ids: Optional[List[str]] = None,
    ) -> str:
        start_str = start_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = end_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        filters = [
            f'logName="projects/{self.project_id}/logs/'
            f'businessaicode.googleapis.com%2Finference_response"',
            f'timestamp >= "{start_str}"',
            f'timestamp <= "{end_str}"',
        ]

        if user_ids:
            safe = [u for u in user_ids if _SAFE_USER_ID.match(u or "")]
            rejected = [u for u in user_ids if u not in safe]
            if rejected:
                logger.warning(
                    "Ignoring %d user id(s) with unsupported characters in log filter: %s",
                    len(rejected),
                    ", ".join(rejected[:5]),
                )
            if safe:
                clauses = " OR ".join([f'labels.user_id = "{u}"' for u in safe])
                filters.append(f"({clauses})" if len(safe) > 1 else clauses)

        return " AND ".join(filters)

    def _query_cloud_logging(
        self,
        start_time: datetime,
        end_time: datetime,
        user_ids: Optional[List[str]] = None,
    ) -> MetricsFetchResult:
        lql_filter = self._build_filter(start_time, end_time, user_ids)
        logger.info("Executing Cloud Logging query: %s", lql_filter)

        try:
            client = self._get_client()
            entries = client.list_entries(filter_=lql_filter, page_size=1000)
            return self._aggregate_cloud_logging_entries(entries)
        except Exception as e:  # noqa: BLE001
            # Never surface a query failure as "zero usage"; gate G3 depends on
            # being able to tell the difference.
            logger.error("Failed to query Cloud Logging: %s", e)
            return MetricsFetchResult(query_ok=False, error=str(e))

    def _aggregate_cloud_logging_entries(self, entries) -> MetricsFetchResult:
        result = MetricsFetchResult()

        for entry in entries:
            result.entry_count += 1
            labels = entry.labels or {}
            user_id = labels.get("user_id")
            if not user_id:
                continue

            canonical_user_id = normalize_email(user_id)
            payload = entry.payload
            metadata = {}
            if isinstance(payload, dict):
                metadata = payload.get("metadata") or {}

            self._accumulate(
                result.metrics,
                user_id=canonical_user_id,
                client_name=labels.get("client_name") or "unknown_client",
                model=_label_model(labels),
                metadata=metadata,
                ts=entry.timestamp,
            )

        return result

    def _aggregate_from_entries(
        self,
        raw_entries: List[dict],
        start_time: datetime,
        end_time: datetime,
        user_ids: Optional[List[str]] = None,
    ) -> Dict[str, UserMetric]:
        """Aggregate helper for mock entries or test fixtures."""
        metrics: Dict[str, UserMetric] = {}
        wanted = {normalize_email(u) for u in user_ids} if user_ids else None

        for entry in raw_entries:
            ts = entry.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if ts and (ts < start_time or ts > end_time):
                continue

            labels = entry.get("labels", {})
            user_id = labels.get("user_id")
            if not user_id:
                continue
            canonical_user_id = normalize_email(user_id)
            if wanted and canonical_user_id not in wanted:
                continue

            payload = entry.get("jsonPayload", {})
            self._accumulate(
                metrics,
                user_id=canonical_user_id,
                client_name=labels.get("client_name") or "unknown_client",
                model=_label_model(labels),
                metadata=payload.get("metadata", {}),
                ts=ts,
            )

        return metrics

    @staticmethod
    def _accumulate(
        metrics: Dict[str, UserMetric],
        user_id: str,
        client_name: str,
        model: str,
        metadata: dict,
        ts,
    ) -> None:
        total_tokens = _to_int(metadata.get("totalTokenCount", 0))
        prompt_tokens = _to_int(metadata.get("promptTokenCount", 0))
        candidates_tokens = _to_int(metadata.get("candidatesTokenCount", 0))

        m = metrics.get(user_id)
        if m is None:
            metrics[user_id] = UserMetric(
                user_id=user_id,
                total_requests=1,
                total_tokens=total_tokens,
                prompt_tokens=prompt_tokens,
                candidates_tokens=candidates_tokens,
                clients=[client_name] if client_name != "unknown_client" else [],
                models=[model] if model != "unknown_model" else [],
                first_active=ts,
                last_active=ts,
            )
            return

        m.total_requests += 1
        m.total_tokens += total_tokens
        m.prompt_tokens += prompt_tokens
        m.candidates_tokens += candidates_tokens
        if client_name != "unknown_client" and client_name not in m.clients:
            m.clients.append(client_name)
        if model != "unknown_model" and model not in m.models:
            m.models.append(model)
        if ts:
            if m.first_active is None or ts < m.first_active:
                m.first_active = ts
            if m.last_active is None or ts > m.last_active:
                m.last_active = ts

    # ------------------------------------------------------------------
    # Audit trail
    # ------------------------------------------------------------------

    def write_audit_log(
        self,
        user_id: str,
        action,
        reason: str,
        details: Optional[dict] = None,
        dry_run: bool = False,
        status: Optional[str] = None,
        reason_code: Optional[str] = None,
    ) -> dict:
        """Writes an administrative audit entry under agy-admin/admin_actions.

        Requires ``roles/logging.logWriter``. A write failure is recorded in the
        returned payload so callers can surface a degraded audit trail instead
        of assuming the record exists.
        """
        action_value = action.value if isinstance(action, AuditAction) else str(action)
        payload = {
            "user_id": user_id,
            "action": action_value,
            "reason": reason,
            "status": status,
            "reason_code": reason_code,
            "dry_run": dry_run,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "written": False,
        }
        if details:
            payload["details"] = details

        try:
            client = self._get_client()
            if hasattr(client, "logger"):
                cloud_logger = client.logger("agy-admin/admin_actions")
                cloud_logger.log_struct(
                    {k: v for k, v in payload.items() if k != "written"},
                    severity="INFO" if dry_run else "NOTICE",
                )
                payload["written"] = True
            logger.info(
                "Audit: user=%s action=%s reason=%s", user_id, action_value, reason
            )
        except Exception as e:  # noqa: BLE001
            payload["write_error"] = str(e)
            logger.warning(
                "Audit log write failed for %s (action=%s): %s. "
                "Verify the identity holds roles/logging.logWriter.",
                user_id,
                action_value,
                e,
            )

        return payload
