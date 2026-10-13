"""Pricing models and list-price cost estimation for Antigravity telemetry."""

from datetime import date, datetime, timezone
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Literal, Optional, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


def _to_int(val) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


def _parse_timestamp(ts: Optional[Union[datetime, str]]) -> datetime:
    if ts is None:
        return datetime.now(timezone.utc)
    if isinstance(ts, str):
        cleaned = ts.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(cleaned)
        except ValueError:
            # Fallback for plain date strings like "2026-01-01"
            try:
                d = date.fromisoformat(cleaned)
                dt = datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
            except ValueError:
                return datetime.now(timezone.utc)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


class PriceRate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    effective_from: str
    input: float = Field(..., ge=0)
    cached: float = Field(..., ge=0)
    output: float = Field(..., ge=0)
    long_context_threshold: Optional[int] = Field(None, ge=0)
    input_long: Optional[float] = Field(None, ge=0)
    cached_long: Optional[float] = Field(None, ge=0)
    output_long: Optional[float] = Field(None, ge=0)
    image_output: Optional[float] = Field(None, ge=0)
    image_output_long: Optional[float] = Field(None, ge=0)


class PriceTable(BaseModel):
    model_config = ConfigDict(extra="forbid")

    currency: str = "USD"
    unknown_model_policy: Literal["max", "skip"] = "max"
    models: Dict[str, List[PriceRate]]


def load_price_table(path: Optional[Union[str, Path]] = None) -> PriceTable:
    """Loads and validates a price table file with Pydantic."""
    if path is None:
        env_path = os.environ.get("CAP_PRICE_FILE")
        if env_path:
            target = Path(env_path)
        else:
            target = Path(__file__).parent / "model_prices.json"
    else:
        target = Path(path)

    if not target.is_file():
        raise FileNotFoundError(f"Price table file not found: {target}")

    with open(target, "r", encoding="utf-8") as f:
        data = json.load(f)

    return PriceTable.model_validate(data)


_DEFAULT_PRICE_TABLE: Optional[PriceTable] = None


def get_default_price_table() -> PriceTable:
    """Returns the cached bundled price table or loads it."""
    global _DEFAULT_PRICE_TABLE
    if _DEFAULT_PRICE_TABLE is None:
        _DEFAULT_PRICE_TABLE = load_price_table()
    return _DEFAULT_PRICE_TABLE


def _select_effective_rate(rates: List[PriceRate], entry_dt: datetime) -> PriceRate:
    """Picks the price rate whose effective_from <= entry_dt (latest wins)."""
    if not rates:
        raise ValueError("Model rates list cannot be empty")

    parsed_rates = []
    for r in rates:
        r_dt = _parse_timestamp(r.effective_from)
        parsed_rates.append((r_dt, r))

    parsed_rates.sort(key=lambda item: item[0])

    applicable = [r for r_dt, r in parsed_rates if r_dt <= entry_dt]
    if applicable:
        return applicable[-1]
    return parsed_rates[0][1]


def _compute_rate_cost(
    rate: PriceRate,
    prompt: int,
    cached: int,
    candidates: int,
    thoughts: int,
) -> float:
    """Computes cost in USD for a single log entry under the given PriceRate."""
    uncached_in = max(0, prompt - cached)
    is_long = (
        rate.long_context_threshold is not None
        and prompt > rate.long_context_threshold
    )

    in_rate = rate.input_long if (is_long and rate.input_long is not None) else rate.input
    cached_rate = rate.cached_long if (is_long and rate.cached_long is not None) else rate.cached
    out_rate = rate.output_long if (is_long and rate.output_long is not None) else rate.output

    if rate.image_output is not None:
        cand_rate = (
            rate.image_output_long
            if (is_long and rate.image_output_long is not None)
            else rate.image_output
        )
        cost = (
            uncached_in * in_rate
            + cached * cached_rate
            + candidates * cand_rate
            + thoughts * out_rate
        )
    else:
        cost = (
            uncached_in * in_rate
            + cached * cached_rate
            + (candidates + thoughts) * out_rate
        )

    return cost / 1_000_000.0


def estimate_entry_cost(
    model: Union[str, PriceTable],
    metadata: Optional[dict] = None,
    ts: Optional[Union[datetime, str, PriceTable]] = None,
    price_table: Optional[PriceTable] = None,
) -> Tuple[float, bool]:
    """Estimates entry cost in USD at list price.

    Returns:
        (usd_cost, priced_flag) where priced_flag is True if the model is known,
        False if unknown.
    """
    if isinstance(model, PriceTable):
        # Dispatched from estimate_entry_cost(price_table, model_name, metadata, ts)
        actual_table = model
        actual_model = str(metadata) if metadata is not None else ""
        actual_meta = ts if isinstance(ts, dict) else {}
        actual_ts = price_table if isinstance(price_table, (datetime, str)) else None
    else:
        if isinstance(ts, PriceTable):
            actual_table = ts
            actual_ts = None
        else:
            actual_table = price_table or get_default_price_table()
            actual_ts = ts
        actual_model = str(model)
        actual_meta = metadata if isinstance(metadata, dict) else {}

    entry_dt = _parse_timestamp(actual_ts)

    prompt = _to_int(actual_meta.get("promptTokenCount", 0))
    cached = _to_int(actual_meta.get("cachedContentTokenCount", 0))
    candidates = _to_int(actual_meta.get("candidatesTokenCount", 0))
    thoughts = _to_int(actual_meta.get("thoughtsTokenCount", 0))

    model_key = actual_model
    if model_key not in actual_table.models and "/" in model_key:
        short_key = model_key.split("/")[-1]
        if short_key in actual_table.models:
            model_key = short_key

    if model_key in actual_table.models:
        rates = actual_table.models[model_key]
        rate = _select_effective_rate(rates, entry_dt)
        usd = _compute_rate_cost(rate, prompt, cached, candidates, thoughts)
        return (usd, True)

    # Unknown model
    if actual_table.unknown_model_policy == "skip":
        return (0.0, False)

    # Policy "max": price at the most expensive known model for this entry
    costs = []
    for m_rates in actual_table.models.values():
        eff_rate = _select_effective_rate(m_rates, entry_dt)
        costs.append(_compute_rate_cost(eff_rate, prompt, cached, candidates, thoughts))

    max_usd = max(costs) if costs else 0.0
    return (max_usd, False)
