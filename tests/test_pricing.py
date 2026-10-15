"""Unit tests for pricing, estimated cost calculation, and dollar cap enforcement."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agy_admin.cap_manager import CapManager
from agy_admin.cli import app
from agy_admin.config import DEFAULT_ALLOWED_ROLE, DEFAULT_CAP_ROLE_ID, Settings
from agy_admin.iam_manager import IAMManager
from agy_admin.logging_client import LoggingMetricsClient
from agy_admin.models import (
    CapConfigFile,
    CapRule,
    DisallowMode,
    PeriodType,
    UserCapLimit,
    UserMetric,
    WindowType,
)
from agy_admin.pricing import (
    PriceTable,
    estimate_entry_cost,
    get_default_price_table,
    load_price_table,
)

runner = CliRunner()
PROJECT = "test-pricing-proj"
CAP_ROLE = f"projects/{PROJECT}/roles/{DEFAULT_CAP_ROLE_ID}"


def make_manager(bindings, price_table=None):
    iam = IAMManager(PROJECT, mock_bindings=bindings)
    client = LoggingMetricsClient(PROJECT, client=object(), price_table=price_table)
    return CapManager(
        project_id=PROJECT,
        logging_client=client,
        iam_manager=iam,
        settings=Settings(project_id=PROJECT),
    ), iam


# ---------------------------------------------------------------------------
# 1. Cost of one entry: uncached vs cached split, thinking billed as output
# ---------------------------------------------------------------------------


def test_single_entry_split_and_thinking_as_output():
    table = get_default_price_table()
    ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    # gemini-3.8-flash (2026): input: 0.75, cached: 0.075, output: 3.75
    metadata = {
        "promptTokenCount": 10000,
        "cachedContentTokenCount": 4000,
        "candidatesTokenCount": 500,
        "thoughtsTokenCount": 500,
    }
    cost, priced = estimate_entry_cost("gemini-3.8-flash", metadata, ts, price_table=table)
    assert priced is True
    # uncached = 10000 - 4000 = 6000
    # uncached cost = 6000 * 0.75 / 1e6 = 0.0045
    # cached cost = 4000 * 0.075 / 1e6 = 0.0003
    # output (500 + 500 = 1000) cost = 1000 * 3.75 / 1e6 = 0.00375
    # total = 0.0045 + 0.0003 + 0.00375 = 0.00855
    assert abs(cost - 0.00855) < 1e-7


# ---------------------------------------------------------------------------
# 2. Image model: 1120 candidates at $120/M = $0.1344
# ---------------------------------------------------------------------------


def test_image_model_output_pricing():
    table = get_default_price_table()
    ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    metadata = {
        "promptTokenCount": 0,
        "candidatesTokenCount": 1120,
        "thoughtsTokenCount": 0,
    }
    cost, priced = estimate_entry_cost("gemini-3-pro-image", metadata, ts, price_table=table)
    assert priced is True
    # 1120 candidates at $120 / 1e6 = 0.1344
    assert abs(cost - 0.1344) < 1e-6


# ---------------------------------------------------------------------------
# 3. Long-context tier switch at threshold+1
# ---------------------------------------------------------------------------


def test_long_context_tier_switch():
    table = get_default_price_table()
    ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    # gemini-3.1-pro-preview: threshold = 200000
    # standard: input: 2.00, cached: 0.20, output: 12.00
    # long: input_long: 4.00, cached_long: 0.40, output_long: 18.00

    # At threshold (200,000): standard rate
    meta_std = {
        "promptTokenCount": 200000,
        "cachedContentTokenCount": 0,
        "candidatesTokenCount": 1000,
    }
    cost_std, priced = estimate_entry_cost("gemini-3.1-pro-preview", meta_std, ts, price_table=table)
    assert priced is True
    # 200000 * 2.00 / 1e6 + 1000 * 12.00 / 1e6 = 0.40 + 0.012 = 0.412
    assert abs(cost_std - 0.412) < 1e-6

    # At threshold + 1 (200,001): long rate
    meta_long = {
        "promptTokenCount": 200001,
        "cachedContentTokenCount": 0,
        "candidatesTokenCount": 1000,
    }
    cost_long, priced = estimate_entry_cost("gemini-3.1-pro-preview", meta_long, ts, price_table=table)
    assert priced is True
    # 200001 * 4.00 / 1e6 + 1000 * 18.00 / 1e6 = 0.800004 + 0.018 = 0.818004
    assert abs(cost_long - 0.818004) < 1e-6


# ---------------------------------------------------------------------------
# 4. effective_from: same entry priced differently on 2026-12-31 vs 2027-01-01
# ---------------------------------------------------------------------------


def test_effective_from_date_switching():
    table = get_default_price_table()
    metadata = {
        "promptTokenCount": 1000000,
        "cachedContentTokenCount": 0,
        "candidatesTokenCount": 1000000,
    }
    ts_2026 = datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    ts_2027 = datetime(2027, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    # 2026: input 0.75, output 3.75 -> total = 4.50
    cost_2026, _ = estimate_entry_cost("gemini-3.8-flash", metadata, ts_2026, price_table=table)
    assert abs(cost_2026 - 4.50) < 1e-6

    # 2027: input 1.50, output 7.50 -> total = 9.00
    cost_2027, _ = estimate_entry_cost("gemini-3.8-flash", metadata, ts_2027, price_table=table)
    assert abs(cost_2027 - 9.00) < 1e-6


# ---------------------------------------------------------------------------
# 4b. Gemini 4 Argon: introductory ($2 in / $0.10 cached / $10 out) vs standard ($4 in / $0.20 cached / $20 out)
# ---------------------------------------------------------------------------


def test_gemini_4_argon_pricing_and_date_tiering():
    table = get_default_price_table()
    metadata = {
        "promptTokenCount": 1000000,
        "cachedContentTokenCount": 200000,
        "candidatesTokenCount": 50000,
        "thoughtsTokenCount": 50000,
    }
    # uncached = 800,000; cached = 200,000; total output (candidates + thoughts) = 100,000
    ts_intro = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
    ts_std = datetime(2026, 12, 1, 0, 0, 0, tzinfo=timezone.utc)

    # Introductory rate (before 2026-12-01):
    # uncached: 800k * $2.00 / 1e6 = $1.60
    # cached: 200k * $0.10 / 1e6 = $0.02
    # output: 100k * $10.00 / 1e6 = $1.00
    # total = $2.62
    cost_intro, priced_intro = estimate_entry_cost("gemini-4-argon", metadata, ts_intro, price_table=table)
    assert priced_intro is True
    assert abs(cost_intro - 2.62) < 1e-6

    # Verify aliases resolve to introductory rate
    for alias in ["gemini-argon", "publishers/google/models/gemini-4-argon", "gemini-4-argon-preview"]:
        cost_alias, priced_alias = estimate_entry_cost(alias, metadata, ts_intro, price_table=table)
        assert priced_alias is True
        assert abs(cost_alias - 2.62) < 1e-6

    # Standard rate (effective 2026-12-01):
    # uncached: 800k * $4.00 / 1e6 = $3.20
    # cached: 200k * $0.20 / 1e6 = $0.04
    # output: 100k * $20.00 / 1e6 = $2.00
    # total = $5.24
    cost_std, priced_std = estimate_entry_cost("gemini-4-argon", metadata, ts_std, price_table=table)
    assert priced_std is True
    assert abs(cost_std - 5.24) < 1e-6


# ---------------------------------------------------------------------------
# 5. Unknown model with max and skip policies, and that it is reported
# ---------------------------------------------------------------------------


def test_unknown_model_policies_and_reporting():
    # max policy
    table_max = PriceTable.model_validate({
        "currency": "USD",
        "unknown_model_policy": "max",
        "models": {
            "cheap": [{"effective_from": "2026-01-01", "input": 1.0, "cached": 0.1, "output": 2.0}],
            "expensive": [{"effective_from": "2026-01-01", "input": 10.0, "cached": 1.0, "output": 20.0}],
        },
    })
    ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    metadata = {"promptTokenCount": 1000000, "candidatesTokenCount": 0}

    cost_max, priced_max = estimate_entry_cost("custom-model", metadata, ts, price_table=table_max)
    assert priced_max is False
    assert cost_max == 10.0  # Priced at expensive model

    # skip policy
    table_skip = PriceTable.model_validate({
        "currency": "USD",
        "unknown_model_policy": "skip",
        "models": {
            "cheap": [{"effective_from": "2026-01-01", "input": 1.0, "cached": 0.1, "output": 2.0}],
        },
    })
    cost_skip, priced_skip = estimate_entry_cost("custom-model", metadata, ts, price_table=table_skip)
    assert priced_skip is False
    assert cost_skip == 0.0


# ---------------------------------------------------------------------------
# 6. Regression: Flash 3.8 real numbers (2026 rates)
# uncached 6,050,036, cached 22,448,280, candidates 174,245, thoughts 177,568 -> $7.5404
# ---------------------------------------------------------------------------


def test_flash_38_regression():
    table = get_default_price_table()
    ts = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
    uncached = 6050036
    cached = 22448280
    prompt = uncached + cached
    candidates = 174245
    thoughts = 177568

    metadata = {
        "promptTokenCount": prompt,
        "cachedContentTokenCount": cached,
        "candidatesTokenCount": candidates,
        "thoughtsTokenCount": thoughts,
    }
    cost, priced = estimate_entry_cost("gemini-3.8-flash", metadata, ts, price_table=table)
    assert priced is True
    assert abs(cost - 7.5404) < 0.0001


# ---------------------------------------------------------------------------
# 7. evaluate_violations with cost default + per-user override; log ids with user: prefix
# ---------------------------------------------------------------------------


def test_evaluate_violations_with_cost_and_user_overrides():
    cap_mgr, _ = make_manager({DEFAULT_ALLOWED_ROLE: ["user:alice@corp.com", "user:bob@corp.com"]})
    rule = CapRule(period=PeriodType.DAILY, max_cost_usd=10.0)
    config = CapConfigFile(
        default=UserCapLimit(max_cost_usd=10.0),
        overrides={
            "user:alice@corp.com": UserCapLimit(max_usd=20.0),
        },
    )

    metrics = {
        "user:alice@corp.com": UserMetric(user_id="user:alice@corp.com", estimated_cost_usd=15.0),
        "bob@corp.com": UserMetric(user_id="bob@corp.com", estimated_cost_usd=12.5),
        "charlie@corp.com": UserMetric(user_id="charlie@corp.com", estimated_cost_usd=5.0),
    }

    violations = cap_mgr.evaluate_violations(metrics, rule, user_overrides=config.overrides)
    # Alice: limit $20.0, actual $15.0 -> OK
    # Bob: limit $10.0, actual $12.5 -> Violation
    # Charlie: limit $10.0, actual $5.0 -> OK
    assert len(violations) == 1
    v = violations[0]
    assert v.user_id == "bob@corp.com"
    assert v.metric_type == "cost_usd"
    assert v.limit == 10.0
    assert v.actual == 12.5
    assert v.overage == 2.5


# ---------------------------------------------------------------------------
# 8. Restore: a CAPPED user at $8 with override $10 is restored; at $12 stays capped
#    (two consecutive cycles, no flapping)
# ---------------------------------------------------------------------------


def test_restore_cost_cap_no_flapping(monkeypatch):
    # User is initially capped
    bindings = {
        DEFAULT_ALLOWED_ROLE: [],
        CAP_ROLE: ["user:recovering@corp.com", "user:still_over@corp.com"],
    }
    cap_mgr, iam = make_manager(bindings)

    config = CapConfigFile(
        default=UserCapLimit(max_cost_usd=10.0),
    )

    # Cycle 1: recovering is at $8.0 (below limit), still_over is at $12.0 (above limit)
    mock_metrics_cycle1 = {
        "user:recovering@corp.com": UserMetric(
            user_id="recovering@corp.com", estimated_cost_usd=8.0
        ),
        "user:still_over@corp.com": UserMetric(
            user_id="still_over@corp.com", estimated_cost_usd=12.0
        ),
    }

    # Monkeypatch fetch_metrics on the logging_client
    from agy_admin.logging_client import MetricsFetchResult

    monkeypatch.setattr(
        cap_mgr.logging_client,
        "fetch_metrics",
        lambda **kw: MetricsFetchResult(metrics=mock_metrics_cycle1, entry_count=2),
    )

    res1 = cap_mgr.enforce_caps(
        period=PeriodType.DAILY,
        max_cost_usd=10.0,
        disallow_mode=DisallowMode.CUSTOM_ROLE,
        dry_run=False,
    )
    assert "recovering@corp.com" in res1.allowed_users
    assert "user:recovering@corp.com" in bindings[DEFAULT_ALLOWED_ROLE]
    assert "user:recovering@corp.com" not in bindings[CAP_ROLE]
    assert "user:still_over@corp.com" in bindings[CAP_ROLE]

    # Cycle 2: recovering is still at $8.0, still_over is still at $12.0
    res2 = cap_mgr.enforce_caps(
        period=PeriodType.DAILY,
        max_cost_usd=10.0,
        disallow_mode=DisallowMode.CUSTOM_ROLE,
        dry_run=False,
    )
    # recovering should be no-op (already allowed, not re-allowed again)
    assert res2.allowed_users == []
    assert "user:recovering@corp.com" in bindings[DEFAULT_ALLOWED_ROLE]
    assert "user:still_over@corp.com" in bindings[CAP_ROLE]


# ---------------------------------------------------------------------------
# 9. CLI --cost-usd validation, batch CAP_COST_USD, malformed price file error
# ---------------------------------------------------------------------------


def test_cli_cost_validation():
    # Negative cost rejected
    res_neg = runner.invoke(app, ["cap", "apply", "--cost-usd", "-5", "--project", PROJECT])
    assert res_neg.exit_code == 1
    assert "must be non-negative" in res_neg.output

    # Nonexistent price file rejected
    res_missing = runner.invoke(
        app, ["cap", "apply", "--cost-usd", "10", "--price-file", "nonexistent.json", "--project", PROJECT]
    )
    assert res_missing.exit_code == 1
    assert "Price file not found" in res_missing.output


def test_malformed_price_file_fails_fast(tmp_path: Path):
    bad_file = tmp_path / "bad_prices.json"
    bad_file.write_text(json.dumps({
        "currency": "USD",
        "unknown_model_policy": "invalid_policy",
        "models": {},
    }))

    with pytest.raises(Exception):
        load_price_table(bad_file)
