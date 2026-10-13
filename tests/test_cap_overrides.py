"""Unit tests for user-specific cap overrides (Workaround 3)."""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from agy_admin.cap_manager import CapManager, load_cap_config
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
    UserStatus,
)

PROJECT = "test-proj"
CAP_ROLE = f"projects/{PROJECT}/roles/{DEFAULT_CAP_ROLE_ID}"


class TestCapOverrides(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.config_path = Path(self.tmp_dir.name) / "user_caps.json"
        self.config_data = {
            "default": {"max_tokens": 5000000, "max_requests": 1000},
            "overrides": {
                "user@example.com": {"max_tokens": 15000000},
                "lead@example.com": {"max_tokens": 25000000, "max_requests": 5000},
            },
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self.config_data, f)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def make_manager(self, bindings):
        iam = IAMManager(PROJECT, mock_bindings=bindings)
        cap_mgr = CapManager(
            project_id=PROJECT,
            logging_client=LoggingMetricsClient(PROJECT, client=object()),
            iam_manager=iam,
            settings=Settings(project_id=PROJECT),
        )
        return cap_mgr, iam

    def test_load_cap_config_success(self):
        config = load_cap_config(self.config_path)
        self.assertEqual(config.default.max_tokens, 5000000)
        self.assertEqual(config.default.max_requests, 1000)
        self.assertIn("user@example.com", config.overrides)
        self.assertEqual(config.overrides["user@example.com"].max_tokens, 15000000)
        self.assertIsNone(config.overrides["user@example.com"].max_requests)
        self.assertEqual(config.overrides["lead@example.com"].max_tokens, 25000000)
        self.assertEqual(config.overrides["lead@example.com"].max_requests, 5000)

    def test_load_cap_config_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_cap_config(Path(self.tmp_dir.name) / "nonexistent.json")

    def test_evaluate_violations_honors_user_overrides(self):
        cap_mgr, _ = self.make_manager({})
        rule = CapRule(period=PeriodType.MONTHLY, max_tokens=5000000, max_requests=1000)

        overrides = {
            "user@example.com": UserCapLimit(max_tokens=15000000),
            "lead@example.com": UserCapLimit(max_tokens=25000000, max_requests=5000),
        }

        metrics = {
            # Standard user exceeding default 5M tokens
            "standard@example.com": UserMetric(
                user_id="standard@example.com",
                total_tokens=6000000,
                total_requests=500,
            ),
            # Overridden user at 10M tokens (above 5M default, but below their 15M limit) -> NO violation
            "user@example.com": UserMetric(
                user_id="user@example.com",
                total_tokens=10000000,
                total_requests=500,
            ),
            # Overridden user at 18M tokens (above their 15M limit) -> VIOLATION
            "heavy_user@example.com": UserMetric(
                user_id="heavy_user@example.com",
                total_tokens=18000000,
                total_requests=500,
            ),
        }
        # Add override for heavy_user
        overrides["heavy_user@example.com"] = UserCapLimit(max_tokens=15000000)

        violations = cap_mgr.evaluate_violations(metrics, rule, user_overrides=overrides)
        violating_users = {v.user_id: v for v in violations}

        # standard user violated default limit
        self.assertIn("standard@example.com", violating_users)
        self.assertEqual(violating_users["standard@example.com"].limit, 5000000)
        self.assertEqual(violating_users["standard@example.com"].overage, 1000000)
        self.assertFalse(violating_users["standard@example.com"].is_override)

        # user@example.com did NOT violate because their limit is 15M
        self.assertNotIn("user@example.com", violating_users)

        # heavy_user@example.com violated their custom 15M limit
        self.assertIn("heavy_user@example.com", violating_users)
        self.assertEqual(violating_users["heavy_user@example.com"].limit, 15000000)
        self.assertEqual(violating_users["heavy_user@example.com"].overage, 3000000)
        self.assertTrue(violating_users["heavy_user@example.com"].is_override)

    def test_evaluate_violations_case_insensitive_email(self):
        cap_mgr, _ = self.make_manager({})
        rule = CapRule(period=PeriodType.MONTHLY, max_tokens=5000000)
        overrides = {
            "user@example.com": {"max_tokens": 15000000}
        }

        # Uppercase in metric user_id
        metrics = {
            "User@Example.com": UserMetric(
                user_id="User@Example.com",
                total_tokens=10000000,
                total_requests=100,
            )
        }

        violations = cap_mgr.evaluate_violations(metrics, rule, user_overrides=overrides)
        # Should not violate because 10M < 15M
        self.assertEqual(len(violations), 0)

    def test_evaluate_violations_with_prefixed_log_id(self):
        """Bug 1 reproduction: log principal with user: prefix must match bare email override."""
        cap_mgr, _ = self.make_manager({})
        rule = CapRule(period=PeriodType.MONTHLY, max_tokens=5000000)
        overrides = {
            "alice@qburst.com": UserCapLimit(max_tokens=15000000)
        }

        # Cloud Logging principal has user: prefix; usage is 10M (under 15M override, but over 5M default)
        metrics = {
            "user:alice@qburst.com": UserMetric(
                user_id="user:alice@qburst.com",
                total_tokens=10000000,
                total_requests=100,
            )
        }

        violations = cap_mgr.evaluate_violations(metrics, rule, user_overrides=overrides)
        # Should not violate because 10M < 15M override.
        self.assertEqual(len(violations), 0)

    def test_enforce_caps_prefixed_log_ids_and_no_flapping(self):
        """Bug 2 reproduction:
        (a) override user over override limit is correctly flagged
        (b) currently-capped user still over cap is NOT restored, while one under cap IS restored
        """
        bindings = {
            CAP_ROLE: [
                "user:capped_over@example.com",
                "user:capped_under@example.com",
            ],
            DEFAULT_ALLOWED_ROLE: [
                "user:heavy_override@example.com",
            ],
        }
        cap_mgr, iam = self.make_manager(bindings)

        mock_entries = [
            # (a) Override user over limit (18M > 15M override)
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "labels": {"user_id": "user:heavy_override@example.com", "client_name": "antigravity"},
                "jsonPayload": {"metadata": {"totalTokenCount": 18000000}},
            },
            # (b1) Currently-capped user STILL over cap (6M > 5M default)
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "labels": {"user_id": "user:capped_over@example.com", "client_name": "antigravity"},
                "jsonPayload": {"metadata": {"totalTokenCount": 6000000}},
            },
            # (b2) Currently-capped user NOW under cap (1M <= 5M default)
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "labels": {"user_id": "user:capped_under@example.com", "client_name": "antigravity"},
                "jsonPayload": {"metadata": {"totalTokenCount": 1000000}},
            },
        ]

        # Use config where heavy_override has 15M max_tokens override
        overrides_cfg_path = Path(self.tmp_dir.name) / "test_flapping_caps.json"
        with open(overrides_cfg_path, "w", encoding="utf-8") as f:
            json.dump({
                "default": {"max_tokens": 5000000},
                "overrides": {
                    "heavy_override@example.com": {"max_tokens": 15000000}
                }
            }, f)

        result = cap_mgr.enforce_caps(
            period=PeriodType.MONTHLY,
            mock_entries=mock_entries,
            config_file=overrides_cfg_path,
            disallow_mode=DisallowMode.CUSTOM_ROLE,
            dry_run=False,
        )

        self.assertFalse(result.aborted)

        # (a) Override user over limit is correctly flagged and disallowed
        heavy_violations = [v for v in result.violations if "heavy_override@example.com" in v.user_id]
        self.assertEqual(len(heavy_violations), 1)
        self.assertEqual(heavy_violations[0].limit, 15000000)
        self.assertTrue(heavy_violations[0].is_override)
        self.assertIn("heavy_override@example.com", [u.replace("user:", "") for u in result.disallowed_users])

        # (b) Currently-capped user still over cap must NOT be restored (no flapping)
        allowed_normalized = [u.replace("user:", "") for u in result.allowed_users]
        self.assertNotIn("capped_over@example.com", allowed_normalized)

        # Currently-capped user now under cap IS restored exactly once
        self.assertIn("capped_under@example.com", allowed_normalized)
        self.assertEqual(allowed_normalized.count("capped_under@example.com"), 1)

        # Verify IAM policy
        snap = iam.get_policy_snapshot()
        self.assertIn("user:capped_over@example.com", snap.members(CAP_ROLE))
        self.assertIn("user:capped_under@example.com", snap.members(DEFAULT_ALLOWED_ROLE))
        self.assertNotIn("user:capped_under@example.com", snap.members(CAP_ROLE))

    def test_enforce_caps_with_config_file(self):
        bindings = {
            DEFAULT_ALLOWED_ROLE: [
                "user:standard@example.com",
                "user:user@example.com",
            ]
        }
        cap_mgr, iam = self.make_manager(bindings)

        mock_entries = [
            # standard user exceeds default (6M tokens)
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "labels": {"user_id": "standard@example.com", "client_name": "antigravity"},
                "jsonPayload": {"metadata": {"totalTokenCount": 6000000}},
            },
            # user@example.com has 10M tokens (under 15M override)
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "labels": {"user_id": "user@example.com", "client_name": "antigravity"},
                "jsonPayload": {"metadata": {"totalTokenCount": 10000000}},
            },
        ]

        result = cap_mgr.enforce_caps(
            period=PeriodType.MONTHLY,
            mock_entries=mock_entries,
            config_file=self.config_path,
            disallow_mode=DisallowMode.CUSTOM_ROLE,
            dry_run=False,
        )

        self.assertFalse(result.aborted)
        # standard user blocked
        self.assertIn("standard@example.com", result.disallowed_users)
        # user@example.com NOT blocked
        self.assertNotIn("user@example.com", result.disallowed_users)
        # Verify IAM role update
        snap = iam.get_policy_snapshot()
        self.assertIn("user:standard@example.com", snap.members(CAP_ROLE))
        self.assertIn("user:user@example.com", snap.members(DEFAULT_ALLOWED_ROLE))

    def test_config_file_authoritative_over_passed_limits(self):
        """Bug 3 reproduction:
        When config_file is set, the config file's default must be authoritative.
        Passed max_tokens (e.g. 1M from env/deploy) must not override the config file's default (5M).
        """
        bindings = {
            DEFAULT_ALLOWED_ROLE: [
                "user:bob@example.com",
            ]
        }
        cap_mgr, iam = self.make_manager(bindings)

        # Bob has 3M tokens and 500 requests.
        # Under config default (5M tokens), Bob is within limits.
        # But if passed max_tokens=1000000 overrides config, Bob would falsely violate.
        mock_entries = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "labels": {"user_id": "bob@example.com", "client_name": "antigravity"},
                "jsonPayload": {"metadata": {"totalTokenCount": 3000000}},
            },
        ]

        result = cap_mgr.enforce_caps(
            period=PeriodType.MONTHLY,
            max_tokens=1000000,  # Fallback/env value that should NOT override config file default (5M)
            mock_entries=mock_entries,
            config_file=self.config_path,  # Has default max_tokens: 5000000
            disallow_mode=DisallowMode.CUSTOM_ROLE,
            dry_run=False,
        )

        self.assertFalse(result.aborted)
        self.assertEqual(len(result.violations), 0)
        self.assertEqual(len(result.disallowed_users), 0)


if __name__ == "__main__":
    unittest.main()

