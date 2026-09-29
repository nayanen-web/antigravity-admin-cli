# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-09-12

Enforcement safety redesign. v0.1.0 answered one question ("does this user hold
a `user:` binding of the base role?") and acted on the answer unconditionally.
That silently mislabelled every user whose access came from a group, a domain
binding, an inherited binding, or another access-granting role, and reported
failed enforcement as success.

v0.2.0 answers a different question: **can this tool actually control this
user's access, and how do we know?** When the answer is "no" or "cannot tell",
no IAM mutation is performed and the reason is recorded.

### BREAKING

- **`UserStatus` values replaced.** `ALLOWED`, `ALLOWED_PRIVILEGED`,
  `ALLOWED_BY_OTHER_ROLES`, and `DISALLOWED` are gone. The new values are
  `ENFORCEABLE_ALLOWED`, `CAPPED_BY_TOOL`, `BLOCKED_BY_ADMIN`,
  `NOT_ENFORCEABLE`, `NO_ACCESS`, `UNKNOWN`. `--filter-status` now accepts
  these values (and `all`) and rejects anything else instead of silently
  returning an empty table.
- **Two marker roles instead of one.** `CustomAntigravityCapBlocked` is applied
  by the automatic cycle and may be reversed automatically;
  `CustomAntigravityAdminBlocked` is applied by `agy-admin disallow` and is
  never reversed automatically. Run `scripts/create_custom_role.sh` again to
  create both. Members of the v0.1.0 role `CustomAntigravityRestrictedUser` are
  conservatively treated as `BLOCKED_BY_ADMIN`; the script prints migration
  commands.
- **`IAMManager.allow_users()` / `disallow_users()` return `ActionOutcome`**
  (`applied` / `no_op` / `refused`) instead of a `(updated, skipped)` tuple.
- **`IAMManager` constructor signature changed**: `restricted_role_id` is
  replaced by `cap_role_id`, `admin_role_id`, `legacy_role_id`, plus
  `privileged_roles`, `other_access_roles`, `require_ancestor_check`, and
  `allow_group_coexistence`. Use `iam_manager.build_iam_manager(settings)`.
- **`IAMManager.get_restricted_users()` removed**, replaced by
  `get_capped_users()` and `get_admin_blocked_users()`.
- **`IAMManager.get_iam_policy_bindings()` removed**, replaced by
  `get_policy_snapshot()` which returns a `PolicySnapshot` carrying a
  `readable` flag.
- **`LoggingMetricsClient.fetch_metrics()`** is the new primary API and returns
  `MetricsFetchResult` (metrics plus a telemetry health signal).
  `fetch_user_metrics()` remains as a thin compatibility wrapper.
- **New CLI exit codes**: `2` when one or more actions were refused, `3` when an
  enforcement cycle aborted on a safety gate. The batch job exits `3` on abort
  and `1` on misconfiguration.
- `CapRule.is_exceeded()` removed; use `CapManager.evaluate_violations()`.

### Fixed

- **Re-allow was a negation, not a whitelist.** Any user not holding the base
  role was `DISALLOWED`, and every `DISALLOWED` user was re-granted access once
  usage fell under the cap. With zero log entries — a broken query, a disabled
  Metadata Logging setting, a new project — the cycle granted the base role to
  every marker-role holder. Automatic re-allow is now restricted to
  `CAPPED_BY_TOOL` and additionally gated on telemetry health (G3).
- **Manual blocks were undone automatically.** An offboarded user blocked by an
  administrator was restored on the next quiet cycle. Manual blocks now use a
  separate marker role that the cycle never touches.
- **Users with no binding at all were granted access.** A never-onboarded user
  who appeared in the logs was classified `DISALLOWED` and therefore "restored"
  — creating a binding that never existed. They are now `NO_ACCESS` and are
  never granted automatically.
- **Group/domain grants produced false success reports.** With
  `group:...` bound to the base role, `disallow` reported the user as blocked
  while access remained intact, and after two cycles the net effect was a *new*
  individual grant. Such users are now `NOT_ENFORCEABLE /
  GROUP_GRANT_PRESENT`, are refused, and appear under "Manual Action Required".
- **Cap violators that could not be blocked were labelled `ALREADY BLOCKED`**
  and were absent from the structured output. They are now reported as
  `NOT ENFORCEABLE (<reason>)`, counted separately, and emitted in
  `unenforceable_violations`.
- **An unreadable IAM policy was treated as "no bindings"** (fail-open). The
  cycle now aborts on gate G1 and manual commands refuse to act.
- **Duplicate role bindings were overwritten.** A role may legally appear more
  than once in a policy (one unconditional plus one or more conditional
  bindings); `bindings[role] = members` dropped all but the last. Members are
  now merged, and conditional members are tracked separately.
- **Email comparison was case-sensitive**, so `user:Alice.Kim@corp.com` was
  never matched against `alice.kim@corp.com`. Principals are now normalized.
- **The policy was read at version 1.** Writing such a policy back can delete
  every conditional binding in the project. Reads now request
  `requested_policy_version=3` and only unconditional bindings are edited.
- **One read-modify-write per user.** A cycle affecting N users issued N policy
  reads and N writes, multiplying quota use and the window for lost updates.
  All changes are now applied in a single batch.
- **`gcloud` fallback failures were swallowed**, so a failed revocation was
  reported as a success. They now propagate.
- **Documented `labels.model_id` was never read** (the code read
  `labels.model`), so the Models column was always empty. Both keys are now
  supported, `model_id` first.
- **The log filter required `jsonPayload.metadata.totalTokenCount:*`**, dropping
  requests that produced no token metadata and undercounting request volume.
  The condition was removed.
- **User IDs were interpolated into the log filter unescaped.** They are now
  validated against a conservative email pattern and rejected otherwise.
- **Audit log writes always failed silently.** The deployment granted
  `roles/logging.viewer` but not `roles/logging.logWriter`. The role is now
  granted, and the write result is reported in the payload (`written`,
  `write_error`) instead of being assumed.
- **CSV/text user files fed their header row into IAM.** Entries are now
  validated as email addresses and duplicates are collapsed.

### Added

- **State decision rules (R1..R9)** in `IAMManager.evaluate_users()`, returning
  a `UserAssessment` with a `UserStatus` and a `ReasonCode`
  (`PRIVILEGED_ROLE`, `OTHER_ACCESS_ROLE`, `GROUP_GRANT_PRESENT`,
  `INHERITED_BINDING`, `CONFLICTING_BINDINGS`, `POLICY_UNREADABLE`,
  `ANCESTOR_UNCHECKED`).
- **Five safety gates** evaluated before any mutation:
  - `G1_POLICY_READABLE` - abort if the IAM policy cannot be read.
  - `G2_ANY_DETERMINATE` - abort if no user state could be determined.
  - `G3_TELEMETRY_HEALTHY` - withhold automatic re-allow when the usage query
    failed or returned zero entries.
  - `G4_CHANGE_BUDGET` - circuit breaker; abort when a cycle would change more
    than `max(AGY_MAX_CHANGES_ABS, AGY_MAX_CHANGES_RATIO x population)`
    bindings. Defaults: `10` and `0.2`.
  - `G5_NON_USER_GRANT_ABSENT` - warn (do not abort) when a group/domain grant
    makes per-user enforcement unprovable.
- **Coverage metric** (`Coverage`) reporting what share of the evaluated
  population this tool can actually control, broken down by reason. Surfaced in
  the text report, the JSON report, and the webhook alert.
- **Manual Action Required reporting** on `allow` / `disallow`. Accounts the
  tool cannot control are never modified; each is listed with its state, reason
  code, and the remediation step required to resolve the underlying grant.
- **New audit actions**: `disallow_not_enforceable`, `allow_withheld`,
  `cycle_aborted`.
- **`scripts/preflight_check.sh`** - inspects group/domain bindings, conditional
  bindings, other access-granting roles, and inherited ancestor bindings, and
  exits non-zero when enforcement would be incomplete. `deploy_cloud_run.sh`
  runs it automatically (bypass with `SKIP_PREFLIGHT=true`).
- **New environment variables**: `AGY_CAP_ROLE_ID`, `AGY_ADMIN_ROLE_ID`,
  `AGY_EXTRA_ACCESS_ROLES`, `AGY_REQUIRE_ANCESTOR_CHECK`,
  `AGY_ALLOW_GROUP_COEXISTENCE`, `AGY_MAX_CHANGES_ABS`,
  `AGY_MAX_CHANGES_RATIO`.
- **Known Limitations** section in both READMEs.

### Changed

- `roles/run.invoker` is granted on the Cloud Run Job resource instead of
  project-wide.
- The batch job refuses to start when neither `CAP_REQUESTS` nor `CAP_TOKENS`
  is set, and when `CAP_PERIOD=all`.
- Webhook alerts now fire on aborted cycles and on cap violations that could not
  be enforced, not only on successful changes, and include the coverage figure.
- Test suite grew from 44 to 103 tests, including regressions for every defect
  listed above.

## [0.1.0] - 2026-09-08

- Initial release.
