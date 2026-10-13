# Antigravity User Usage Monitoring & Cap Control (`agy-admin`)

[English](README.md) | [한국어](README.ko.md)

[![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)](pyproject.toml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

`agy-admin` is a CLI and automated batch tool for monitoring user-level usage and managing quota caps for Google Antigravity (Antigravity Desktop, CLI, and IDE extensions) under Gemini Enterprise licenses.

> **Disclaimer**: This project is a custom administrative solution for enterprise monitoring and governance. It is not an officially supported Google Cloud product or service.

### Enforcement Scope
This tool manages direct `user:` IAM bindings on the target project. If access is granted through Google Groups (`group:`), domain bindings (`domain:`), inherited folder/organization policies, or broader roles (`roles/owner`, `roles/discoveryengine.admin`, etc.), modifying project-level individual bindings will not revoke access.

In these scenarios, `agy-admin` classifies the user as `NOT_ENFORCEABLE`, skips IAM modifications, and lists them under **Manual Action Required**.

Run [`scripts/preflight_check.sh`](scripts/preflight_check.sh) before enabling automated enforcement to review your project's controllable user population. See [Known Limitations](#11-known-limitations) for details.

> **v0.2.0 Update**: Version 0.2.0 introduces updates to the status model, marker roles, and configuration schema. If updating from v0.1.0, review [CHANGELOG.md](CHANGELOG.md) and run `scripts/create_custom_role.sh`.

---

## Table of Contents

- [1. Key Features](#1-key-features)
- [2. Architecture & How It Works](#2-architecture--how-it-works)
- [3. Prerequisites & Setup](#3-prerequisites--setup)
- [4. Installation](#4-installation)
- [5. User Onboarding Flow](#5-user-onboarding-flow)
- [6. CLI Usage Guide (`agy-admin-cli`)](#6-cli-usage-guide-agy-admin-cli)
- [7. Cloud Run Batch Job (Automated Enforcement)](#7-cloud-run-batch-job-automated-enforcement)
- [8. Configuration & Environment Variables](#8-configuration--environment-variables)
- [9. Running Tests](#9-running-tests)
- [10. References](#10-references)
- [11. Known Limitations](#11-known-limitations)

---

## 1. Key Features

- **Usage Metrics from Cloud Logging**: Parses `businessaicode.googleapis.com%2Finference_response` logs to extract per-user request counts, token metrics (total, prompt, candidate), client surfaces, and model identifiers.
- **Configurable Aggregation Windows**:
  - Periods: `daily`, `weekly`, `monthly`, or `all` (bounded to 90 days)
  - Window calculations: `calendar` (reset at 00:00 UTC) or `rolling` (sliding window over past 24h, 7d, etc.)
- **Safe Enforcement Rules**:
  - Operates without external databases or storage state.
  - Automated cycles only block users in `ENFORCEABLE_ALLOWED` and only restore users previously blocked by the tool (`CAPPED_BY_TOOL`).
- **Enforceability Classification & Reporting**:
  - Distinguishes between successfully enforced caps and unenforceable violations (e.g. group members, elevated roles).
  - Reports enforceable coverage ratios alongside a list of users requiring administrator review.
- **Safety Gates**: Pre-validates IAM policy readability, classification determinacy, logging health, change volume thresholds (circuit breaker), and group assignment presence before modifying IAM policies.
- **Distinct Marker Roles**: Distinguishes administrative blocks (`disallow`) from quota cap blocks (`cap apply`), preventing offboarded accounts from being restored by scheduled jobs.
- **Resource Manager SDK Integration**: Uses `google.cloud.resourcemanager_v3` with IAM policy version 3, batching policy updates into a single atomic read-modify-write operation per cycle.
- **Multiple Output Formats**: Supports interactive terminal tables, structured JSON, and CSV exports.
- **Alert Webhooks**: Sends notifications to Slack or Google Chat for cap blocks, restorations, aborted cycles, and manual action items.
- **Audit Logging**: Logs administrative actions, skipped accounts, and aborted runs to Cloud Logging under `projects/{PROJECT_ID}/logs/agy-admin%2Fadmin_actions`.

---

## 2. Architecture & How It Works

### 1) Observability Pipeline
In Gemini Enterprise, Antigravity inference traffic routes through the Business AI Code backend (`businessaicode.googleapis.com`). Telemetry logs are written to Cloud Logging in the customer project:
- **Log Name**: `projects/{PROJECT_ID}/logs/businessaicode.googleapis.com%2Finference_response`
- **Key Fields**:
  - `labels.user_id`: Authenticated user email (e.g., `user@company.com`)
  - `labels.client_name`: Client application (`antigravity_hub`, `antigravity_cli`, IDE plugins)
  - `labels.model_id`: Model identifier (falls back to `labels.model` if absent)
  - `jsonPayload.metadata.totalTokenCount`: Total tokens consumed per call

### 2) IAM Status Model (6 States)

Before taking action, `agy-admin` verifies whether an account's access path can be safely managed through individual project bindings:

| State | Description | Auto-block | Auto-restore |
|---|---|:---:|:---:|
| `ENFORCEABLE_ALLOWED` | Granted `roles/discoveryengine.agentspaceUser` exclusively via direct `user:` binding | Yes | - |
| `CAPPED_BY_TOOL` | Temporarily restricted due to cap exceedance (`CustomAntigravityCapBlocked`) | - | Yes |
| `BLOCKED_BY_ADMIN` | Manually restricted by an administrator (`CustomAntigravityAdminBlocked` or legacy role) | - | No |
| `NOT_ENFORCEABLE` | Has access, but cannot be managed per-user (e.g. groups, inherited bindings, admin roles) | No | No |
| `NO_ACCESS` | No active access path identified | No | No |
| `UNKNOWN` | Insufficient information to classify (e.g. policy read errors) | No | No |

Users marked `NOT_ENFORCEABLE` include a reason code (`PRIVILEGED_ROLE`, `OTHER_ACCESS_ROLE`, `GROUP_GRANT_PRESENT`, `INHERITED_BINDING`, or `CONFLICTING_BINDINGS`). Users marked `UNKNOWN` include `POLICY_UNREADABLE` or `ANCESTOR_UNCHECKED`.

Manual `allow` and `disallow` commands always refuse to act on `NOT_ENFORCEABLE` and `UNKNOWN` accounts. There is no override flag. Because the tool cannot revoke access that originates outside individual project bindings, applying a marker role to such an account would grant a new permission without removing anything, while reporting a block that did not occur. These accounts are listed under **Manual Action Required** with the remediation step for each reason code, and the command exits with code `2`.

### 3) Marker Roles

When restricting access, `agy-admin` replaces `roles/discoveryengine.agentspaceUser` with a custom marker role containing identical permissions minus `businessaicode.*`. This restricts developer tool inference while preserving general Gemini Enterprise chat and search capabilities.

| Role ID | Assigned By | Automatic Restoration |
|---|---|---|
| `CustomAntigravityCapBlocked` | Automated cap batch job / `cap apply` | Yes, when usage falls below cap |
| `CustomAntigravityAdminBlocked` | Administrator CLI command (`disallow`) | No (requires manual `allow`) |
| `CustomAntigravityRestrictedUser` | v0.1.0 legacy installations | No (treated as administrative block) |

### 4) Safety Gates

Automated cycles evaluate five safety gates before applying IAM updates:

| Gate | Condition | Action |
|---|---|---|
| `G1_POLICY_READABLE` | Failed to retrieve project IAM policy | Abort run (exit code 3) |
| `G2_ANY_DETERMINATE` | Unable to classify any user state | Abort run (exit code 3) |
| `G3_TELEMETRY_HEALTHY` | Usage query failed or returned zero records | Apply blocks, but withhold automatic restorations |
| `G4_CHANGE_BUDGET` | Planned changes exceed `max(10, 20% of population)` | Abort run (exit code 3) |
| `G5_NON_USER_GRANT_ABSENT` | Group or domain bindings exist on access roles | Warn; affected users marked `NOT_ENFORCEABLE` |

Gate G3 prevents logging outages or misconfigurations from triggering unintended bulk access restorations.

---

## 3. Prerequisites & Setup

### 1) Required IAM Roles
The identity executing the CLI or Cloud Run Job requires:
- `roles/logging.viewer`: Read inference logs from Cloud Logging
- `roles/logging.logWriter`: Write audit logs to Cloud Logging
- `roles/resourcemanager.projectIamAdmin`: Manage project IAM policy bindings
- `roles/iam.roleViewer`: Read custom marker role configurations
- `roles/iam.roleAdmin`: Create custom marker roles (initial setup only)

### 2) Google Cloud CLI Authentication
```bash
# Authenticate gcloud CLI
gcloud auth login

# Configure Application Default Credentials (ADC)
gcloud auth application-default login

# Set active project
gcloud config set project <PROJECT_ID>
```

### 3) Enable Required GCP APIs
```bash
gcloud services enable \
  businessaicode.googleapis.com \
  discoveryengine.googleapis.com \
  logging.googleapis.com \
  --project <PROJECT_ID>
```

### 4) Enable Gemini Enterprise Observability
Detailed token counts require metadata logging in the Gemini Enterprise console:
1. Navigate to **Gemini Enterprise** (or Discovery Engine) > **Configurations**.
2. In the **AI Developer Tools** tab, toggle **Enable AI Developer Tools**.
3. In the **Observability** tab:
   - Check **Enable instrumentation of OpenTelemetry traces and logs**.
   - Check **Metadata Logging (`metadata_logging_enabled`)**.

If Metadata Logging is turned off, usage queries will return zero records. Gate G3 will flag telemetry as unavailable and withhold automated restorations. Ensure this setting remains enabled during operation.

### 5) Run Compatibility Preflight Check
Before enabling automated cap enforcement, verify whether your project's IAM configuration supports per-user management:

```bash
chmod +x scripts/preflight_check.sh
./scripts/preflight_check.sh <PROJECT_ID>
```

The script checks for:
- Non-user members (`group:`, `domain:`, `allUsers`) assigned to `roles/discoveryengine.agentspaceUser`
- Conditional IAM bindings on the target role
- Individual users holding administrative or broader access roles
- Inherited folder or organization level grants

A non-zero exit code indicates configurations where certain users will be classified as `NOT_ENFORCEABLE`.

### 6) Create Custom Marker Roles
```bash
chmod +x scripts/create_custom_role.sh
./scripts/create_custom_role.sh <PROJECT_ID>
```

This creates both `CustomAntigravityCapBlocked` and `CustomAntigravityAdminBlocked`. If legacy role `CustomAntigravityRestrictedUser` is detected, migration instructions are displayed.

---

## 4. Installation

```bash
# Create and activate Python virtual environment (Python 3.10+)
python3 -m venv venv
source venv/bin/activate

# Install agy-admin in editable mode
pip install -e .

# Confirm installation
agy-admin-cli --help
```

---

## 5. User Onboarding Flow

1. **Assign License**: Assign a Gemini Enterprise license in the Google Workspace Admin Console or Cloud Identity.
2. **Grant Initial Access**:
   ```bash
   # Single user onboarding
   agy-admin-cli allow dev1@company.com --project <PROJECT_ID>

   # Bulk onboarding from file
   agy-admin-cli allow --file users.txt --project <PROJECT_ID>
   ```
3. **User Client Sign-in**: The developer launches Antigravity, authenticates with their corporate Google credentials, and specifies `<PROJECT_ID>`.

---

## 6. CLI Usage Guide (`agy-admin-cli`)

### 1) View Usage Metrics (`list`)
```bash
# Current calendar month, sorted by token count
agy-admin-cli list --project <PROJECT_ID>

# Specify period (daily, weekly, monthly, all)
agy-admin-cli list --period daily --project <PROJECT_ID>

# Sliding 24-hour window
agy-admin-cli list --period daily --window rolling --project <PROJECT_ID>

# Filter by username, state, or minimum token threshold
# Allowed status filters: all, ENFORCEABLE_ALLOWED, CAPPED_BY_TOOL,
#                         BLOCKED_BY_ADMIN, NOT_ENFORCEABLE, NO_ACCESS, UNKNOWN
agy-admin-cli list --filter-user "devuser01" --filter-status ENFORCEABLE_ALLOWED --min-tokens 50000 --project <PROJECT_ID>

# View users that cannot be managed automatically
agy-admin-cli list --filter-status NOT_ENFORCEABLE --project <PROJECT_ID>

# Export to JSON or CSV
agy-admin-cli list --format json --project <PROJECT_ID>
agy-admin-cli list --format csv --project <PROJECT_ID>
```

### 2) Inspect Specific Users (`user`)
```bash
agy-admin-cli user dev1@company.com dev2@company.com --project <PROJECT_ID>
agy-admin-cli user --file users.txt --format json --project <PROJECT_ID>
```

### 3) Manage Access Manually (`allow`, `disallow`)
```bash
# Grant access
agy-admin-cli allow dev1@company.com --project <PROJECT_ID>

# Restrict access (applies CustomAntigravityAdminBlocked)
agy-admin-cli disallow dev1@company.com --reason "Offboarded" --project <PROJECT_ID>

# Preview changes without modifying IAM (dry-run)
agy-admin-cli disallow dev1@company.com --dry-run --project <PROJECT_ID>
```

When a user's access cannot be revoked through an individual project binding, the command does not modify IAM. The account is reported under **Manual Action Required** with its state and reason code, and the process exits with code `2`.

#### Handling accounts reported as Manual Action Required

There is no flag that forces the tool to act on these accounts. Removing the base-role binding would not revoke their access, and applying a marker role would add a permission rather than remove one. The access sources corresponding to each reason code are as follows:

| Reason code | Where the access comes from |
|---|---|
| `GROUP_GRANT_PRESENT` | A `group:` or `domain:` member holds the base role |
| `PRIVILEGED_ROLE` | `roles/owner` or `roles/editor` |
| `OTHER_ACCESS_ROLE` | Another access-granting role such as `roles/discoveryengine.admin` |
| `INHERITED_BINDING` | A folder or organization level binding |
| `CONFLICTING_BINDINGS` | A conditional binding, or the base role and a marker role held at once |
| `POLICY_UNREADABLE` | The project IAM policy could not be read |
| `ANCESTOR_UNCHECKED` | Parent policies could not be inspected |

To review the affected accounts before starting remediation:

```bash
# List every account the tool cannot control, with its reason code
agy-admin-cli list --filter-status NOT_ENFORCEABLE --project <PROJECT_ID>

# Inspect which principals hold the base role, including groups
gcloud projects get-iam-policy <PROJECT_ID> \
  --flatten="bindings[].members" \
  --filter="bindings.role:roles/discoveryengine.agentspaceUser" \
  --format="value(bindings.members)"
```

Once the group membership or role has been removed, re-run `agy-admin-cli user <email>` to confirm the account reports `NO_ACCESS`.

### 4) Evaluate and Apply Caps (`cap apply`)
```bash
# Daily cap of 500,000 tokens
agy-admin-cli cap apply --period daily --tokens 500000 --project <PROJECT_ID>

# Daily rolling window cap of 800,000 tokens
agy-admin-cli cap apply --period daily --window rolling --tokens 800000 --project <PROJECT_ID>

# Combined request and token caps
agy-admin-cli cap apply --period daily --requests 1000 --tokens 500000 --project <PROJECT_ID>

# Apply default caps with user-specific overrides from JSON file
agy-admin-cli cap apply --period monthly --config-file user_caps.json --project <PROJECT_ID>

# Preview cap evaluation without changing IAM
agy-admin-cli cap apply --period daily --tokens 500000 --dry-run --project <PROJECT_ID>
```

#### User-Specific Cap Overrides (`user_caps.json`)
You can define default limits alongside custom limits for specific users (e.g. VIPs, team leads):
```json
{
  "default": {
    "max_tokens": 5000000
  },
  "overrides": {
    "user@example.com": {
      "max_tokens": 15000000
    },
    "lead@example.com": {
      "max_tokens": 25000000
    }
  }
}
```
* Users listed in `overrides` are evaluated against their custom limits.
* All other users fall back to `default`.
* Email matching is case-insensitive.

The report includes:
1. **Cap Enforcement Summary**: Coverage ratio, applied blocks, and manual review counts
2. **Cap Violations**: Per-user action outcomes (`DISALLOWED`, `ALREADY CAPPED`, or `NOT ENFORCEABLE`)
3. **Manual Action Required**: Violators who cannot be managed via direct project bindings

### 5) Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success. All requested actions were applied or already fulfilled. |
| `1` | Invalid arguments or input file formatting error. |
| `2` | One or more actions were refused due to user state compatibility. |
| `3` | Enforcement cycle aborted by a safety gate. No IAM changes were applied. |

---

## 7. Cloud Run Batch Job (Automated Enforcement)

Automate cap enforcement cycles using Cloud Run Jobs scheduled via Cloud Scheduler.

### 1) Deploying the Cloud Run Job
```bash
# Standard deployment (runs every 15 minutes, preflight check included)
./scripts/deploy_cloud_run.sh <PROJECT_ID> asia-south1 "*/15 * * * *"

# Deploy in dry-run mode for initial observation
DRY_RUN=true ./scripts/deploy_cloud_run.sh <PROJECT_ID> asia-south1 "*/15 * * * *"

# Deploy with customized cap thresholds, per-user overrides, and alerts
CAP_PERIOD="monthly" \
CAP_CONFIG_FILE="user_caps.json" \
ALERT_WEBHOOK_URL="https://chat.googleapis.com/v1/spaces/..." \
./scripts/deploy_cloud_run.sh <PROJECT_ID> asia-south1 "*/15 * * * *"

# Bypass preflight check when partial coverage is expected
SKIP_PREFLIGHT=true ./scripts/deploy_cloud_run.sh <PROJECT_ID> asia-south1 "*/15 * * * *"
```

### 2) Execution & Verification
```bash
# Trigger an immediate run
gcloud run jobs execute agy-cap-enforcer --region=asia-south1 --project=<PROJECT_ID>

# View job execution logs
gcloud beta run jobs executions logs tail \
  $(gcloud run jobs executions list --job=agy-cap-enforcer --region=asia-south1 --project=<PROJECT_ID> --limit=1 --format="value(name)") \
  --project=<PROJECT_ID>

# Review administrative audit records
gcloud logging read \
  'logName="projects/<PROJECT_ID>/logs/agy-admin%2Fadmin_actions"' \
  --project=<PROJECT_ID> --limit=50
```

---

## 8. Configuration & Environment Variables

### Enforcement Options

| Variable | Default | Description |
|---|---|---|
| `GCP_PROJECT` | - | Target Google Cloud project ID |
| `CAP_PERIOD` | `daily` | Aggregation period (`daily`, `weekly`, `monthly`) |
| `WINDOW_TYPE` | `calendar` | Window calculation (`calendar` or `rolling`) |
| `CAP_TOKENS` | - | Token cap threshold (e.g. `800000`) |
| `CAP_REQUESTS` | - | Request count threshold (e.g. `1000`) |
| `CAP_CONFIG_FILE` | - | Path to JSON file defining default limits and per-user overrides (e.g. `user_caps.json`) |
| `IAM_DISALLOW_MODE` | `custom_role` | Restriction mode (`custom_role` or `revoke`) |
| `DRY_RUN` | `false` | When `true`, evaluates without modifying IAM |
| `INTERVAL_MINUTES` | `0` | `0` executes once and exits. Set to `0` when deployed as a Cloud Run Job |
| `ALERT_WEBHOOK_URL` | - | Slack or Google Chat webhook URL for alerts |

### Roles and Classification

| Variable | Default | Description |
|---|---|---|
| `AGY_ALLOWED_ROLE` | `roles/discoveryengine.agentspaceUser` | Base role granting Antigravity access |
| `AGY_CAP_ROLE_ID` | `CustomAntigravityCapBlocked` | Marker role applied by automated cap cycles |
| `AGY_ADMIN_ROLE_ID` | `CustomAntigravityAdminBlocked` | Marker role applied by manual `disallow` |
| `AGY_CUSTOM_RESTRICTED_ROLE_ID` | `CustomAntigravityRestrictedUser` | Legacy marker role (treated as `BLOCKED_BY_ADMIN`) |
| `AGY_EXTRA_ACCESS_ROLES` | - | Comma-separated list of additional access-granting roles |
| `AGY_LOG_ID` | `businessaicode.googleapis.com/inference_response` | Source log stream name |

### Safety Gates

| Variable | Default | Description |
|---|---|---|
| `AGY_REQUIRE_ANCESTOR_CHECK` | `false` | Check folder/org policies. If true and check fails, all users become `UNKNOWN` |
| `AGY_ALLOW_GROUP_COEXISTENCE` | `false` | If true, permits direct binding management even if group bindings exist on the role |
| `AGY_MAX_CHANGES_ABS` | `10` | Change budget minimum floor |
| `AGY_MAX_CHANGES_RATIO` | `0.2` | Change budget ratio (`max(abs, ratio x population)`) |

---

## 9. Running Tests

```bash
pytest -v tests/
```

The test suite covers:
- Six-state classification logic and reason code assignments
- User-specific cap limits and per-user overrides evaluation (`user_caps.json`)
- Regression tests for edge cases (group bindings, missing logs, policy read failures)
- Safety gates G1 through G5 and circuit breaker behavior
- Resource Manager SDK version 3 policy reads and atomic writes
- Coverage metrics and manual action reporting
- Audit log payloads and webhook generation
- CLI argument validation and command exit codes

---

## 10. References

- [Gemini Enterprise - Configure AI developer tools settings](https://docs.cloud.google.com/gemini/enterprise/docs/ai-developer-tools-settings)
- [Gemini Enterprise - Create custom roles to restrict access to AI developer tools](https://cloud.google.com/gemini/enterprise/docs/ai-developer-tools-creating-custom-roles)
- [Discovery Engine IAM Access Control](https://cloud.google.com/generative-ai-app-builder/docs/access-control)
- [IAM Conditions and policy versions](https://cloud.google.com/iam/docs/policies#versions)

---

## 11. Known Limitations

### 11.1 Direct `user:` Bindings Only
The tool modifies project-level IAM policies. It cannot alter Google Group memberships, domain-level grants, or inherited folder/organization policies. Users who receive access through these mechanisms are classified as `NOT_ENFORCEABLE` and must be managed manually.

No override flag is provided for these accounts. Removing the base-role binding would not revoke access, and applying a marker role would add a permission instead of removing one, so the command refuses and reports the required remediation.

### 11.2 Ancestor Inheritance Checks Disabled by Default
`AGY_REQUIRE_ANCESTOR_CHECK` defaults to `false` because querying parent resource policies requires elevated permissions not typically granted to project-level service accounts. When disabled, inherited permissions are not detected. When enabled, a read failure marks all users as `UNKNOWN` and halts execution.

### 11.3 Conditional IAM Bindings Not Modified
Bindings with IAM Conditions are not modified to prevent unintended condition removal. Users whose base role is tied to a conditional binding are classified as `NOT_ENFORCEABLE (CONFLICTING_BINDINGS)`.

### 11.4 Revoke Mode Lacks Automatic Restoration
Using `--mode revoke` removes the user's `roles/discoveryengine.agentspaceUser` role binding without applying a replacement marker role. Because the tool cannot distinguish this state from a user who was never granted access (`NO_ACCESS`), automated restorations are not supported in this mode. Use `custom_role` mode if automated restoration is required.

### 11.5 Periodic Batch Latency
Enforcement runs on a scheduled interval (e.g., every 15 minutes). Usage between cycles is bounded by the interval length rather than an immediate real-time cutoff.

### 11.6 Calendar Windows Use UTC
`--window calendar` aligns to UTC boundaries (00:00 UTC). For lookback windows independent of UTC day boundaries, use `--window rolling`.

### 11.7 Ninety-Day Bounded Lookback for `all`
The `all` period queries up to the past 90 days to stay within practical log query performance limits.

### 11.8 Custom Access Roles Require Explicit Configuration
Standard roles like `roles/owner` and `roles/editor` are recognized automatically. Custom organization roles that grant `businessaicode.*` permissions must be explicitly listed in `AGY_EXTRA_ACCESS_ROLES`.

### 11.9 Dependency on Gemini Enterprise Metadata Logging
If Metadata Logging is disabled in the console, usage metrics will return zero records. Gate G3 withholds bulk restoration, but cap violations will also not be detected.

### 11.10 Service Accounts and Non-User Principals Excluded
Only individual user accounts (`user:`) are evaluated. Service account usage is included in log metrics but excluded from automated IAM enforcement.
