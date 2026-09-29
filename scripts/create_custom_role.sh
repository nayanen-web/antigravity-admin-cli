#!/usr/bin/env bash
# Creates the two marker roles used by agy-admin v0.2.0.
#
# Both roles carry the permissions of roles/discoveryengine.agentspaceUser
# minus every businessaicode.* permission, so a member keeps Gemini Enterprise
# access but loses AI developer tools (Antigravity).
#
# Why two roles instead of one?
#   CustomAntigravityCapBlocked   - applied by the automatic cap cycle.
#                                   Eligible for automatic restoration once
#                                   usage falls back under the cap.
#   CustomAntigravityAdminBlocked - applied by a human via `agy-admin disallow`.
#                                   Never restored automatically.
#
# v0.1.0 used a single role for both, so the nightly job happily re-granted
# access to users an administrator had deliberately offboarded.
#
# Reference: https://cloud.google.com/gemini/enterprise/docs/ai-developer-tools-creating-custom-roles

set -euo pipefail

PROJECT_ID="${1:-${GCP_PROJECT:-}}"
CAP_ROLE_ID="${AGY_CAP_ROLE_ID:-CustomAntigravityCapBlocked}"
ADMIN_ROLE_ID="${AGY_ADMIN_ROLE_ID:-CustomAntigravityAdminBlocked}"
BASE_ROLE="${AGY_ALLOWED_ROLE:-roles/discoveryengine.agentspaceUser}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "Usage: $0 <PROJECT_ID>"
  echo "Error: PROJECT_ID must be specified or set in the GCP_PROJECT environment variable."
  exit 1
fi

echo "==> Fetching permissions from base role: ${BASE_ROLE}..."
PERMS=$(gcloud iam roles describe "${BASE_ROLE}" --format="value(includedPermissions)")

# Drop businessaicode.* (the Antigravity permissions) and permissions that are
# not supported in project-level custom roles.
FILTERED_PERMS=$(echo "${PERMS}" \
  | tr ';' '\n' \
  | grep -v '^businessaicode\.' \
  | grep -v '^resourcemanager\.projects\.list$' \
  | paste -sd, -)

if [[ -z "${FILTERED_PERMS}" ]]; then
  echo "Error: no permissions remain after filtering. Aborting." >&2
  exit 1
fi

echo "==> Filtered permissions count: $(echo "${FILTERED_PERMS}" | tr ',' '\n' | wc -l)"

upsert_role() {
  local role_id="$1"
  local title="$2"
  local description="$3"

  if gcloud iam roles describe "${role_id}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "==> Role '${role_id}' exists. Updating permissions..."
    gcloud iam roles update "${role_id}" \
      --project="${PROJECT_ID}" \
      --permissions="${FILTERED_PERMS}" \
      --stage="GA" \
      --quiet
  else
    echo "==> Creating role '${role_id}'..."
    gcloud iam roles create "${role_id}" \
      --project="${PROJECT_ID}" \
      --title="${title}" \
      --description="${description}" \
      --permissions="${FILTERED_PERMS}" \
      --stage="GA" \
      --quiet
  fi
  echo "==> Ready: projects/${PROJECT_ID}/roles/${role_id}"
}

upsert_role "${CAP_ROLE_ID}" \
  "Antigravity Cap Blocked" \
  "Blocked by the agy-admin cap cycle. Restored automatically when usage resets."

upsert_role "${ADMIN_ROLE_ID}" \
  "Antigravity Admin Blocked" \
  "Blocked manually by an administrator. Never restored automatically."

# --- Migration note for existing v0.1.0 deployments -------------------------
LEGACY_ROLE_ID="${AGY_CUSTOM_RESTRICTED_ROLE_ID:-CustomAntigravityRestrictedUser}"
if gcloud iam roles describe "${LEGACY_ROLE_ID}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  cat <<EOF

------------------------------------------------------------------------------
NOTICE: the v0.1.0 role '${LEGACY_ROLE_ID}' still exists in this project.

agy-admin v0.2.0 treats its members as BLOCKED_BY_ADMIN, i.e. it will never
restore their access automatically. That is the safe default, but it is
probably not what you want for users who were only over a usage cap.

Review the members and move the cap-related ones to the new cap role:

  gcloud projects get-iam-policy ${PROJECT_ID} \\
    --flatten="bindings[].members" \\
    --filter="bindings.role:projects/${PROJECT_ID}/roles/${LEGACY_ROLE_ID}" \\
    --format="value(bindings.members)"

  # for each user that was capped (not offboarded):
  gcloud projects add-iam-policy-binding ${PROJECT_ID} \\
    --member="user:USER@EXAMPLE.COM" \\
    --role="projects/${PROJECT_ID}/roles/${CAP_ROLE_ID}" --condition=None
  gcloud projects remove-iam-policy-binding ${PROJECT_ID} \\
    --member="user:USER@EXAMPLE.COM" \\
    --role="projects/${PROJECT_ID}/roles/${LEGACY_ROLE_ID}" --condition=None
------------------------------------------------------------------------------
EOF
fi
