#!/usr/bin/env bash
# Preflight check for agy-admin.
#
# This tool can only revoke Antigravity access from principals bound
# INDIVIDUALLY (member type `user:`) to the base role. If access reaches a user
# through a group, a domain binding, an inherited folder/organization binding,
# or another access-granting role, removing the individual binding does not
# revoke anything.
#
# Run this before enabling enforcement. It reports how much of your population
# the tool can actually control, and exits non-zero when the answer is "not
# all of it", so it can be wired into a deployment gate.
#
# Usage: scripts/preflight_check.sh <PROJECT_ID>

set -uo pipefail

PROJECT_ID="${1:-${GCP_PROJECT:-}}"
BASE_ROLE="${AGY_ALLOWED_ROLE:-roles/discoveryengine.agentspaceUser}"
PRIVILEGED_ROLES=("roles/owner" "roles/editor")
OTHER_ACCESS_ROLES=(
  "roles/discoveryengine.admin"
  "roles/discoveryengine.editor"
  "roles/discoveryengine.agentspaceAdmin"
)

if [[ -z "${PROJECT_ID}" ]]; then
  echo "Usage: $0 <PROJECT_ID>"
  exit 2
fi

FINDINGS=0

note()  { echo "  - $*"; }
fail()  { echo "  ! $*"; FINDINGS=$((FINDINGS + 1)); }

echo "=============================================================="
echo " agy-admin preflight check: ${PROJECT_ID}"
echo "=============================================================="

POLICY_JSON=$(gcloud projects get-iam-policy "${PROJECT_ID}" --format=json 2>/dev/null)
if [[ -z "${POLICY_JSON}" ]]; then
  echo "FATAL: could not read the IAM policy for ${PROJECT_ID}."
  echo "       The tool refuses to act on an unreadable policy (gate G1),"
  echo "       so enforcement would abort on every cycle."
  exit 2
fi

members_of() {
  echo "${POLICY_JSON}" | python3 -c "
import json,sys
role=sys.argv[1]
policy=json.load(sys.stdin)
out=set()
for b in policy.get('bindings',[]):
    if b.get('role')==role:
        out.update(b.get('members',[]))
print('\n'.join(sorted(out)))
" "$1"
}

conditional_members_of() {
  echo "${POLICY_JSON}" | python3 -c "
import json,sys
role=sys.argv[1]
policy=json.load(sys.stdin)
out=set()
for b in policy.get('bindings',[]):
    if b.get('role')==role and b.get('condition'):
        out.update(b.get('members',[]))
print('\n'.join(sorted(out)))
" "$1"
}

# --- 1. Base role composition ------------------------------------------------
echo
echo "[1/5] Base role membership (${BASE_ROLE})"
BASE_MEMBERS=$(members_of "${BASE_ROLE}")
if [[ -z "${BASE_MEMBERS}" ]]; then
  note "No members. Nothing to enforce yet."
else
  INDIVIDUAL=$(echo "${BASE_MEMBERS}" | grep -c '^user:' || true)
  COLLECTIVE=$(echo "${BASE_MEMBERS}" | grep -cE '^(group:|domain:|principalSet:|allUsers|allAuthenticatedUsers)' || true)
  SERVICE=$(echo "${BASE_MEMBERS}" | grep -c '^serviceAccount:' || true)
  note "individual (user:) members : ${INDIVIDUAL}   <- controllable"
  note "service accounts           : ${SERVICE}      <- ignored by the tool"
  if [[ "${COLLECTIVE}" -gt 0 ]]; then
    fail "group/domain members       : ${COLLECTIVE}      <- NOT controllable"
    echo "${BASE_MEMBERS}" | grep -E '^(group:|domain:|principalSet:|allUsers|allAuthenticatedUsers)' | sed 's/^/        /'
    echo "        With these present the tool marks every user NOT_ENFORCEABLE"
    echo "        and refuses to claim a block it cannot deliver."
  else
    note "group/domain members       : 0"
  fi
fi

# --- 2. Conditional bindings -------------------------------------------------
echo
echo "[2/5] Conditional bindings on the base role"
COND=$(conditional_members_of "${BASE_ROLE}")
if [[ -n "${COND}" ]]; then
  fail "$(echo "${COND}" | wc -l) member(s) hold the base role through a CONDITIONAL binding."
  echo "${COND}" | sed 's/^/        /'
  echo "        The tool only edits unconditional bindings, so these are NOT_ENFORCEABLE."
else
  note "None."
fi

# --- 3. Other access-granting roles -----------------------------------------
echo
echo "[3/5] Other roles that grant Antigravity access"
for role in "${PRIVILEGED_ROLES[@]}" "${OTHER_ACCESS_ROLES[@]}"; do
  M=$(members_of "${role}" | grep '^user:' || true)
  if [[ -n "${M}" ]]; then
    fail "${role}: $(echo "${M}" | wc -l) individual member(s) - NOT controllable"
    echo "${M}" | sed 's/^/        /'
  fi
done
if [[ "${FINDINGS}" -eq 0 ]]; then
  note "None."
fi

# --- 4. Inherited (ancestor) bindings ---------------------------------------
echo
echo "[4/5] Inherited bindings from parent folders / organization"
if gcloud projects get-ancestors-iam-policy "${PROJECT_ID}" --format=json >/tmp/agy_ancestors.json 2>/dev/null; then
  INHERITED=$(python3 - "${BASE_ROLE}" <<'PY'
import json,sys
role=sys.argv[1]
watched={role,"roles/owner","roles/editor",
         "roles/discoveryengine.admin","roles/discoveryengine.editor",
         "roles/discoveryengine.agentspaceAdmin"}
data=json.load(open("/tmp/agy_ancestors.json"))
hits=[]
for level in data:
    res=level.get("id") or level.get("resource") or "?"
    for b in level.get("policy",{}).get("bindings",[]):
        if b.get("role") in watched and b.get("members"):
            hits.append(f"{res}: {b['role']} -> {len(b['members'])} member(s)")
print("\n".join(hits))
PY
)
  rm -f /tmp/agy_ancestors.json
  if [[ -n "${INHERITED}" ]]; then
    fail "Access-granting bindings exist above this project:"
    echo "${INHERITED}" | sed 's/^/        /'
    echo "        Set AGY_REQUIRE_ANCESTOR_CHECK=true so the tool refuses to"
    echo "        claim enforcement it cannot verify."
  else
    note "None."
  fi
else
  note "Could not inspect ancestors (missing permission). Treat inheritance as unknown."
fi

# --- 5. Service account permissions -----------------------------------------
echo
echo "[5/5] Required permissions for the enforcement identity"
note "roles/logging.viewer                    - read usage telemetry"
note "roles/logging.logWriter                 - write the audit trail (v0.1.0 omitted this)"
note "roles/resourcemanager.projectIamAdmin   - modify project IAM bindings"
note "roles/iam.roleViewer                    - read the marker role definitions"

echo
echo "=============================================================="
if [[ "${FINDINGS}" -eq 0 ]]; then
  echo " RESULT: OK. Every access path is individually bound and controllable."
  exit 0
fi
echo " RESULT: ${FINDINGS} issue(s) found."
echo
echo " agy-admin will still run, but it will classify the affected users as"
echo " NOT_ENFORCEABLE and list them under 'Manual Action Required' instead of"
echo " silently reporting a block that never happened."
echo
echo " To make enforcement effective, convert group/domain grants of"
echo " ${BASE_ROLE} into individual user: bindings."
echo "=============================================================="
exit 1
