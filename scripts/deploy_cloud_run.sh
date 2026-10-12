#!/usr/bin/env bash
# Deploy script for agy-admin Cloud Run Batch Job & Cloud Scheduler

set -euo pipefail

PROJECT_ID="${1:-${GCP_PROJECT:-}}"
REGION="${2:-asia-south1}"
JOB_NAME="agy-cap-enforcer"
SCHEDULE="${3:-*/15 * * * *}" # Run every 15 minutes by default

if [[ -z "${PROJECT_ID}" ]]; then
  echo "Usage: $0 <PROJECT_ID> [REGION] [SCHEDULE_CRON]"
  echo "Example: $0 my-gcp-project asia-south1 '*/10 * * * *'"
  exit 1
fi

REPO_NAME="agy-admin"
IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/${JOB_NAME}:latest"
SERVICE_ACCOUNT="agy-admin-sa@${PROJECT_ID}.iam.gserviceaccount.com"

# Cap and policy settings (override by exporting or prefixing before running script)
CAP_PERIOD="${CAP_PERIOD:-daily}"
CAP_REQUESTS="${CAP_REQUESTS:-1000}"
CAP_TOKENS="${CAP_TOKENS:-1000000}"
WINDOW_TYPE="${WINDOW_TYPE:-calendar}"
IAM_DISALLOW_MODE="${IAM_DISALLOW_MODE:-custom_role}"
DRY_RUN="${DRY_RUN:-false}"
ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"

echo "==> Configuring project '${PROJECT_ID}' in region '${REGION}'..."

# 0. Preflight. Enforcement is only meaningful when access is bound to
#    individual users; the check reports how much of the population this tool
#    can actually control. Set SKIP_PREFLIGHT=true to bypass deliberately.
if [[ "${SKIP_PREFLIGHT:-false}" != "true" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if ! bash "${SCRIPT_DIR}/preflight_check.sh" "${PROJECT_ID}"; then
    echo
    echo "Preflight reported issues (see above)."
    echo "Deploy anyway with SKIP_PREFLIGHT=true, ideally with DRY_RUN=true first."
    exit 1
  fi
fi

if [[ "${DRY_RUN}" != "true" ]]; then
  echo "==> NOTE: DRY_RUN=false. This deployment will modify IAM bindings on a schedule."
fi

# 1. Enable required APIs
echo "==> Enabling required APIs..."
gcloud services enable \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  cloudscheduler.googleapis.com \
  logging.googleapis.com \
  --project="${PROJECT_ID}"

# 2. Create Service Account if not exists
echo "==> Setting up Service Account: ${SERVICE_ACCOUNT}..."
if ! gcloud iam service-accounts describe "${SERVICE_ACCOUNT}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create agy-admin-sa \
    --display-name="Antigravity Cap Enforcer Service Account" \
    --project="${PROJECT_ID}"
fi

# Grant permissions.
#   logging.viewer                  - read Antigravity usage telemetry
#   logging.logWriter               - write the admin_actions audit trail.
#                                     v0.1.0 omitted this, so every audit write
#                                     failed and was swallowed as a warning.
#   resourcemanager.projectIamAdmin - modify project IAM bindings
#   iam.roleViewer                  - read the marker role definitions
echo "==> Granting IAM roles to ${SERVICE_ACCOUNT}..."
for role in \
  "roles/logging.viewer" \
  "roles/logging.logWriter" \
  "roles/resourcemanager.projectIamAdmin" \
  "roles/iam.roleViewer"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="${role}" \
    --condition=None --quiet
done

# 3. Create Artifact Registry repository if not exists
echo "==> Checking Artifact Registry repository..."
if ! gcloud artifacts repositories describe "${REPO_NAME}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud artifacts repositories create "${REPO_NAME}" \
    --repository-format=docker \
    --location="${REGION}" \
    --description="Antigravity Admin docker images" \
    --project="${PROJECT_ID}"
fi

# 4. Build and push image using Cloud Build
echo "==> Building and pushing container image with Cloud Build..."
gcloud builds submit --tag "${IMAGE_URI}" --project="${PROJECT_ID}" .

# 5. Create or update Cloud Run Job
echo "==> Deploying Cloud Run Job '${JOB_NAME}'..."
ENV_VARS="GCP_PROJECT=${PROJECT_ID},CAP_PERIOD=${CAP_PERIOD},CAP_REQUESTS=${CAP_REQUESTS},CAP_TOKENS=${CAP_TOKENS},WINDOW_TYPE=${WINDOW_TYPE},IAM_DISALLOW_MODE=${IAM_DISALLOW_MODE},DRY_RUN=${DRY_RUN}"
if [[ -n "${ALERT_WEBHOOK_URL}" ]]; then
  ENV_VARS="${ENV_VARS},ALERT_WEBHOOK_URL=${ALERT_WEBHOOK_URL}"
fi
if [[ -n "${CAP_CONFIG_FILE:-}" ]]; then
  ENV_VARS="${ENV_VARS},CAP_CONFIG_FILE=${CAP_CONFIG_FILE}"
fi

gcloud run jobs deploy "${JOB_NAME}" \
  --image="${IMAGE_URI}" \
  --region="${REGION}" \
  --service-account="${SERVICE_ACCOUNT}" \
  --set-env-vars="${ENV_VARS}" \
  --max-retries=1 \
  --task-timeout=10m \
  --project="${PROJECT_ID}"

# 6. Set up Cloud Scheduler to trigger the Cloud Run Job
SCHEDULER_JOB="${JOB_NAME}-schedule"
echo "==> Setting up Cloud Scheduler job '${SCHEDULER_JOB}' (${SCHEDULE})..."

# Grant Cloud Run Invoker on the job resource only. Granting it project-wide
# would let the scheduler identity invoke every Cloud Run service in the
# project, which is far more authority than this schedule needs.
gcloud run jobs add-iam-policy-binding "${JOB_NAME}" \
  --region="${REGION}" \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/run.invoker" \
  --project="${PROJECT_ID}" --quiet

if gcloud scheduler jobs describe "${SCHEDULER_JOB}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud scheduler jobs delete "${SCHEDULER_JOB}" --location="${REGION}" --project="${PROJECT_ID}" --quiet
fi

gcloud scheduler jobs create http "${SCHEDULER_JOB}" \
  --location="${REGION}" \
  --schedule="${SCHEDULE}" \
  --uri="https://${REGION}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${PROJECT_ID}/jobs/${JOB_NAME}:run" \
  --http-method=POST \
  --oauth-service-account-email="${SERVICE_ACCOUNT}" \
  --project="${PROJECT_ID}"

echo "==> Deployment complete!"
echo "    Cloud Run Job: ${JOB_NAME}"
echo "    Scheduler: ${SCHEDULER_JOB} running at schedule '${SCHEDULE}'"
