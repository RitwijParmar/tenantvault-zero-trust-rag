#!/usr/bin/env bash
# Deploy TenantVault as a public demo backed by Cloud SQL pgvector.
# This script is idempotent. It creates billable GCP resources; use cleanup.sh
# when the portfolio demo is no longer needed.
set -euo pipefail

if [[ -z "${CLOUDSDK_PYTHON:-}" ]] && command -v python3.11 >/dev/null 2>&1; then
  export CLOUDSDK_PYTHON="$(command -v python3.11)"
fi

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-tenantvault}"
INSTANCE="${INSTANCE:-tenantvault-pg}"
DATABASE="${DATABASE:-tenantvault}"
REPOSITORY="${REPOSITORY:-tenantvault}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}/tenantvault"
CONNECTION_NAME="${PROJECT_ID}:${REGION}:${INSTANCE}"
RUNTIME_SA="tenantvault-runtime@${PROJECT_ID}.iam.gserviceaccount.com"
MIGRATOR_SA="tenantvault-migrator@${PROJECT_ID}.iam.gserviceaccount.com"

require_command() { command -v "$1" >/dev/null || { echo "Missing required command: $1" >&2; exit 1; }; }
require_command gcloud
require_command openssl

ensure_service_account() {
  local account="$1" label="$2"
  if ! gcloud iam service-accounts describe "$account" --project "$PROJECT_ID" >/dev/null 2>&1; then
    gcloud iam service-accounts create "${account%@*}" --display-name "$label" --project "$PROJECT_ID"
  fi
}

grant_role() {
  gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:$1" --role="$2" --condition=None --quiet >/dev/null
}

grant_secret_access() {
  gcloud secrets add-iam-policy-binding "$1" --member="serviceAccount:$2" --role=roles/secretmanager.secretAccessor --project "$PROJECT_ID" --condition=None --quiet >/dev/null
}

ensure_secret() {
  local name="$1" value="$2"
  if ! gcloud secrets describe "$name" --project "$PROJECT_ID" >/dev/null 2>&1; then
    gcloud secrets create "$name" --replication-policy=automatic --project "$PROJECT_ID" >/dev/null
  fi
  printf '%s' "$value" | gcloud secrets versions add "$name" --data-file=- --project "$PROJECT_ID" >/dev/null
}

latest_secret_version() {
  gcloud secrets versions list "$1" --project "$PROJECT_ID" --filter='state:ENABLED' --sort-by='~createTime' --limit=1 --format='value(name)'
}

echo "Enabling required APIs in ${PROJECT_ID}…"
gcloud services enable run.googleapis.com sqladmin.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com iam.googleapis.com --project "$PROJECT_ID" --quiet

if ! gcloud artifacts repositories describe "$REPOSITORY" --location "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud artifacts repositories create "$REPOSITORY" --repository-format=docker --location="$REGION" --description="TenantVault Cloud Run images" --project "$PROJECT_ID"
fi

ensure_service_account "$RUNTIME_SA" "TenantVault runtime"
ensure_service_account "$MIGRATOR_SA" "TenantVault migrator"
grant_role "$RUNTIME_SA" roles/cloudsql.client
grant_role "$MIGRATOR_SA" roles/cloudsql.client

if ! gcloud sql instances describe "$INSTANCE" --project "$PROJECT_ID" >/dev/null 2>&1; then
  echo "Creating Cloud SQL PostgreSQL 16 instance (this is billable)…"
  # No authorized networks are configured. Cloud Run reaches this instance via
  # the Cloud SQL Auth Proxy Unix socket rather than an exposed database port.
  gcloud sql instances create "$INSTANCE" --database-version=POSTGRES_16 --edition=ENTERPRISE --tier=db-f1-micro --region="$REGION" --storage-type=SSD --storage-size=10 --availability-type=zonal --project="$PROJECT_ID" --quiet
fi

if ! gcloud sql databases describe "$DATABASE" --instance "$INSTANCE" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud sql databases create "$DATABASE" --instance "$INSTANCE" --project "$PROJECT_ID"
fi

ADMIN_PASSWORD="$(openssl rand -hex 32)"
API_PASSWORD="$(openssl rand -hex 32)"
gcloud sql users set-password postgres --instance "$INSTANCE" --password "$ADMIN_PASSWORD" --project "$PROJECT_ID" --quiet

DATABASE_URL="postgresql://tenantvault_api:${API_PASSWORD}@/${DATABASE}?host=/cloudsql/${CONNECTION_NAME}"
ADMIN_DATABASE_URL="postgresql://postgres:${ADMIN_PASSWORD}@/${DATABASE}?host=/cloudsql/${CONNECTION_NAME}"
ensure_secret tenantvault-database-url "$DATABASE_URL"
ensure_secret tenantvault-admin-database-url "$ADMIN_DATABASE_URL"
ensure_secret tenantvault-api-database-password "$API_PASSWORD"
ensure_secret tenantvault-token-signing "$(openssl rand -hex 48)"
ensure_secret tenantvault-tenant-key-root "$(openssl rand -hex 48)"
ensure_secret tenantvault-receipt-signing "$(openssl rand -hex 48)"

DATABASE_URL_VERSION="$(latest_secret_version tenantvault-database-url)"
ADMIN_DATABASE_URL_VERSION="$(latest_secret_version tenantvault-admin-database-url)"
API_DATABASE_PASSWORD_VERSION="$(latest_secret_version tenantvault-api-database-password)"
TOKEN_SIGNING_VERSION="$(latest_secret_version tenantvault-token-signing)"
TENANT_KEY_ROOT_VERSION="$(latest_secret_version tenantvault-tenant-key-root)"
RECEIPT_SIGNING_VERSION="$(latest_secret_version tenantvault-receipt-signing)"

for secret in tenantvault-database-url tenantvault-token-signing tenantvault-tenant-key-root tenantvault-receipt-signing; do
  grant_secret_access "$secret" "$RUNTIME_SA"
done
grant_secret_access tenantvault-admin-database-url "$MIGRATOR_SA"
grant_secret_access tenantvault-api-database-password "$MIGRATOR_SA"

echo "Building immutable image with Cloud Build…"
COMMIT_SHA="$(git rev-parse --short=12 HEAD)"
gcloud builds submit --config cloudbuild.yaml --substitutions="_REGION=${REGION},_REPOSITORY=${REPOSITORY},_IMAGE=tenantvault,_TAG=${COMMIT_SHA}" --project "$PROJECT_ID" .

JOB_ARGS=(--image "${IMAGE}:${COMMIT_SHA}" --region "$REGION" --service-account "$MIGRATOR_SA" --set-cloudsql-instances "$CONNECTION_NAME" --set-secrets "DATABASE_URL=tenantvault-admin-database-url:${ADMIN_DATABASE_URL_VERSION},API_DATABASE_PASSWORD=tenantvault-api-database-password:${API_DATABASE_PASSWORD_VERSION}" --command python --args=-m,tenantvault.migrate --max-retries 1 --task-timeout 10m --project "$PROJECT_ID")
if gcloud run jobs describe "${SERVICE}-migrate" --region "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud run jobs update "${SERVICE}-migrate" "${JOB_ARGS[@]}"
else
  gcloud run jobs create "${SERVICE}-migrate" "${JOB_ARGS[@]}"
fi
gcloud run jobs execute "${SERVICE}-migrate" --region "$REGION" --project "$PROJECT_ID" --wait

gcloud run deploy "$SERVICE" --image "${IMAGE}:${COMMIT_SHA}" --region "$REGION" --service-account "$RUNTIME_SA" --add-cloudsql-instances "$CONNECTION_NAME" --set-env-vars "STORE_MODE=postgres,DEMO_MODE=true,APP_ROOT=/app" --set-secrets "DATABASE_URL=tenantvault-database-url:${DATABASE_URL_VERSION},TOKEN_SIGNING_SECRET=tenantvault-token-signing:${TOKEN_SIGNING_VERSION},TENANT_KEY_ROOT=tenantvault-tenant-key-root:${TENANT_KEY_ROOT_VERSION},RECEIPT_SIGNING_SECRET=tenantvault-receipt-signing:${RECEIPT_SIGNING_VERSION}" --allow-unauthenticated --min 0 --max 3 --cpu 1 --memory 512Mi --concurrency 20 --timeout 30s --execution-environment gen2 --project "$PROJECT_ID"

URL="$(gcloud run services describe "$SERVICE" --region "$REGION" --project "$PROJECT_ID" --format='value(status.url)')"
echo "TenantVault deployed: $URL"
echo "Health: $URL/health"
