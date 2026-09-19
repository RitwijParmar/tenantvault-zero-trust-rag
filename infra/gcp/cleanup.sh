#!/usr/bin/env bash
# Intentionally manual cleanup for the portfolio demo's billable GCP resources.
set -euo pipefail
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-tenantvault}"
INSTANCE="${INSTANCE:-tenantvault-pg}"
REPOSITORY="${REPOSITORY:-tenantvault}"

echo "This deletes the TenantVault Cloud Run service, migration job, Cloud SQL instance, artifact repository, and secrets in $PROJECT_ID."
read -r -p "Type DELETE-TENANTVAULT to continue: " confirmation
[[ "$confirmation" == "DELETE-TENANTVAULT" ]] || { echo "Cancelled."; exit 1; }
gcloud run services delete "$SERVICE" --region "$REGION" --project "$PROJECT_ID" --quiet || true
gcloud run jobs delete "${SERVICE}-migrate" --region "$REGION" --project "$PROJECT_ID" --quiet || true
gcloud sql instances delete "$INSTANCE" --project "$PROJECT_ID" --quiet || true
gcloud artifacts repositories delete "$REPOSITORY" --location "$REGION" --project "$PROJECT_ID" --quiet || true
for secret in tenantvault-database-url tenantvault-admin-database-url tenantvault-api-database-password tenantvault-token-signing tenantvault-tenant-key-root tenantvault-receipt-signing; do
  gcloud secrets delete "$secret" --project "$PROJECT_ID" --quiet || true
done
