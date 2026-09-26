#!/usr/bin/env bash
# Run BoundaryLab's synthetic candidate gate as a Cloud Run Job.
# The target must be a synthetic-demo candidate URL; this script changes no
# Cloud Run traffic and never promotes a revision on its own.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-tenantvault}"
REPOSITORY="${REPOSITORY:-tenantvault}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
TARGET_URL="${TARGET_URL:?Set TARGET_URL=https://candidate-service.run.app}"
JOB="${SERVICE}-verify"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}/tenantvault:${IMAGE_TAG}"

require_command() { command -v "$1" >/dev/null || { echo "Missing required command: $1" >&2; exit 1; }; }
require_command gcloud

JOB_ARGS=(
  --image "$IMAGE"
  --region "$REGION"
  --command python
  --args=-m,tenantvault.release_verifier,--url,"$TARGET_URL",--output,/tmp/release_gate.json
  --max-retries 0
  --task-timeout 5m
  --project "$PROJECT_ID"
)

if gcloud run jobs describe "$JOB" --region "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud run jobs update "$JOB" "${JOB_ARGS[@]}"
else
  gcloud run jobs create "$JOB" "${JOB_ARGS[@]}"
fi

echo "Running BoundaryLab candidate gate against $TARGET_URL"
gcloud run jobs execute "$JOB" --region "$REGION" --project "$PROJECT_ID" --wait
echo "Gate passed. Review the Cloud Run Job logs for the signed report."
