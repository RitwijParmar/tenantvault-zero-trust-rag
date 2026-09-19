# Cloud Run deployment

`deploy.sh` provisions a small public portfolio deployment in the active GCP project:

```text
Browser → Cloud Run service → Cloud SQL Auth Proxy socket → Cloud SQL PostgreSQL + pgvector
                  ↘ Secret Manager                         ↗
             runtime service account       migration Cloud Run Job
```

It creates an Artifact Registry repository, two service accounts, Cloud SQL for PostgreSQL 16, a Cloud SQL database, Secret Manager values, a Cloud Run migration Job, and a public Cloud Run service. The migration job alone receives the admin database connection; the runtime receives only its application database URL and three application secrets.

## Deploy

```bash
cd TenantVault
chmod +x infra/gcp/deploy.sh infra/gcp/cleanup.sh
PROJECT_ID=your-gcp-project REGION=us-central1 ./infra/gcp/deploy.sh
```

The script uses Cloud Build, so no local Docker daemon is required. It prints the deployed service URL and `/health` URL at completion.

## Security decisions

- Cloud Run accesses Cloud SQL over the managed Cloud SQL Auth Proxy Unix socket.
- The API and migration Job have separate service accounts.
- Secret access is bound per secret, not granted broadly at project scope.
- The database migration creates a non-owner, non-superuser `tenantvault_api` database role; it cannot bypass row-level security.
- The public endpoint is intentional for the portfolio demo. Its customer data is only seeded synthetic content, and the API still requires a bearer token.

## Cost and cleanup

Cloud SQL, Cloud Run, Artifact Registry, and secret versions can incur charges. Run `./infra/gcp/cleanup.sh` when you are finished; it requires typing an exact confirmation before it deletes the project resources.
