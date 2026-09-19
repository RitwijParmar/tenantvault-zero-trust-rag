# Production-demo verification runbook

After a Cloud Run deployment, run these checks before sharing the URL:

1. Open `/health`; it should report `store: postgres`.
2. Use the UI as Northstar Health. Ask about the cardiac escalation owner and confirm that a source card and signed receipt appear.
3. Click **Run isolation challenge** as Northstar. It must pass.
4. Switch to Acme Robotics and repeat the challenge. It must also pass; the app uses the reciprocal canary.
5. Send a query with an `X-Tenant-Id` header. The API must return `400`.
6. Send a query body containing `tenant_id`. The API must return `422`.
7. Confirm the Cloud Run service uses `tenantvault-runtime` and the migration job uses `tenantvault-migrator`.
8. Confirm the service's Cloud SQL connection is the expected instance and the public UI only contains synthetic demo content.

Keep the Cloud SQL instance small for a portfolio demo. Delete the deployment using `infra/gcp/cleanup.sh` when the sharing window closes.
