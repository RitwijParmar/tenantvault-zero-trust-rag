# Measured-security methodology

TenantVault’s portfolio metrics are deliberately narrow and reproducible.
`scripts/measure_live_isolation.py` performs black-box checks against a local or
Cloud Run deployment using its synthetic demo tenants.

For each tenant and iteration, it verifies a normal tenant-scoped retrieval
returns a receipt with the caller’s tenant and at least one grounded source. It
also runs the reciprocal cross-tenant canary probe. Finally, it sends one header
tenant-override attempt and one JSON tenant-override attempt.

The report records actual end-to-end HTTP round-trip latency for normal
retrievals. A local run measures the in-memory demo path; a Cloud Run run also
includes its network and Cloud SQL path. Neither result claims large-corpus
vector performance, real-customer data protection, throughput at scale, or
business savings. Those require a representative corpus, load model, and
production traffic measurement.

The repository includes a [recorded local synthetic baseline](../artifacts/local_synthetic_isolation_baseline.json).
Use that result only as an integration-security check. Re-run the command after
every meaningful security change and publish a separately labeled Cloud Run
artifact only when that deployment is available.

Run it with:

```bash
python scripts/measure_live_isolation.py \
  --url https://your-service.run.app \
  --iterations 25 --workers 8 \
  --output artifacts/live_isolation_benchmark.json
```
