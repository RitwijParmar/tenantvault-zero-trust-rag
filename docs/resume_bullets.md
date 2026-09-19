# Resume-ready project bullets

Use the measured-result version after running the benchmark; it is the most
specific defensible form for this project.

## Recommended

- **TenantVault — Zero-Trust Multi-Tenant RAG | Python, FastAPI, PostgreSQL/pgvector, GCP**: Built and deployed a Cloud Run RAG service that binds retrieval to signed tenant claims and enforces `FORCE ROW LEVEL SECURITY` on vector and audit tables; validated **0 cross-tenant exposures across N adversarial canary probes** and rejected tenant-header/body override attempts.
- Added tenant-bound AES-256-GCM source encryption and signed isolation receipts that bind the tenant, source hashes, policy revision, and hash-chained audit head; shipped reproducible live verification and GitHub Actions security tests.

Replace **N** with the `attempted` value in the committed benchmark artifact.

## Compact one-line version

Built a zero-trust multi-tenant RAG platform on Cloud Run + pgvector; enforced PostgreSQL RLS and tenant-bound encryption, achieving **0/ N cross-tenant canary exposures** in repeatable live validation.

## What not to claim

Do not say “prevented data breaches,” “production-scale,” “reduced cost,” or
“sub-second latency” unless you have corresponding customer, scale, or load-test
evidence. The benchmark is an integration-security result over synthetic data.
