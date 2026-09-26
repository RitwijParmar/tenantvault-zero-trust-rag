# Resume-ready project bullets

These are deliberately scoped to a reproducible local synthetic evaluation and
the repository’s automated checks. They do not imply customer usage or
production-scale performance.

## Recommended

- **TenantVault — Zero-Trust Multi-Tenant RAG | Python, FastAPI, PostgreSQL/pgvector, GCP**: Built a Cloud Run-ready RAG service that binds retrieval to signed tenant claims and enforces `FORCE ROW LEVEL SECURITY` on vector and audit tables; added 8 automated security checks covering cross-tenant canaries, tenant-bound encryption, receipt tampering, and override rejection.
- Built a repeatable black-box isolation evaluator that passed **100/100 local synthetic control checks** (50 signed retrievals + 50 reciprocal canary probes), observed **0 cross-tenant canary exposures**, and rejected header/body tenant override attacks with HTTP **400/422**.
- Added tenant-bound AES-256-GCM encryption and signed isolation receipts binding tenant, source hashes, policy revision, and hash-chained audit head, making every retrieval boundary inspectable during the demo.

The 100/100 result is recorded in
[`artifacts/local_synthetic_isolation_baseline.json`](../artifacts/local_synthetic_isolation_baseline.json).
Replace it only with a new recorded result; label a Cloud Run result separately.

## Compact one-line version

Built a zero-trust multi-tenant RAG platform with PostgreSQL RLS and tenant-bound encryption; passed **100/100** local synthetic isolation checks with **0** cross-tenant canary exposures.

## What not to claim

Do not say “prevented data breaches,” “production-scale,” “reduced cost,” or
“sub-second latency” unless you have corresponding customer, scale, or load-test
evidence. The benchmark is an integration-security result over synthetic data;
it is not a live Cloud Run benchmark while the public deployment is offline.
