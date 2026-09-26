# Resume-ready project bullets

These are deliberately scoped to a reproducible synthetic fault-injection
evaluation and the repository’s automated checks. They do not imply customer
usage or production-scale performance.

## Recommended

- **TenantVault — Zero-Trust Multi-Tenant RAG | Python, FastAPI, PostgreSQL/pgvector, GCP**: Built a Cloud Run-ready RAG service that binds retrieval to signed tenant claims and enforces `FORCE ROW LEVEL SECURITY` on vector and audit tables; added 9 automated security checks covering cross-tenant canaries, tenant-bound encryption, receipt tampering, and override rejection.
- Designed a **12-tenant / 576-document** fault-injection benchmark: a naïve global vector retriever selected foreign canaries in **132/132** missing-filter attacks, while TenantVault returned **0/132** foreign sources and blocked **132/132** cross-tenant ciphertext replays.
- Added signed isolation receipts binding tenant, source hashes, policy revision, and audit-chain head; detected **12/12** tenant-tampering attempts and made every retrieval boundary inspectable in the demo.

The comparative result is recorded in
[`artifacts/fault_injection_scorecard.json`](../artifacts/fault_injection_scorecard.json).
Replace it only with a newly generated, committed result; label a Cloud Run
result separately.

## Compact one-line version

Built a zero-trust multi-tenant RAG platform with PostgreSQL RLS and tenant-bound encryption; reduced foreign-source selection from **132/132** in a missing-filter baseline to **0/132** under tenant-scoped retrieval.

## What not to claim

Do not say “prevented data breaches,” “production-scale,” “reduced cost,” or
“sub-second latency” unless you have corresponding customer, scale, or load-test
evidence. The benchmark is an integration-security result over synthetic data;
it is not a live Cloud Run benchmark while the public deployment is offline.
