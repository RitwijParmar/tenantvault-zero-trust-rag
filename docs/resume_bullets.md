# Resume-ready project bullets

These describe the implemented release-control mechanism. Add scale and latency
numbers only after running the Cloud SQL verification experiment described in
`docs/control_plane.md`.

## Recommended

- **BoundaryLab — Continuous Authorization Verification for RAG | Python, FastAPI, PostgreSQL/pgvector, GCP**: Built a policy-as-code control plane that validates signed tenant contracts before retrieval, issues signed isolation attestations, and fail-closes only the affected tenant workspace on a failed security check.
- Built a post-deploy release verifier that exercises forged tenant-header/body attacks and cross-tenant canary probes against a candidate service; gates promotion on active workspace state, policy version, contract hash, and signed attestation evidence.
- Implemented TenantVault’s zero-trust data plane with signed tenant identity, `FORCE ROW LEVEL SECURITY`, tenant-bound AES-256-GCM, hash-chained audit events, and source-level isolation receipts.

Use the measured-result version only after committing a Cloud SQL gate report.

## Compact one-line version

Built BoundaryLab, a policy-as-code release gate for multi-tenant RAG that signs isolation attestations and quarantines a tenant when its security contract fails.

## What not to claim

Do not say “prevented data breaches,” “production-scale,” “reduced cost,” or
“sub-second latency” unless you have corresponding customer, scale, or load-test
evidence. The benchmark is an integration-security result over synthetic data;
it is not a live Cloud Run benchmark while the public deployment is offline.
