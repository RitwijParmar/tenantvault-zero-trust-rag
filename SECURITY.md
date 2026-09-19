# Security policy

TenantVault is a portfolio reference implementation. Do not report a suspected vulnerability in a public GitHub issue if it could expose a deployment, credentials, tenant-bound data, or a path around row-level security.

Report privately to the repository owner with a minimal reproduction, affected endpoint or migration area, and any mitigations you have already tested. Never include production credentials, customer data, or full access tokens in a report.

## Design invariants worth testing

1. A tenant identifier originates only from a verified identity claim.
2. The runtime database role is not an owner, superuser, or `BYPASSRLS` role.
3. `app.tenant_id` is set inside the database transaction, never retained on a pooled connection.
4. Vectors, encrypted source chunks, and audit rows have the same database tenant fence.
5. A receipt signature breaks if its tenant, result hashes, or policy version changes.

The test suite intentionally covers tenant-header injection, JSON tenant injection, cross-tenant canaries, key-bound decryption, receipt mutation, and migration policy presence. A production deployment should add a real Cloud SQL integration test using the non-owner application role.
