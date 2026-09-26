# BoundaryLab control plane

BoundaryLab addresses a lifecycle problem that row-level security alone cannot:
how does a platform team prove that an AI release still honors a tenant contract
after a code, policy, or database change?

## Components

| Component | Responsibility |
| --- | --- |
| `policies/tenant-contracts.json` | Reviewed policy-as-code contracts: tenant, policy revision, required scope, retrieval cap, and attestation SLO. The compiler rejects any contract that drops a fixed isolation control. |
| TenantVault data plane | Signed tenant identity, transaction-local PostgreSQL RLS, tenant-bound AES-GCM, hash-chained audit events, and signed retrieval receipts. |
| `IsolationControlPlane` | Authorizes every request against the compiled contract, creates signed attestations, and quarantines only the tenant whose attestation fails. |
| `release_verifier.py` | Black-box candidate gate. It verifies header/body identity defenses, runs one signed attestation per tenant, and requires each workspace to remain active. |

## Release gate contract

An eligible candidate must satisfy all of the following:

1. A caller-provided `X-Tenant-Id` receives HTTP 400.
2. A caller-provided `tenant_id` body field receives HTTP 422.
3. Each tenant’s cross-tenant canary attestation passes.
4. Each attestation has a control-plane signature, contract hash, and policy
   version.
5. The control plane reports the workspace as `active`.

Any failed attestation changes only the affected workspace to `quarantined`.
The runtime then rejects future retrievals for that tenant with HTTP 423 rather
than silently continuing after an isolation failure.

## GCP promotion topology

```text
Cloud Build → candidate Cloud Run revision → Cloud Run verification Job
                                                   │
                                      signed gate report + Cloud Logging
                                                   │
                              promote candidate or leave it without traffic
```

Cloud SQL/pgvector stays behind Cloud Run’s managed socket. Secret Manager holds
the signing material, and the runtime database role remains non-owner and cannot
bypass RLS. A production implementation should persist the control-plane ledger
and quarantine state in a separately privileged store; the self-contained demo
keeps that state in process while its existing data-plane audit ledger persists
to PostgreSQL.

## What to measure before putting numbers on a resume

Run a production-like Cloud SQL experiment with a fixed corpus, tenant count,
query mix, and concurrency. Report only observed values for:

- candidate-gate pass/fail coverage by attack class;
- p50/p95 retrieval latency with and without the RLS policy;
- verification-job duration and failure-to-quarantine time; and
- policy-revision rollback time.

Do not call local synthetic results production performance or business impact.
