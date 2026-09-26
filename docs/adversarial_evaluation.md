# Adversarial retrieval evaluation

TenantVault’s primary portfolio metric is a comparative fault-injection result,
not a raw test count. The experiment asks what happens if a developer omits the
tenant constraint in a vector search—the failure this architecture is meant to
contain.

## Recorded result

| Control path | Result |
| --- | --- |
| Corpus | 12 synthetic tenants, 48 documents each, 576 documents total |
| Missing-filter global vector baseline | Selected a foreign target canary in 132/132 cross-tenant attack paths |
| TenantVault tenant-scoped retrieval | Returned 0/132 foreign sources |
| Tenant-bound AES-256-GCM | Blocked 132/132 foreign ciphertext replay attempts |
| Signed isolation receipts | Detected 12/12 tenant-claim mutations |

The recorded JSON is [the fault-injection scorecard](../artifacts/fault_injection_scorecard.json).

## Why this comparison is meaningful

Each tenant owns one unique, high-similarity canary document. Every other
tenant queries for that exact canary. The unsafe reference intentionally ranks
over the entire corpus, representing a common missing-tenant-filter failure.
It selects the victim’s canary as the top result in every attack path.

TenantVault runs the same queries through its tenant-scoped store. A returned
source counts as an exposure only when it contains the victim’s exact canary.
The benchmark separately attempts to decrypt each foreign canary using the
attacker’s tenant-derived AES-GCM key and mutates each tenant claim in a signed
receipt.

## Reproduce it

```bash
python scripts/fault_injection_benchmark.py \
  --tenants 12 --documents-per-tenant 48 \
  --output artifacts/fault_injection_scorecard.json
```

The runner exits nonzero if the unsafe baseline does not select all expected
target canaries, if TenantVault returns a foreign source, if a foreign
ciphertext decrypts, or if a receipt mutation still verifies.

## Honest boundary

This is a deterministic local, in-memory synthetic evaluation. It demonstrates
retrieval-boundary behavior and defense in depth; it does not measure database
throughput, HNSW recall, Cloud Run latency, real-customer exposure, or business
impact. The PostgreSQL deployment keeps an additional `FORCE ROW LEVEL SECURITY`
control, which should be verified separately against a running database.
