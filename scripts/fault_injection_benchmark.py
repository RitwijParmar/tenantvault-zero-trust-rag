"""Quantify how TenantVault responds when a RAG tenant filter is missing.

This is a deterministic, synthetic evaluation. It compares an intentionally
unsafe global-vector baseline with the tenant-scoped TenantVault engine, then
checks the independent encryption and receipt-integrity fences. It does not
measure PostgreSQL throughput or production traffic.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidTag

from tenantvault.embeddings import cosine_similarity
from tenantvault.engine import TenantVaultEngine
from tenantvault.models import IngestRequest, QueryRequest
from tenantvault.security import Principal, TenantCipher
from tenantvault.store import MemoryRagStore, sign_receipt


def benchmark_principal(index: int) -> Principal:
    return Principal(
        tenant_id=UUID(int=index + 1),
        subject=f"benchmark-tenant-{index + 1:02d}",
        scopes=frozenset({"rag:read", "rag:write"}),
    )


def canary_for(index: int) -> str:
    return f"TENANT-{index + 1:02d}-CANARY-DO-NOT-DISCLOSE"


def receipt_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: receipt[key]
        for key in [
            "request_id",
            "tenant_id",
            "actor",
            "policy_version",
            "search_space_count",
            "result_document_hashes",
            "audit_chain_head",
        ]
    }


def run_benchmark(tenant_count: int = 12, documents_per_tenant: int = 48) -> dict[str, Any]:
    """Run a reproducible missing-filter experiment and return JSON-safe metrics."""
    if tenant_count < 2:
        raise ValueError("tenant_count must be at least 2")
    if documents_per_tenant < 2:
        raise ValueError("documents_per_tenant must be at least 2")

    cipher = TenantCipher("benchmark-root-secret-not-for-production")
    store = MemoryRagStore(cipher)
    receipt_secret = "benchmark-receipt-secret-not-for-production"
    engine = TenantVaultEngine(store, receipt_secret)
    principals = [benchmark_principal(index) for index in range(tenant_count)]
    canary_documents = {}

    for index, principal in enumerate(principals):
        canary = canary_for(index)
        engine.ingest(
            principal,
            IngestRequest(
                title=f"Tenant {index + 1:02d} restricted brief",
                source_uri=f"benchmark://tenant-{index + 1:02d}/restricted",
                content=f"{canary} belongs only to tenant {index + 1:02d}.",
            ),
        )
        canary_documents[principal.tenant_id] = store._documents[principal.tenant_id][-1]
        for document_number in range(1, documents_per_tenant):
            engine.ingest(
                principal,
                IngestRequest(
                    title=f"Tenant {index + 1:02d} operational note {document_number:02d}",
                    source_uri=f"benchmark://tenant-{index + 1:02d}/note-{document_number:02d}",
                    content=(
                        f"Tenant {index + 1:02d} internal operational note {document_number:02d}. "
                        "This synthetic document is a retrieval distractor."
                    ),
                ),
            )

    all_documents = [document for documents in store._documents.values() for document in documents]
    baseline_selected_foreign_canaries = 0
    tenantvault_foreign_sources_returned = 0
    encryption_replays_blocked = 0
    attack_pairs = 0

    for attacker in principals:
        for victim_index, victim in enumerate(principals):
            if attacker.tenant_id == victim.tenant_id:
                continue
            attack_pairs += 1
            victim_canary = canary_for(victim_index)
            query_embedding = engine.embedder.embed(victim_canary)

            # Intentionally unsafe reference: a global vector search after a
            # developer omitted the tenant condition. It selects the victim's
            # exact canary document for every attack pair in this corpus.
            naive_top_hit = max(
                all_documents,
                key=lambda document: cosine_similarity(query_embedding, document.embedding),
            )
            if naive_top_hit.tenant_id == victim.tenant_id:
                baseline_selected_foreign_canaries += 1

            secured_result = engine.query(attacker, QueryRequest(question=victim_canary, top_k=1))
            if any(victim_canary in source["excerpt"] for source in secured_result["sources"]):
                tenantvault_foreign_sources_returned += 1

            victim_document = canary_documents[victim.tenant_id]
            try:
                cipher.decrypt(attacker.tenant_id, victim_document.nonce, victim_document.ciphertext)
            except InvalidTag:
                encryption_replays_blocked += 1

    receipt_tampering_detected = 0
    for index, principal in enumerate(principals):
        result = engine.query(principal, QueryRequest(question=canary_for(index), top_k=1))
        receipt = result["isolation_receipt"]
        tampered = receipt_payload(receipt)
        tampered["tenant_id"] = str(principals[(index + 1) % tenant_count].tenant_id)
        if receipt["signature"] != sign_receipt(receipt_secret, tampered):
            receipt_tampering_detected += 1

    total_documents = tenant_count * documents_per_tenant
    return {
        "schema_version": 1,
        "scope": (
            "Deterministic local synthetic fault injection. It compares retrieval-boundary "
            "behavior, not PostgreSQL throughput, production traffic, or business impact."
        ),
        "configuration": {
            "tenants": tenant_count,
            "documents_per_tenant": documents_per_tenant,
            "total_documents": total_documents,
            "cross_tenant_attack_pairs": attack_pairs,
        },
        "naive_global_vector_baseline": {
            "foreign_canaries_selected": baseline_selected_foreign_canaries,
            "attack_pairs": attack_pairs,
            "selection_rate": round(baseline_selected_foreign_canaries / attack_pairs, 4),
            "meaning": "A missing tenant filter selected the target foreign canary as top result.",
        },
        "tenantvault_tenant_scoped_retrieval": {
            "foreign_sources_returned": tenantvault_foreign_sources_returned,
            "attack_pairs": attack_pairs,
            "exposure_rate": round(tenantvault_foreign_sources_returned / attack_pairs, 4),
        },
        "tenant_bound_encryption": {
            "foreign_ciphertext_replays_blocked": encryption_replays_blocked,
            "attempts": attack_pairs,
            "block_rate": round(encryption_replays_blocked / attack_pairs, 4),
        },
        "signed_receipts": {
            "tenant_tampering_detected": receipt_tampering_detected,
            "attempts": tenant_count,
            "detection_rate": round(receipt_tampering_detected / tenant_count, 4),
        },
        "passed": (
            baseline_selected_foreign_canaries == attack_pairs
            and tenantvault_foreign_sources_returned == 0
            and encryption_replays_blocked == attack_pairs
            and receipt_tampering_detected == tenant_count
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TenantVault's synthetic fault-injection benchmark.")
    parser.add_argument("--tenants", type=int, default=12, help="Synthetic tenant count (default: 12)")
    parser.add_argument("--documents-per-tenant", type=int, default=48, help="Documents per tenant (default: 48)")
    parser.add_argument("--output", type=Path, required=True, help="JSON report location")
    args = parser.parse_args()

    try:
        report = run_benchmark(args.tenants, args.documents_per_tenant)
    except ValueError as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
