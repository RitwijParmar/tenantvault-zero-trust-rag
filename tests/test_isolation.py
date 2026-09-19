from __future__ import annotations

from pathlib import Path
from uuid import UUID

from tenantvault.engine import TenantVaultEngine
from tenantvault.models import IngestRequest, QueryRequest
from tenantvault.security import Principal, TenantCipher
from tenantvault.store import MemoryRagStore, sign_receipt

ALPHA = UUID("11111111-1111-1111-1111-111111111111")
BETA = UUID("22222222-2222-2222-2222-222222222222")


def principal(tenant_id: UUID, scopes: set[str] | None = None) -> Principal:
    return Principal(tenant_id, f"user-{tenant_id.hex[:4]}", frozenset(scopes or {"rag:read", "rag:write"}))


def test_cross_tenant_canary_is_never_retrieved() -> None:
    engine = TenantVaultEngine(MemoryRagStore(TenantCipher("test-root-secret")), "receipt-secret")
    engine.ingest(principal(ALPHA), IngestRequest(title="Alpha plan", content="Alpha only: service ownership is green."))
    engine.ingest(principal(BETA), IngestRequest(title="Beta secret", content="CONDOR-74-NEVER-LEAK belongs only to Beta."))

    result = engine.query(principal(ALPHA), QueryRequest(question="What is CONDOR-74-NEVER-LEAK?"))

    assert result["sources"] == []
    assert all("CONDOR-74-NEVER-LEAK" not in hit["excerpt"] for hit in result["sources"])
    assert result["isolation_receipt"]["search_space_count"] == 1
    assert result["isolation_receipt"]["tenant_id"] == ALPHA


def test_source_ciphertext_cannot_be_decrypted_using_another_tenant_key() -> None:
    cipher = TenantCipher("test-root-secret")
    nonce, ciphertext = cipher.encrypt(ALPHA, "confidential alpha content")

    from cryptography.exceptions import InvalidTag

    try:
        cipher.decrypt(BETA, nonce, ciphertext)
    except InvalidTag:
        pass
    else:  # pragma: no cover - this is an explicit security regression assertion
        raise AssertionError("cross-tenant decryption unexpectedly succeeded")


def test_receipt_signature_binds_the_tenant_and_result_set() -> None:
    engine = TenantVaultEngine(MemoryRagStore(TenantCipher("test-root-secret")), "receipt-secret")
    engine.ingest(principal(ALPHA), IngestRequest(title="Alpha plan", content="Alpha document."))
    result = engine.query(principal(ALPHA), QueryRequest(question="Alpha document"))
    receipt = result["isolation_receipt"]
    signed = {key: receipt[key] for key in ["request_id", "tenant_id", "actor", "policy_version", "search_space_count", "result_document_hashes", "audit_chain_head"]}

    assert receipt["signature"] == sign_receipt("receipt-secret", signed)
    signed["tenant_id"] = str(BETA)
    assert receipt["signature"] != sign_receipt("receipt-secret", signed)


def test_database_migration_forces_rls_and_requires_a_tenant_context() -> None:
    sql = (Path(__file__).parents[1] / "migrations" / "001_zero_trust.sql").read_text()

    assert "FORCE ROW LEVEL SECURITY" in sql
    assert "RAISE EXCEPTION 'tenant context is required'" in sql
    assert "tenant_id = app.require_tenant()" in sql
    assert "GRANT SELECT, INSERT ON rag.documents TO tenantvault_api" in sql
    assert "GRANT ALL" not in sql
