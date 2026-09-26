from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID, uuid4

from .control_plane import IsolationControlPlane
from .embeddings import HashingEmbedder
from .models import IngestRequest, IsolationReceipt, QueryRequest
from .security import Principal
from .store import RagStore, sign_receipt

POLICY_VERSION = "zt-rag/2026.09/rls+tenant-keys+receipts"
NORTHSTAR_TENANT = UUID("11111111-1111-1111-1111-111111111111")


class TenantVaultEngine:
    def __init__(self, store: RagStore, receipt_secret: str, control_plane: IsolationControlPlane | None = None) -> None:
        self.store = store
        self.embedder = HashingEmbedder()
        self._receipt_secret = receipt_secret
        self.control_plane = control_plane

    def ingest(self, principal: Principal, request: IngestRequest, request_id: UUID | None = None) -> dict[str, Any]:
        if self.control_plane:
            self.control_plane.authorize(principal)
        request_id = request_id or uuid4()
        document = self.store.ingest(
            principal,
            title=request.title,
            content=request.content,
            source_uri=request.source_uri,
            metadata=request.metadata,
            embedding=self.embedder.embed(request.content),
        )
        self.store.append_audit(
            principal,
            action="document.ingested",
            request_id=request_id,
            result_count=1,
            detail={"document_hash": document.content_sha256},
        )
        return {
            "document_id": str(document.document_id),
            "content_sha256": document.content_sha256,
            "tenant_bound": True,
            "message": "Encrypted chunk stored in the caller's tenant partition.",
        }

    def query(self, principal: Principal, request: QueryRequest, request_id: UUID | None = None) -> dict[str, Any]:
        if self.control_plane:
            self.control_plane.authorize(principal, request.top_k)
        request_id = request_id or uuid4()
        hits = self.store.search(principal, self.embedder.embed(request.question), request.top_k)
        event = self.store.append_audit(
            principal,
            action="retrieval.completed",
            request_id=request_id,
            result_count=len(hits),
            detail={"query_sha256": hashlib.sha256(request.question.encode()).hexdigest()},
        )
        receipt_payload = {
            "request_id": str(request_id),
            "tenant_id": str(principal.tenant_id),
            "actor": principal.subject,
            "policy_version": self.control_plane.policy_version(principal) if self.control_plane else POLICY_VERSION,
            "search_space_count": self.store.count_for_tenant(principal),
            "result_document_hashes": [hit.content_sha256 for hit in hits],
            "audit_chain_head": event.event_hash,
        }
        receipt = IsolationReceipt(**receipt_payload, signature=sign_receipt(self._receipt_secret, receipt_payload))
        answer = self._grounded_answer(request.question, hits)
        return {"answer": answer, "sources": [hit.model_dump() for hit in hits], "isolation_receipt": receipt.model_dump()}

    @staticmethod
    def _grounded_answer(question: str, hits: list[Any]) -> str:
        if not hits:
            return "No tenant-scoped evidence matched this question. TenantVault will not broaden the search boundary."
        citations = ", ".join(f"[{index + 1}] {hit.title}" for index, hit in enumerate(hits))
        excerpt = hits[0].excerpt.replace("\n", " ")
        return f"Tenant-scoped evidence: {excerpt}  Sources: {citations}"

    def isolation_probe(self, principal: Principal) -> dict[str, Any]:
        """A harmless public challenge: query for another demo tenant's canary.

        The response intentionally says only whether the caller saw a match; it
        never returns another tenant's canary, identifier, or document count.
        """
        other_tenant_canary = "CONDOR-74-NEVER-LEAK" if principal.tenant_id == NORTHSTAR_TENANT else "ORCHID-27-NEVER-LEAK"
        probe = self.query(principal, QueryRequest(question=other_tenant_canary, top_k=3))
        leaked = any(other_tenant_canary in source["excerpt"] for source in probe["sources"])
        return {
            "status": "failed" if leaked else "passed",
            "assertion": "A cross-tenant canary was not present in this caller's retrieval results.",
            "receipt": probe["isolation_receipt"],
        }

    def attest(self, principal: Principal) -> dict[str, Any]:
        if not self.control_plane:
            raise RuntimeError("an isolation control plane is required for attestation")
        return self.control_plane.attest(principal, lambda: self.isolation_probe(principal))
