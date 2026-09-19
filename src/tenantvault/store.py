from __future__ import annotations

import hashlib
import hmac
import json
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from .embeddings import cosine_similarity
from .models import AuditEvent, RetrievalHit, StoredDocument
from .security import Principal, TenantCipher, digest


class RagStore(Protocol):
    def ingest(
        self,
        principal: Principal,
        *,
        title: str,
        content: str,
        source_uri: str,
        metadata: dict[str, Any],
        embedding: list[float],
    ) -> StoredDocument: ...

    def search(self, principal: Principal, embedding: list[float], top_k: int) -> list[RetrievalHit]: ...

    def count_for_tenant(self, principal: Principal) -> int: ...

    def append_audit(
        self, principal: Principal, *, action: str, request_id: UUID, result_count: int, detail: dict[str, Any]
    ) -> AuditEvent: ...

    def audit_head(self, principal: Principal) -> str: ...


@dataclass
class MemoryRagStore:
    """Demo implementation with the same no-cross-tenant method contract as Postgres.

    Its Python fence makes the demo self-contained. Production uses PostgresRagStore,
    where the matching fence is mandatory database RLS, not an application convention.
    """

    cipher: TenantCipher

    def __post_init__(self) -> None:
        self._documents: dict[UUID, list[StoredDocument]] = defaultdict(list)
        self._events: dict[UUID, list[AuditEvent]] = defaultdict(list)

    def ingest(
        self,
        principal: Principal,
        *,
        title: str,
        content: str,
        source_uri: str,
        metadata: dict[str, Any],
        embedding: list[float],
    ) -> StoredDocument:
        if not principal.can("rag:write"):
            raise PermissionError("principal lacks rag:write")
        nonce, ciphertext = self.cipher.encrypt(principal.tenant_id, content)
        document = StoredDocument(
            tenant_id=principal.tenant_id,
            title=title,
            source_uri=source_uri,
            nonce=nonce,
            ciphertext=ciphertext,
            content_sha256=digest(content),
            embedding=embedding,
            metadata=metadata,
        )
        self._documents[principal.tenant_id].append(document)
        return document

    def search(self, principal: Principal, embedding: list[float], top_k: int) -> list[RetrievalHit]:
        if not principal.can("rag:read"):
            raise PermissionError("principal lacks rag:read")
        # Never scan all tenant buckets. This defensive local behavior mirrors the
        # SQL policy; it is deliberately visible for reviewers and test authors.
        candidates = self._documents[principal.tenant_id]
        ranked = sorted(
            (
                (cosine_similarity(embedding, document.embedding), document)
                for document in candidates
                if cosine_similarity(embedding, document.embedding) >= 0.18
            ),
            key=lambda item: item[0],
            reverse=True,
        )[:top_k]
        hits: list[RetrievalHit] = []
        for score, document in ranked:
            plaintext = self.cipher.decrypt(principal.tenant_id, document.nonce, document.ciphertext)
            hits.append(
                RetrievalHit(
                    document_id=document.document_id,
                    title=document.title,
                    source_uri=document.source_uri,
                    excerpt=plaintext[:500],
                    score=round(score, 4),
                    content_sha256=document.content_sha256,
                )
            )
        return hits

    def count_for_tenant(self, principal: Principal) -> int:
        return len(self._documents[principal.tenant_id])

    def append_audit(
        self, principal: Principal, *, action: str, request_id: UUID, result_count: int, detail: dict[str, Any]
    ) -> AuditEvent:
        previous_hash = self.audit_head(principal)
        created_at = datetime.now(UTC)
        canonical = json.dumps(
            {
                "tenant_id": str(principal.tenant_id),
                "actor": principal.subject,
                "action": action,
                "request_id": str(request_id),
                "result_count": result_count,
                "detail": detail,
                "previous_hash": previous_hash,
                "created_at": created_at.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        event = AuditEvent(
            tenant_id=principal.tenant_id,
            actor_id=principal.subject,
            action=action,
            request_id=request_id,
            result_count=result_count,
            previous_hash=previous_hash or None,
            event_hash=hashlib.sha256(canonical.encode()).hexdigest(),
            created_at=created_at,
        )
        self._events[principal.tenant_id].append(event)
        return event

    def audit_head(self, principal: Principal) -> str:
        events = self._events[principal.tenant_id]
        return events[-1].event_hash if events else "0" * 64


class PostgresRagStore:
    """PostgreSQL implementation. Every operation sets tenant context locally.

    The server role is non-owner and the migration uses FORCE ROW LEVEL SECURITY,
    so a missed WHERE clause still cannot disclose another tenant's rows.
    """

    def __init__(self, database_url: str, cipher: TenantCipher) -> None:
        try:
            import psycopg
            from psycopg.types.json import Jsonb
        except ImportError as error:  # pragma: no cover - packaging guard
            raise RuntimeError("Install TenantVault with the postgres dependency") from error
        self._psycopg = psycopg
        self._jsonb = Jsonb
        self._database_url = database_url
        self.cipher = cipher

    @contextmanager
    def _transaction(self, principal: Principal):
        connection = self._psycopg.connect(self._database_url)
        transaction = connection.transaction()
        transaction.__enter__()
        try:
            # true means the setting is transaction-local. A pooled connection cannot
            # accidentally carry Tenant A's context into a Tenant B request.
            connection.execute("SELECT set_config('app.tenant_id', %s, true)", (str(principal.tenant_id),))
            yield connection
            transaction.__exit__(None, None, None)
        except BaseException as error:
            transaction.__exit__(type(error), error, error.__traceback__)
            raise
        finally:
            connection.close()

    def ingest(self, principal: Principal, **kwargs: Any) -> StoredDocument:
        if not principal.can("rag:write"):
            raise PermissionError("principal lacks rag:write")
        content = kwargs["content"]
        nonce, ciphertext = self.cipher.encrypt(principal.tenant_id, content)
        document = StoredDocument(
            tenant_id=principal.tenant_id,
            title=kwargs["title"],
            source_uri=kwargs["source_uri"],
            nonce=nonce,
            ciphertext=ciphertext,
            content_sha256=digest(content),
            embedding=kwargs["embedding"],
            metadata=kwargs["metadata"],
        )
        with self._transaction(principal) as connection:
            connection.execute(
                """
                INSERT INTO rag.documents
                  (document_id, title, source_uri, content_ciphertext, content_nonce,
                   content_sha256, metadata, embedding)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s::vector)
                """,
                (
                    document.document_id,
                    document.title,
                    document.source_uri,
                    document.ciphertext,
                    document.nonce,
                    document.content_sha256,
                    self._jsonb(document.metadata),
                    self._vector_literal(document.embedding),
                ),
            )
        return document

    def search(self, principal: Principal, embedding: list[float], top_k: int) -> list[RetrievalHit]:
        if not principal.can("rag:read"):
            raise PermissionError("principal lacks rag:read")
        with self._transaction(principal) as connection:
            rows = connection.execute(
                """
                SELECT document_id, title, source_uri, content_ciphertext, content_nonce,
                       content_sha256, 1 - (embedding <=> %s::vector) AS score
                FROM rag.documents
                WHERE (embedding <=> %s::vector) <= 0.82
                ORDER BY embedding <=> %s::vector
                LIMIT %s
                """,
                (self._vector_literal(embedding), self._vector_literal(embedding), self._vector_literal(embedding), top_k),
            ).fetchall()
        return [
            RetrievalHit(
                document_id=row[0],
                title=row[1],
                source_uri=row[2],
                excerpt=self.cipher.decrypt(principal.tenant_id, row[4], bytes(row[3]))[:500],
                content_sha256=row[5],
                score=round(float(row[6]), 4),
            )
            for row in rows
        ]

    def count_for_tenant(self, principal: Principal) -> int:
        with self._transaction(principal) as connection:
            return int(connection.execute("SELECT count(*) FROM rag.documents").fetchone()[0])

    def append_audit(self, principal: Principal, *, action: str, request_id: UUID, result_count: int, detail: dict[str, Any]) -> AuditEvent:
        previous_hash = self.audit_head(principal)
        created_at = datetime.now(UTC)
        canonical = json.dumps(
            {"tenant": str(principal.tenant_id), "actor": principal.subject, "action": action, "request": str(request_id), "results": result_count, "detail": detail, "previous": previous_hash, "time": created_at.isoformat()},
            sort_keys=True,
            separators=(",", ":"),
        )
        event = AuditEvent(tenant_id=principal.tenant_id, actor_id=principal.subject, action=action, request_id=request_id, result_count=result_count, previous_hash=previous_hash if previous_hash != "0" * 64 else None, event_hash=hashlib.sha256(canonical.encode()).hexdigest(), created_at=created_at)
        with self._transaction(principal) as connection:
            connection.execute(
                "INSERT INTO audit.events (event_id, actor_id, action, request_id, result_count, detail, previous_hash, event_hash, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (event.event_id, event.actor_id, event.action, event.request_id, event.result_count, self._jsonb(detail), event.previous_hash, event.event_hash, event.created_at),
            )
        return event

    def audit_head(self, principal: Principal) -> str:
        with self._transaction(principal) as connection:
            row = connection.execute("SELECT event_hash FROM audit.events ORDER BY created_at DESC LIMIT 1").fetchone()
        return str(row[0]) if row else "0" * 64

    @staticmethod
    def _vector_literal(vector: list[float]) -> str:
        return "[" + ",".join(f"{value:.8f}" for value in vector) + "]"


def sign_receipt(secret: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
