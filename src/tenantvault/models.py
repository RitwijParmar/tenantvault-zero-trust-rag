from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=160)
    content: str = Field(min_length=1, max_length=20_000)
    source_uri: str = Field(default="manual://upload", max_length=500)
    metadata: dict[str, Any] = Field(default_factory=dict)


class QueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=2, max_length=2_000)
    top_k: int = Field(default=4, ge=1, le=10)


class StoredDocument(BaseModel):
    document_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    title: str
    source_uri: str
    nonce: bytes
    ciphertext: bytes
    content_sha256: str
    embedding: list[float]
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RetrievalHit(BaseModel):
    document_id: UUID
    title: str
    source_uri: str
    excerpt: str
    score: float
    content_sha256: str


class IsolationReceipt(BaseModel):
    receipt_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    tenant_id: UUID
    actor: str
    policy_version: str
    search_space_count: int
    result_document_hashes: list[str]
    audit_chain_head: str
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    signature: str


class AuditEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    actor_id: str
    action: str
    request_id: UUID
    result_count: int
    previous_hash: str | None
    event_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
