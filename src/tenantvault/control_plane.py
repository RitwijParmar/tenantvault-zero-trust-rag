"""Policy-as-code contracts and fail-closed tenant isolation attestations."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from .security import Principal

REQUIRED_CONTROLS = {
    "signed_tenant_claim",
    "postgres_force_rls",
    "tenant_bound_aes_gcm",
    "signed_isolation_receipt",
}


class ContractError(ValueError):
    """Raised when a policy contract weakens TenantVault's fixed trust boundary."""


class TenantQuarantinedError(PermissionError):
    """Raised when a failed attestation has fail-closed a tenant workspace."""


@dataclass(frozen=True)
class TenantContract:
    tenant_id: UUID
    policy_version: str
    max_results: int
    required_scopes: frozenset[str]
    attestation_slo_seconds: int
    contract_hash: str


class PolicyCompiler:
    """Loads reviewed contracts and rejects configurations that remove core controls."""

    def __init__(self, contracts: dict[UUID, TenantContract], release_gate: dict[str, Any]) -> None:
        self._contracts = contracts
        self.release_gate = release_gate

    @classmethod
    def from_file(cls, path: Path) -> PolicyCompiler:
        source = json.loads(path.read_text())
        if source.get("schema_version") != 1:
            raise ContractError("unsupported policy contract schema")
        release_gate = source.get("release_gate", {})
        configured_controls = set(release_gate.get("required_controls", []))
        if not REQUIRED_CONTROLS.issubset(configured_controls):
            missing = ", ".join(sorted(REQUIRED_CONTROLS - configured_controls))
            raise ContractError(f"policy contract removes required controls: {missing}")
        if release_gate.get("quarantine_on_failed_attestation") is not True:
            raise ContractError("failed attestations must quarantine the affected tenant")

        contracts: dict[UUID, TenantContract] = {}
        for raw in source.get("contracts", []):
            tenant_id = UUID(raw["tenant_id"])
            max_results = int(raw["max_results"])
            if not 1 <= max_results <= 10:
                raise ContractError("max_results must be between 1 and 10")
            scopes = frozenset(raw.get("required_scopes", []))
            if "rag:read" not in scopes:
                raise ContractError("every tenant contract must require rag:read")
            canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
            contracts[tenant_id] = TenantContract(
                tenant_id=tenant_id,
                policy_version=str(raw["policy_version"]),
                max_results=max_results,
                required_scopes=scopes,
                attestation_slo_seconds=int(raw["attestation_slo_seconds"]),
                contract_hash=hashlib.sha256(canonical.encode()).hexdigest(),
            )
        if not contracts:
            raise ContractError("at least one tenant contract is required")
        return cls(contracts, release_gate)

    def contract_for(self, tenant_id: UUID) -> TenantContract:
        try:
            return self._contracts[tenant_id]
        except KeyError as error:
            raise ContractError("tenant has no approved policy contract") from error


class IsolationControlPlane:
    """Owns contract state, attestation ledger, and tenant-local quarantine state.

    The in-process version supports the self-contained demo. The external release
    verifier treats its signed records as the deployment gate; production should
    persist this ledger in a separately privileged control-plane store.
    """

    def __init__(self, compiler: PolicyCompiler, signing_secret: str) -> None:
        self._compiler = compiler
        self._signing_key = signing_secret.encode()
        self._state = {tenant_id: "active" for tenant_id in compiler._contracts}
        self._attestations: dict[UUID, list[dict[str, Any]]] = {tenant_id: [] for tenant_id in compiler._contracts}

    def authorize(self, principal: Principal, requested_top_k: int | None = None) -> TenantContract:
        contract = self._compiler.contract_for(principal.tenant_id)
        if self._state[principal.tenant_id] == "quarantined":
            raise TenantQuarantinedError("tenant workspace is quarantined after a failed isolation attestation")
        if not contract.required_scopes.issubset(principal.scopes):
            raise PermissionError("principal does not satisfy the tenant policy contract")
        if requested_top_k is not None and requested_top_k > contract.max_results:
            raise PermissionError("requested result count exceeds the tenant policy contract")
        return contract

    def policy_version(self, principal: Principal) -> str:
        return self._compiler.contract_for(principal.tenant_id).policy_version

    def record_attestation(self, principal: Principal, probe: dict[str, Any], elapsed_ms: float) -> dict[str, Any]:
        contract = self._compiler.contract_for(principal.tenant_id)
        passed = probe.get("status") == "passed" and elapsed_ms <= contract.attestation_slo_seconds * 1000
        if not passed:
            self._state[principal.tenant_id] = "quarantined"
        record = {
            "attestation_id": str(uuid4()),
            "tenant_id": str(principal.tenant_id),
            "policy_version": contract.policy_version,
            "contract_hash": contract.contract_hash,
            "status": "passed" if passed else "failed",
            "quarantined": self._state[principal.tenant_id] == "quarantined",
            "elapsed_ms": round(elapsed_ms, 2),
            "issued_at": datetime.now(UTC).isoformat(),
            "probe_receipt_signature": probe.get("receipt", {}).get("signature"),
        }
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
        record["signature"] = hmac.new(self._signing_key, canonical.encode(), hashlib.sha256).hexdigest()
        self._attestations[principal.tenant_id].append(record)
        return record

    def attest(self, principal: Principal, run_probe: Any) -> dict[str, Any]:
        self.authorize(principal)
        started = time.perf_counter()
        probe = run_probe()
        return self.record_attestation(principal, probe, (time.perf_counter() - started) * 1000)

    def status_for(self, principal: Principal) -> dict[str, Any]:
        contract = self._compiler.contract_for(principal.tenant_id)
        records = self._attestations[principal.tenant_id]
        return {
            "tenant_id": str(principal.tenant_id),
            "workspace_state": self._state[principal.tenant_id],
            "policy_version": contract.policy_version,
            "contract_hash": contract.contract_hash,
            "attestation_slo_seconds": contract.attestation_slo_seconds,
            "last_attestation": records[-1] if records else None,
        }
