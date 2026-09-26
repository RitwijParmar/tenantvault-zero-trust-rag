from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from tenantvault.control_plane import (
    ContractError,
    IsolationControlPlane,
    PolicyCompiler,
    TenantQuarantinedError,
)
from tenantvault.security import Principal

POLICY_PATH = Path(__file__).parents[1] / "policies" / "tenant-contracts.json"
NORTHSTAR = UUID("11111111-1111-1111-1111-111111111111")


def principal() -> Principal:
    return Principal(NORTHSTAR, "control-plane-test", frozenset({"rag:read", "rag:write"}))


def test_contract_compiler_requires_the_fixed_isolation_controls(tmp_path: Path) -> None:
    path = tmp_path / "unsafe-contract.json"
    path.write_text('{"schema_version": 1, "release_gate": {"required_controls": [], "quarantine_on_failed_attestation": true}, "contracts": []}')

    with pytest.raises(ContractError, match="removes required controls"):
        PolicyCompiler.from_file(path)


def test_failed_attestation_quarantines_only_the_affected_tenant() -> None:
    control_plane = IsolationControlPlane(PolicyCompiler.from_file(POLICY_PATH), "test-control-plane-secret")
    record = control_plane.record_attestation(principal(), {"status": "failed", "receipt": {}}, elapsed_ms=2.0)

    assert record["status"] == "failed"
    assert record["quarantined"] is True
    assert record["signature"]
    with pytest.raises(TenantQuarantinedError):
        control_plane.authorize(principal())
