from __future__ import annotations

import importlib.util
from pathlib import Path


def load_benchmark_module():
    script = Path(__file__).parents[1] / "scripts" / "fault_injection_benchmark.py"
    spec = importlib.util.spec_from_file_location("fault_injection_benchmark", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fault_injection_benchmark_shows_baseline_selection_and_zero_exposure() -> None:
    report = load_benchmark_module().run_benchmark(tenant_count=3, documents_per_tenant=4)

    assert report["configuration"]["total_documents"] == 12
    assert report["configuration"]["cross_tenant_attack_pairs"] == 6
    assert report["naive_global_vector_baseline"]["foreign_canaries_selected"] == 6
    assert report["tenantvault_tenant_scoped_retrieval"]["foreign_sources_returned"] == 0
    assert report["tenant_bound_encryption"]["foreign_ciphertext_replays_blocked"] == 6
    assert report["signed_receipts"]["tenant_tampering_detected"] == 3
    assert report["passed"] is True
