"""Run repeatable, black-box security and latency checks against a live TenantVault URL.

The output intentionally measures only what this script observes. It is an
integration check for the seeded demo corpus, not a production capacity claim.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

TENANTS = {
    "northstar": "11111111-1111-1111-1111-111111111111",
    "acme": "22222222-2222-2222-2222-222222222222",
}
QUESTIONS = {
    "northstar": "Who owns the cardiac escalation review?",
    "acme": "What is restricted in the Acme flight systems note?",
}


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def post_json(client: httpx.Client, url: str, headers: dict[str, str], body: dict[str, Any] | None) -> tuple[int, Any, float]:
    started = time.perf_counter()
    response = client.post(url, headers=headers, json=body)
    elapsed_ms = (time.perf_counter() - started) * 1000
    try:
        payload = response.json()
    except ValueError:
        payload = {"unparseable_response": True}
    return response.status_code, payload, elapsed_ms


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure TenantVault's live isolation controls.")
    parser.add_argument("--url", required=True, help="Cloud Run service URL, without a trailing slash")
    parser.add_argument("--iterations", type=int, default=25, help="Checks per tenant and endpoint")
    parser.add_argument("--workers", type=int, default=8, help="Maximum concurrent HTTP requests")
    parser.add_argument("--output", type=Path, required=True, help="JSON report location")
    args = parser.parse_args()
    if args.iterations < 1 or args.workers < 1:
        parser.error("iterations and workers must be positive")

    base_url = args.url.rstrip("/")
    with httpx.Client(timeout=20.0) as client:
        tokens_response = client.get(f"{base_url}/api/demo/tokens")
        tokens_response.raise_for_status()
        tokens = {name: data["token"] for name, data in tokens_response.json().items()}

        boundary_checks: dict[str, int] = {}
        alpha_headers = {"Authorization": f"Bearer {tokens['northstar']}"}
        status, _, _ = post_json(
            client,
            f"{base_url}/v1/query",
            {**alpha_headers, "X-Tenant-Id": TENANTS["acme"]},
            {"question": QUESTIONS["northstar"]},
        )
        boundary_checks["header_override_status"] = status
        status, _, _ = post_json(
            client,
            f"{base_url}/v1/query",
            alpha_headers,
            {"question": QUESTIONS["northstar"], "tenant_id": TENANTS["acme"]},
        )
        boundary_checks["body_override_status"] = status

        def retrieval(tenant: str) -> dict[str, Any]:
            status, payload, elapsed_ms = post_json(
                client,
                f"{base_url}/v1/query",
                {"Authorization": f"Bearer {tokens[tenant]}"},
                {"question": QUESTIONS[tenant], "top_k": 3},
            )
            receipt = payload.get("isolation_receipt", {}) if isinstance(payload, dict) else {}
            return {
                "kind": "retrieval",
                "tenant": tenant,
                "status": status,
                "latency_ms": elapsed_ms,
                "valid": (
                    status == 200
                    and receipt.get("tenant_id") == TENANTS[tenant]
                    and bool(receipt.get("signature"))
                    and bool(payload.get("sources"))
                ),
            }

        def canary_probe(tenant: str) -> dict[str, Any]:
            status, payload, elapsed_ms = post_json(
                client,
                f"{base_url}/v1/isolation/probe",
                {"Authorization": f"Bearer {tokens[tenant]}"},
                None,
            )
            return {
                "kind": "canary_probe",
                "tenant": tenant,
                "status": status,
                "latency_ms": elapsed_ms,
                "valid": status == 200 and isinstance(payload, dict) and payload.get("status") == "passed",
            }

        jobs = []
        for _ in range(args.iterations):
            for tenant in TENANTS:
                jobs.extend([(retrieval, tenant), (canary_probe, tenant)])
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(function, tenant) for function, tenant in jobs]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

    retrieval_results = [result for result in results if result["kind"] == "retrieval"]
    probe_results = [result for result in results if result["kind"] == "canary_probe"]
    retrieval_latencies = [result["latency_ms"] for result in retrieval_results]
    report = {
        "schema_version": 1,
        "measured_at_utc": datetime.now(UTC).isoformat(),
        "target": base_url,
        "scope": "Synthetic two-tenant runtime check; not a production load or business-impact benchmark.",
        "configuration": {"iterations_per_tenant": args.iterations, "workers": args.workers},
        "boundary_checks": boundary_checks,
        "retrieval": {
            "attempted": len(retrieval_results),
            "passed": sum(result["valid"] for result in retrieval_results),
            "p50_ms": round(statistics.median(retrieval_latencies), 2),
            "p95_ms": round(percentile(retrieval_latencies, 0.95), 2),
        },
        "cross_tenant_canary": {
            "attempted": len(probe_results),
            "passed": sum(result["valid"] for result in probe_results),
            "exposures_observed": sum(not result["valid"] for result in probe_results),
        },
    }
    report["passed"] = (
        boundary_checks == {"header_override_status": 400, "body_override_status": 422}
        and report["retrieval"]["attempted"] == report["retrieval"]["passed"]
        and report["cross_tenant_canary"]["exposures_observed"] == 0
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
