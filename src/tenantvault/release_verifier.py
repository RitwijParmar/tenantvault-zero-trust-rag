"""Post-deploy release gate for the public synthetic BoundaryLab demo."""
from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx


def run_release_gate(base_url: str) -> dict[str, Any]:
    """Verify identity fences and signed tenant attestations over HTTP."""
    url = base_url.rstrip("/")
    with httpx.Client(timeout=20.0) as client:
        tokens_response = client.get(f"{url}/api/demo/tokens")
        tokens_response.raise_for_status()
        tokens = {name: value["token"] for name, value in tokens_response.json().items()}
        northstar_headers = {"Authorization": f"Bearer {tokens['northstar']}"}
        header_override = client.post(
            f"{url}/v1/query",
            headers={**northstar_headers, "X-Tenant-Id": "22222222-2222-2222-2222-222222222222"},
            json={"question": "Who owns the cardiac escalation review?"},
        )
        body_override = client.post(
            f"{url}/v1/query",
            headers=northstar_headers,
            json={"question": "Who owns the cardiac escalation review?", "tenant_id": "22222222-2222-2222-2222-222222222222"},
        )

        attestations = []
        for tenant, token in tokens.items():
            headers = {"Authorization": f"Bearer {token}"}
            attestation = client.post(f"{url}/v1/attestations/run", headers=headers)
            status = client.get(f"{url}/v1/control-plane/status", headers=headers)
            attestation_payload = attestation.json() if attestation.headers.get("content-type", "").startswith("application/json") else {}
            status_payload = status.json() if status.headers.get("content-type", "").startswith("application/json") else {}
            attestations.append(
                {
                    "tenant": tenant,
                    "attestation_status_code": attestation.status_code,
                    "attestation_status": attestation_payload.get("status"),
                    "attestation_signature_present": bool(attestation_payload.get("signature")),
                    "workspace_state": status_payload.get("workspace_state"),
                    "policy_version": status_payload.get("policy_version"),
                }
            )

    passed = (
        header_override.status_code == 400
        and body_override.status_code == 422
        and all(
            item["attestation_status_code"] == 200
            and item["attestation_status"] == "passed"
            and item["attestation_signature_present"]
            and item["workspace_state"] == "active"
            and item["policy_version"]
            for item in attestations
        )
    )
    return {
        "schema_version": 1,
        "measured_at_utc": datetime.now(UTC).isoformat(),
        "target": url,
        "scope": "Synthetic demo release gate; not a production authorization audit or load benchmark.",
        "identity_fence": {
            "header_override_status": header_override.status_code,
            "body_override_status": body_override.status_code,
        },
        "tenant_attestations": attestations,
        "passed": passed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run BoundaryLab's post-deploy synthetic release gate.")
    parser.add_argument("--url", required=True, help="Candidate service URL, without a trailing slash")
    parser.add_argument("--output", type=Path, required=True, help="JSON report location")
    args = parser.parse_args()
    report = run_release_gate(args.url)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
