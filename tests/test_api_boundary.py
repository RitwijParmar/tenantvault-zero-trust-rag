from __future__ import annotations

from fastapi.testclient import TestClient

from tenantvault.api import app


def token(client: TestClient, tenant: str = "northstar") -> str:
    return client.get("/api/demo/tokens").json()[tenant]["token"]


def test_api_rejects_header_tenant_override() -> None:
    client = TestClient(app)
    response = client.post(
        "/v1/query",
        headers={"Authorization": f"Bearer {token(client)}", "X-Tenant-Id": "22222222-2222-2222-2222-222222222222"},
        json={"question": "Who owns the cardiac escalation review?"},
    )
    assert response.status_code == 400
    assert "forbidden" in response.json()["detail"]


def test_api_rejects_body_tenant_override_and_returns_receipt() -> None:
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token(client)}"}
    injection = client.post("/v1/query", headers=headers, json={"question": "hello", "tenant_id": "22222222-2222-2222-2222-222222222222"})
    assert injection.status_code == 422

    response = client.post("/v1/query", headers=headers, json={"question": "Who owns the cardiac escalation review?"})
    assert response.status_code == 200
    receipt = response.json()["isolation_receipt"]
    assert receipt["tenant_id"] == "11111111-1111-1111-1111-111111111111"
    assert receipt["signature"]


def test_api_cross_tenant_canary_probe_passes() -> None:
    client = TestClient(app)
    response = client.post("/v1/isolation/probe", headers={"Authorization": f"Bearer {token(client, 'northstar')}"})
    assert response.status_code == 200
    assert response.json()["status"] == "passed"

    response = client.post("/v1/isolation/probe", headers={"Authorization": f"Bearer {token(client, 'acme')}"})
    assert response.status_code == 200
    assert response.json()["status"] == "passed"


def test_api_adds_browser_security_headers_and_prevents_api_caching() -> None:
    client = TestClient(app)
    response = client.post(
        "/v1/query",
        headers={"Authorization": f"Bearer {token(client)}"},
        json={"question": "cardiac escalation"},
    )
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
