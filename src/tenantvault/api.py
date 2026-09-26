from __future__ import annotations

from pathlib import Path
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from .control_plane import IsolationControlPlane, PolicyCompiler, TenantQuarantinedError
from .engine import TenantVaultEngine
from .models import IngestRequest, QueryRequest
from .security import AuthenticationError, Principal, TenantCipher, TokenAuthority
from .settings import settings
from .store import MemoryRagStore, PostgresRagStore

ROOT = Path(settings.app_root) if (Path(settings.app_root) / "web").exists() else Path(__file__).resolve().parents[2]
ALPHA = UUID("11111111-1111-1111-1111-111111111111")
BETA = UUID("22222222-2222-2222-2222-222222222222")
bearer = HTTPBearer(auto_error=False)
authority = TokenAuthority(settings.token_secret)


def build_engine() -> TenantVaultEngine:
    cipher = TenantCipher(settings.tenant_key_root)
    contracts = PolicyCompiler.from_file(ROOT / "policies" / "tenant-contracts.json")
    control_plane = IsolationControlPlane(contracts, settings.receipt_secret)
    if settings.store_mode == "postgres":
        if not settings.database_url:
            raise RuntimeError("DATABASE_URL is required when STORE_MODE=postgres")
        store = PostgresRagStore(settings.database_url, cipher)
    else:
        store = MemoryRagStore(cipher)
    engine = TenantVaultEngine(store, settings.receipt_secret, control_plane)
    if settings.demo_mode:
        _seed_demo(engine)
    return engine


def _seed_demo(engine: TenantVaultEngine) -> None:
    alpha = Principal(ALPHA, "alice@northstar.example", frozenset({"rag:read", "rag:write"}))
    beta = Principal(BETA, "bob@acme.example", frozenset({"rag:read", "rag:write"}))
    # A privileged control plane, not an end-user endpoint, performs tenant onboarding.
    # Avoid duplicate fixtures when the API container restarts against an existing DB.
    if engine.store.count_for_tenant(alpha) == 0:
        engine.ingest(alpha, IngestRequest(title="Northstar care operations", source_uri="northstar://care-ops", content="ORCHID-27-NEVER-LEAK is Northstar Health's restricted incident canary. Northstar's care-operations playbook requires an on-call nurse review for cardiac escalation. The weekday escalation owner is Maya Chen."))
    if engine.store.count_for_tenant(beta) == 0:
        engine.ingest(beta, IngestRequest(title="Acme flight systems", source_uri="acme://flight-systems", content="CONDOR-74-NEVER-LEAK is Acme Robotics' flight-control canary. The prototype's launch window and guidance parameters are restricted to Acme Robotics."))


engine = build_engine()
app = FastAPI(
    title="TenantVault",
    version="1.0.0",
    summary="Zero-trust multi-tenant RAG with database-enforced isolation.",
)
app.mount("/assets", StaticFiles(directory=ROOT / "web"), name="assets")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; img-src 'self' data:"
    if request.url.path.startswith("/v1/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def authenticated_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    tenant_override: str | None = Header(default=None, alias="X-Tenant-Id"),
) -> Principal:
    if tenant_override is not None:
        # This blocks a common confused-deputy anti-pattern before it can reach a store.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="X-Tenant-Id is forbidden; tenant identity comes only from the signed credential.")
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer credential required")
    try:
        return authority.verify(credentials.credentials)
    except AuthenticationError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(error)) from error


@app.get("/")
def home() -> FileResponse:
    return FileResponse(ROOT / "web" / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "tenantvault", "store": settings.store_mode, "isolation": "postgres-rls-ready"}


@app.get("/api/demo/tokens")
def demo_tokens() -> dict[str, dict[str, str]]:
    if not settings.demo_mode:
        raise HTTPException(status_code=404, detail="Demo identities are disabled")
    scopes = {"rag:read", "rag:write"}
    return {
        "northstar": {"label": "Northstar Health", "token": authority.mint(ALPHA, "alice@northstar.example", scopes)},
        "acme": {"label": "Acme Robotics", "token": authority.mint(BETA, "bob@acme.example", scopes)},
    }


@app.post("/v1/documents", status_code=status.HTTP_201_CREATED)
def ingest(request: IngestRequest, principal: Principal = Depends(authenticated_principal)) -> dict:
    try:
        return engine.ingest(principal, request)
    except PermissionError as error:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(error)) from error


@app.post("/v1/query")
def query(request: QueryRequest, principal: Principal = Depends(authenticated_principal)) -> dict:
    try:
        return engine.query(principal, request)
    except TenantQuarantinedError as error:
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=str(error)) from error
    except PermissionError as error:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(error)) from error


@app.post("/v1/isolation/probe")
def isolation_probe(principal: Principal = Depends(authenticated_principal)) -> dict:
    try:
        return engine.isolation_probe(principal)
    except PermissionError as error:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(error)) from error


@app.post("/v1/attestations/run")
def run_attestation(principal: Principal = Depends(authenticated_principal)) -> dict:
    try:
        return engine.attest(principal)
    except TenantQuarantinedError as error:
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=str(error)) from error
    except PermissionError as error:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(error)) from error


@app.get("/v1/control-plane/status")
def control_plane_status(principal: Principal = Depends(authenticated_principal)) -> dict:
    return engine.control_plane.status_for(principal) if engine.control_plane else {}


@app.get("/v1/isolation/status")
def isolation_status(principal: Principal = Depends(authenticated_principal)) -> dict:
    return {
        "tenant_id": str(principal.tenant_id),
        "principal": principal.subject,
        "controls": [
            "signed tenant claim; no caller-supplied tenant selector",
            "transaction-local database tenant context",
            "FORCE ROW LEVEL SECURITY on vectors and audit rows",
            "per-tenant AES-256-GCM source encryption",
            "tamper-evident audit chain and signed retrieval receipt",
        ],
    }
