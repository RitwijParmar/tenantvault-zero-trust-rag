from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    store_mode: str = os.getenv("STORE_MODE", "memory")
    database_url: str | None = os.getenv("DATABASE_URL")
    token_secret: str = os.getenv("TOKEN_SIGNING_SECRET", "dev-token-secret-not-for-production-00001")
    tenant_key_root: str = os.getenv("TENANT_KEY_ROOT", "dev-tenant-key-root-not-for-production-0002")
    receipt_secret: str = os.getenv("RECEIPT_SIGNING_SECRET", "dev-receipt-secret-not-for-production-0003")
    demo_mode: bool = os.getenv("DEMO_MODE", "true").lower() == "true"
    app_root: str = os.getenv("APP_ROOT", os.getcwd())


settings = Settings()
