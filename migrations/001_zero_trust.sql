-- TenantVault's trust boundary lives in the database, not in application filters.
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS rag;
CREATE SCHEMA IF NOT EXISTS audit;

-- This role is deliberately not the database owner and cannot bypass RLS.
DO $$
DECLARE
  app_api_password text := coalesce(current_setting('app.api_password', true), 'local-dev-only');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenantvault_api') THEN
    EXECUTE format('CREATE ROLE tenantvault_api LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', app_api_password);
  ELSE
    EXECUTE format('ALTER ROLE tenantvault_api PASSWORD %L', app_api_password);
  END IF;
END
$$;

CREATE OR REPLACE FUNCTION app.require_tenant()
RETURNS uuid
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
  requested_tenant text;
BEGIN
  requested_tenant := current_setting('app.tenant_id', true);
  IF requested_tenant IS NULL OR requested_tenant = '' THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  RETURN requested_tenant::uuid;
END;
$$;

CREATE TABLE IF NOT EXISTS app.tenants (
  tenant_id uuid PRIMARY KEY,
  display_name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rag.documents (
  document_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL DEFAULT app.require_tenant() REFERENCES app.tenants(tenant_id),
  title text NOT NULL,
  source_uri text NOT NULL,
  content_ciphertext bytea NOT NULL,
  content_nonce bytea NOT NULL,
  content_sha256 text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  embedding vector(96) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, content_sha256)
);
CREATE INDEX IF NOT EXISTS documents_embedding_hnsw ON rag.documents USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS documents_tenant_created ON rag.documents (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit.events (
  event_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL DEFAULT app.require_tenant() REFERENCES app.tenants(tenant_id),
  actor_id text NOT NULL,
  action text NOT NULL,
  request_id uuid NOT NULL,
  result_count integer NOT NULL DEFAULT 0,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  previous_hash text,
  event_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS events_tenant_created ON audit.events (tenant_id, created_at DESC);

-- FORCE protects these tables even if a migration accidentally runs as their owner.
ALTER TABLE rag.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE rag.documents FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS document_tenant_fence ON rag.documents;
CREATE POLICY document_tenant_fence ON rag.documents
  USING (tenant_id = app.require_tenant())
  WITH CHECK (tenant_id = app.require_tenant());

DROP POLICY IF EXISTS audit_tenant_fence ON audit.events;
CREATE POLICY audit_tenant_fence ON audit.events
  USING (tenant_id = app.require_tenant())
  WITH CHECK (tenant_id = app.require_tenant());

REVOKE ALL ON SCHEMA app, rag, audit FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA app, rag, audit FROM PUBLIC;
REVOKE ALL ON FUNCTION app.require_tenant() FROM PUBLIC;
GRANT USAGE ON SCHEMA app, rag, audit TO tenantvault_api;
GRANT SELECT, INSERT ON rag.documents TO tenantvault_api;
GRANT SELECT, INSERT ON audit.events TO tenantvault_api;
GRANT SELECT ON app.tenants TO tenantvault_api;
GRANT EXECUTE ON FUNCTION app.require_tenant() TO tenantvault_api;

-- Fixtures are only for a local demo. Production onboarding uses a privileged control plane.
INSERT INTO app.tenants (tenant_id, display_name) VALUES
  ('11111111-1111-1111-1111-111111111111', 'Northstar Health'),
  ('22222222-2222-2222-2222-222222222222', 'Acme Robotics')
ON CONFLICT (tenant_id) DO NOTHING;
