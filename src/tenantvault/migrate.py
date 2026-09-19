"""Apply the database migration from a Cloud Run Job, never from the API service."""
from __future__ import annotations

import os
from pathlib import Path


def main() -> None:
    try:
        import psycopg
    except ImportError as error:  # pragma: no cover
        raise RuntimeError("psycopg is required for migrations") from error

    database_url = os.environ["DATABASE_URL"]
    api_password = os.environ["API_DATABASE_PASSWORD"]
    migration_path = Path(os.getenv("MIGRATION_PATH", "/app/migrations/001_zero_trust.sql"))
    migration = migration_path.read_text()
    with psycopg.connect(database_url) as connection:
        # The value never appears in the SQL migration or logs. It is consumed
        # by the migration's local setting to create/rotate only the API role.
        connection.execute("SELECT set_config('app.api_password', %s, false)", (api_password,))
        connection.execute(migration)
    print(f"Applied {migration_path.name} successfully.")


if __name__ == "__main__":
    main()
