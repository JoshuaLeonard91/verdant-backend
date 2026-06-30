#!/bin/sh
set -eu

if [ -z "${POSTGRES_APP_PASSWORD:-}" ]; then
  echo "POSTGRES_APP_PASSWORD is required to create the runtime app login role" >&2
  exit 1
fi

POSTGRES_APP_ROLE="${POSTGRES_APP_ROLE:-app_runtime}"
POSTGRES_APP_LOGIN="${POSTGRES_APP_LOGIN:-app_runtime_login}"
# Existing migrations grant RLS/table privileges to this base role. Keep it
# internal so public examples can use generic operator-facing role names without
# breaking fresh deployments.
POSTGRES_RLS_BASE_ROLE="${POSTGRES_RLS_BASE_ROLE:-verdant_app}"

case "$POSTGRES_APP_ROLE" in
  *[!A-Za-z0-9_]* | [0-9]* | "")
    echo "POSTGRES_APP_ROLE must be a PostgreSQL identifier using letters, digits, and underscores, and must not start with a digit" >&2
    exit 1
    ;;
esac

case "$POSTGRES_APP_LOGIN" in
  *[!A-Za-z0-9_]* | [0-9]* | "")
    echo "POSTGRES_APP_LOGIN must be a PostgreSQL identifier using letters, digits, and underscores, and must not start with a digit" >&2
    exit 1
    ;;
esac

case "$POSTGRES_RLS_BASE_ROLE" in
  *[!A-Za-z0-9_]* | [0-9]* | "")
    echo "POSTGRES_RLS_BASE_ROLE must be a PostgreSQL identifier using letters, digits, and underscores, and must not start with a digit" >&2
    exit 1
    ;;
esac

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${POSTGRES_RLS_BASE_ROLE}') THEN
    CREATE ROLE "${POSTGRES_RLS_BASE_ROLE}" NOLOGIN;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${POSTGRES_APP_ROLE}') THEN
    CREATE ROLE "${POSTGRES_APP_ROLE}" NOLOGIN;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${POSTGRES_APP_LOGIN}') THEN
    CREATE ROLE "${POSTGRES_APP_LOGIN}" LOGIN;
  END IF;

  IF '${POSTGRES_APP_ROLE}' <> '${POSTGRES_RLS_BASE_ROLE}' THEN
    GRANT "${POSTGRES_RLS_BASE_ROLE}" TO "${POSTGRES_APP_ROLE}";
  END IF;

  GRANT "${POSTGRES_APP_ROLE}" TO "${POSTGRES_APP_LOGIN}";
END
\$\$;
SQL

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  -v app_password="$POSTGRES_APP_PASSWORD" <<SQL
ALTER ROLE "${POSTGRES_APP_LOGIN}" WITH PASSWORD :'app_password';
SQL
