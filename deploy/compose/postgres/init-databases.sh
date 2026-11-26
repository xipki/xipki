#!/usr/bin/env bash

set -Eeuo pipefail

read_secret() {
  local name="$1"
  tr -d '\r\n' < "/run/secrets/${name}"
}

ca_password="$(read_secret ca_db_password)"
gateway_password="$(read_secret gateway_db_password)"
ocsp_password="$(read_secret ocsp_db_password)"
console_password="$(read_secret console_db_password)"

psql --set ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname postgres \
  --set ca_password="${ca_password}" \
  --set gateway_password="${gateway_password}" \
  --set ocsp_password="${ocsp_password}" \
  --set console_password="${console_password}" <<'SQL'
SELECT 'CREATE ROLE xipki_ca LOGIN' WHERE NOT EXISTS
  (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'xipki_ca')\gexec
ALTER ROLE xipki_ca PASSWORD :'ca_password';

SELECT 'CREATE ROLE xipki_gateway LOGIN' WHERE NOT EXISTS
  (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'xipki_gateway')\gexec
ALTER ROLE xipki_gateway PASSWORD :'gateway_password';

SELECT 'CREATE ROLE xipki_ocsp LOGIN' WHERE NOT EXISTS
  (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'xipki_ocsp')\gexec
ALTER ROLE xipki_ocsp PASSWORD :'ocsp_password';

SELECT 'CREATE ROLE xipki_console LOGIN' WHERE NOT EXISTS
  (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'xipki_console')\gexec
ALTER ROLE xipki_console PASSWORD :'console_password';

SELECT format('CREATE DATABASE %I OWNER xipki_ca', name)
FROM (VALUES ('caconf'), ('ca'), ('ocsp'), ('keypool')) AS databases(name)
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = name)\gexec

SELECT 'CREATE DATABASE acme OWNER xipki_gateway'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'acme')\gexec
SELECT 'CREATE DATABASE xipki_console OWNER xipki_console'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'xipki_console')\gexec
SQL

# Creating tables as the service roles makes ownership enforce the same data
# boundary after initialization; the bootstrap superuser is not used at runtime.
for database in caconf ca ocsp keypool; do
  psql --set ON_ERROR_STOP=1 --username xipki_ca --dbname "${database}" \
    --file "/opt/xipki/sql/${database}-init.postgresql.sql"
done

psql --set ON_ERROR_STOP=1 --username xipki_gateway --dbname acme \
  --file /opt/xipki/sql/acme-init.postgresql.sql

psql --set ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname postgres <<'SQL'
GRANT CONNECT ON DATABASE ca, ocsp TO xipki_ocsp;
SQL

for database in ca ocsp; do
  psql --set ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${database}" <<'SQL'
GRANT USAGE ON SCHEMA public TO xipki_ocsp;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO xipki_ocsp;
ALTER DEFAULT PRIVILEGES FOR ROLE xipki_ca IN SCHEMA public
  GRANT SELECT ON TABLES TO xipki_ocsp;
SQL
done
