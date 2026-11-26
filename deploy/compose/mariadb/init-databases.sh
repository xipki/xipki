#!/usr/bin/env bash

set -Eeuo pipefail

read_secret() {
  local name="$1"
  tr -d '\r\n' < "/run/secrets/${name}"
}

sql_escape() {
  # Escape backslashes before quotes so operator-supplied secrets cannot change
  # the generated SQL literal. Launcher-generated passwords are hexadecimal.
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e "s/'/''/g"
}

ca_password="$(sql_escape "$(read_secret ca_db_password)")"
gateway_password="$(sql_escape "$(read_secret gateway_db_password)")"
ocsp_password="$(sql_escape "$(read_secret ocsp_db_password)")"
console_password="$(sql_escape "$(read_secret console_db_password)")"

initialize_schema() {
  local database="$1"
  local script="$2"

  # The portable XiPKI scripts begin with best-effort foreign-key cleanup for
  # upgrades. This entrypoint only runs against a new data directory, so start
  # at the first idempotent DROP TABLE and keep strict error handling afterward.
  sed -n '/^DROP TABLE IF EXISTS/,$p' "${script}" \
    | mariadb --protocol=socket -uroot -p"${MARIADB_ROOT_PASSWORD}" "${database}"
}

mariadb --protocol=socket -uroot -p"${MARIADB_ROOT_PASSWORD}" <<SQL
CREATE USER IF NOT EXISTS 'xipki_ca'@'%' IDENTIFIED BY '${ca_password}';
ALTER USER 'xipki_ca'@'%' IDENTIFIED BY '${ca_password}';
CREATE USER IF NOT EXISTS 'xipki_gateway'@'%' IDENTIFIED BY '${gateway_password}';
ALTER USER 'xipki_gateway'@'%' IDENTIFIED BY '${gateway_password}';
CREATE USER IF NOT EXISTS 'xipki_ocsp'@'%' IDENTIFIED BY '${ocsp_password}';
ALTER USER 'xipki_ocsp'@'%' IDENTIFIED BY '${ocsp_password}';
CREATE USER IF NOT EXISTS 'xipki_console'@'%' IDENTIFIED BY '${console_password}';
ALTER USER 'xipki_console'@'%' IDENTIFIED BY '${console_password}';

CREATE DATABASE IF NOT EXISTS caconf CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE DATABASE IF NOT EXISTS ca CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE DATABASE IF NOT EXISTS ocsp CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE DATABASE IF NOT EXISTS keypool CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE DATABASE IF NOT EXISTS acme CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE DATABASE IF NOT EXISTS xipki_console CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;

GRANT ALL PRIVILEGES ON caconf.* TO 'xipki_ca'@'%';
GRANT ALL PRIVILEGES ON ca.* TO 'xipki_ca'@'%';
GRANT ALL PRIVILEGES ON ocsp.* TO 'xipki_ca'@'%';
GRANT ALL PRIVILEGES ON keypool.* TO 'xipki_ca'@'%';
GRANT ALL PRIVILEGES ON acme.* TO 'xipki_gateway'@'%';
GRANT SELECT ON ca.* TO 'xipki_ocsp'@'%';
GRANT SELECT ON ocsp.* TO 'xipki_ocsp'@'%';
GRANT ALL PRIVILEGES ON xipki_console.* TO 'xipki_console'@'%';
FLUSH PRIVILEGES;
SQL

for database in caconf ca ocsp keypool; do
  initialize_schema "${database}" "/opt/xipki/sql/${database}-init.mysql.sql"
done

initialize_schema acme /opt/xipki/sql/acme-init.mysql.sql
