# External database preparation

XiPKI external database mode connects with four fixed, least-privilege service
accounts. It never asks for or stores a database administrator credential. A
DBA must create the accounts, databases, grants, and XiPKI schemas before XiPKI
nodes are started.

This first external-database contract supports MariaDB and PostgreSQL. Standalone
mode uses the default names below. Distributed role nodes may replace account and
database names through `node.sh config`; all roles in one prepared deployment use
the same database engine. Migration from the managed database, password rotation,
and JDBC TLS settings are not implemented yet. Use a private trusted network for
this release and do not repoint an initialized node by editing `node.env`.

## Required identities and databases

| Account | Databases | Required access |
| --- | --- | --- |
| `xipki_ca` | `caconf`, `ca`, `ocsp`, `keypool` | Own/read/write schema and data |
| `xipki_gateway` | `acme` | Own/read/write schema and data |
| `xipki_ocsp` | `ca`, `ocsp` | Connect and read all current and future tables |
| `xipki_console` | `xipki_console` | Create/alter tables and read/write data |

Use separate passwords for all four accounts. For standalone mode, give all four
passwords to the XiPKI operator. For distributed mode, give each password only
to the administrator of the role that consumes it. Use the organization's
approved secret channel; do not add passwords to SQL files, `xipki.env`,
`node.env`, command history, tickets, or release archives.

## Schema scripts

The release bundle contains the matching XiPKI schema files under:

- `database/mariadb/`
- `database/postgres/`

In a source checkout, the same files are under
`assemblies/xipki-setup/src/assembly/unfiltered/xipki-mgmt-cli/xipki/sql/`.
Initialize the databases as follows:

| Database | MariaDB script | PostgreSQL script |
| --- | --- | --- |
| `caconf` | `caconf-init.mysql.sql` | `caconf-init.postgresql.sql` |
| `ca` | `ca-init.mysql.sql` | `ca-init.postgresql.sql` |
| `ocsp` | `ocsp-init.mysql.sql` | `ocsp-init.postgresql.sql` |
| `keypool` | `keypool-init.mysql.sql` | `keypool-init.postgresql.sql` |
| `acme` | `acme-init.mysql.sql` | `acme-init.postgresql.sql` |

The MariaDB scripts begin with best-effort foreign-key cleanup statements that
can fail on a new database. For a fresh database, execute each file starting at
its first `DROP TABLE IF EXISTS` statement. PostgreSQL scripts can be executed
with `ON_ERROR_STOP` enabled. These scripts drop and recreate XiPKI tables, so
they must never be run against a database containing data that must be kept.

Leave `xipki_console` empty. On its first successful connection, Console creates
and versions its schema atomically. The `xipki_console` account therefore needs
DDL permission as well as normal DML permission.

The deployment bundle intentionally excludes XiPKI's optional database-audit and
OCSP response-cache schemas. This container release configures file-backed CA
audit and direct OCSP status reads, so those schemas are neither initialized nor
supported by the deployment launcher.

For PostgreSQL, ensure `xipki_ocsp` has `CONNECT` on `ca` and `ocsp`, `USAGE` on
their `public` schemas, `SELECT` on existing tables, and default `SELECT`
privileges for tables subsequently created by `xipki_ca`. For MariaDB, grant
`SELECT` on `ca.*` and `ocsp.*` to `xipki_ocsp`.

## MariaDB example

The following example uses the default standalone names. For a distributed installation with
custom names, replace each account and database name with the values agreed with the matching node
administrator. Run the administrative client with history disabled, then replace the four marked
password values inside the session:

~~~bash
MYSQL_HISTFILE=/dev/null mariadb --host DB_HOST --user root --password
~~~

~~~sql
CREATE USER 'xipki_ca'@'%' IDENTIFIED BY '<CA_PASSWORD>';
CREATE USER 'xipki_gateway'@'%' IDENTIFIED BY '<GATEWAY_PASSWORD>';
CREATE USER 'xipki_ocsp'@'%' IDENTIFIED BY '<OCSP_PASSWORD>';
CREATE USER 'xipki_console'@'%' IDENTIFIED BY '<CONSOLE_PASSWORD>';

CREATE DATABASE caconf CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE DATABASE ca CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE DATABASE ocsp CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE DATABASE keypool CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE DATABASE acme CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE DATABASE xipki_console CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;

GRANT ALL PRIVILEGES ON caconf.* TO 'xipki_ca'@'%';
GRANT ALL PRIVILEGES ON ca.* TO 'xipki_ca'@'%';
GRANT ALL PRIVILEGES ON ocsp.* TO 'xipki_ca'@'%';
GRANT ALL PRIVILEGES ON keypool.* TO 'xipki_ca'@'%';
GRANT ALL PRIVILEGES ON acme.* TO 'xipki_gateway'@'%';
GRANT SELECT ON ca.* TO 'xipki_ocsp'@'%';
GRANT SELECT ON ocsp.* TO 'xipki_ocsp'@'%';
GRANT ALL PRIVILEGES ON xipki_console.* TO 'xipki_console'@'%';
FLUSH PRIVILEGES;
~~~

From the unpacked XiPKI release directory, initialize only the five XiPKI data schemas. Each client
prompts for the matching service-account password; do not add it to the command line:

~~~bash
export DB_HOST=db.internal.example.com
for database in caconf ca ocsp keypool; do
  sed -n '/^DROP TABLE IF EXISTS/,$p' "database/mariadb/$database-init.mysql.sql" \
    | mariadb --host "$DB_HOST" --user xipki_ca --password "$database"
done
sed -n '/^DROP TABLE IF EXISTS/,$p' database/mariadb/acme-init.mysql.sql \
  | mariadb --host "$DB_HOST" --user xipki_gateway --password acme
unset DB_HOST
~~~

Do not initialize xipki_console; Console creates that schema itself.

## PostgreSQL example

Connect as a database administrator. PostgreSQL's \password command prompts without placing the
password in SQL or command history:

~~~bash
psql --host DB_HOST --username postgres --dbname postgres
~~~

~~~sql
CREATE ROLE xipki_ca LOGIN;
\password xipki_ca
CREATE ROLE xipki_gateway LOGIN;
\password xipki_gateway
CREATE ROLE xipki_ocsp LOGIN;
\password xipki_ocsp
CREATE ROLE xipki_console LOGIN;
\password xipki_console

CREATE DATABASE caconf OWNER xipki_ca;
CREATE DATABASE ca OWNER xipki_ca;
CREATE DATABASE ocsp OWNER xipki_ca;
CREATE DATABASE keypool OWNER xipki_ca;
CREATE DATABASE acme OWNER xipki_gateway;
CREATE DATABASE xipki_console OWNER xipki_console;
~~~

Initialize the data schemas as their owners. The commands prompt for the corresponding service
passwords:

~~~bash
export DB_HOST=db.internal.example.com
for database in caconf ca ocsp keypool; do
  psql --host "$DB_HOST" --username xipki_ca --dbname "$database" \
    --set ON_ERROR_STOP=1 --file "database/postgres/$database-init.postgresql.sql"
done
psql --host "$DB_HOST" --username xipki_gateway --dbname acme \
  --set ON_ERROR_STOP=1 --file database/postgres/acme-init.postgresql.sql
~~~

Finally, reconnect as the administrator to grant the read-only OCSP role access to current and
future CA/OCSP tables:

~~~bash
psql --host "$DB_HOST" --username postgres --dbname postgres \
  --command 'GRANT CONNECT ON DATABASE ca, ocsp TO xipki_ocsp;'
for database in ca ocsp; do
  psql --host "$DB_HOST" --username postgres --dbname "$database" <<'SQL'
GRANT USAGE ON SCHEMA public TO xipki_ocsp;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO xipki_ocsp;
ALTER DEFAULT PRIVILEGES FOR ROLE xipki_ca IN SCHEMA public
  GRANT SELECT ON TABLES TO xipki_ocsp;
SQL
done
unset DB_HOST
~~~

Do not initialize xipki_console; Console creates that schema itself.

## Handoff verification

For standalone external-database mode, the XiPKI operator runs:

```bash
./container.sh config
./container.sh config show
./container.sh config check
```

The final command opens a short-lived Bootstrap container and verifies every
role-scoped connection. It requires the core databases to contain the XiPKI
`DBSCHEMA` marker and accepts only an empty or recognized Console database. It
does not modify the database and does not use an administrator account.

For distributed mode, the control host runs `container.sh config check` without
database credentials and then generates the role archives. On each target host,
the role administrator runs:

```bash
./node.sh setup
```

`node.sh setup` stores only that role's database password under the local
owner-protected `.state/secrets/` directory, runs a live least-privilege JDBC
preflight, starts the role, and waits for health. The control host and role
archive never receive the password. If this node differs from the prepared
defaults, run `node.sh config` first; it accepts the role's database host, port,
account, and data-domain database names. `node.sh doctor` repeats the readiness
checks without changing the database.
