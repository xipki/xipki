# XiPKI container deployment

This package starts XiPKI with managed MariaDB 11.4 LTS by default, plus Bootstrap, CA, Gateway, OCSP, and the browser Console, from prebuilt images published under the `docker.io/xipki` Docker Hub namespace. CA, Gateway, OCSP, and Console remain separate containers but share the single `xipki` application image. Managed or DBA-prepared external PostgreSQL and MariaDB are also supported. The packaged `.env` selects the exact release version. The public Docker Hub repositories permit anonymous pull; Maven, a JDK, and the XiPKI source tree are not required.

## Prerequisites

- Docker with Compose v2
- OpenSSL
- curl

## Start

```bash
./container.sh up
```

The launcher creates random database credentials under the local, owner-only `.state/` directory, pulls all images, starts the stack, and waits for the smoke test to pass. The protected directories use mode `0700`; files mounted as Compose secrets use mode `0444` so the non-root services can read native Linux bind mounts without making the files reachable to other host users.

The packaged `.env` pins the Docker Hub namespace and release version. Process environment variables can override either setting when an operator deliberately needs another registry or version.

The default managed MariaDB deployment needs no configuration. To persist a
different supported setup, use the guided configuration before `up`:

```bash
./container.sh config
./container.sh config show
./container.sh config check
```

Non-secret values are stored in `xipki.env`; the file is parsed as a strict
documented `KEY=VALUE` interface and is never executed as shell code. Database
passwords are stored only as files under `.state/secrets/`. Do not put a
password in `xipki.env`. `xipki.env.example` lists every setting supported by
this release. Effective priority is process environment, `xipki.env`, the
packaged `.env`, then built-in defaults.

To select a managed PostgreSQL database, run `config` and choose `managed` and
`postgres`. Automation may instead use the same setting for every command:

```bash
XIPKI_DATABASE=postgres ./container.sh up
```

The two engines use independent Docker volumes. Changing this setting does not migrate an existing database; use a separate `XIPKI_COMPOSE_PROJECT` for a parallel installation or perform an explicit data migration.

## Complete the standalone first run

The standalone defaults are:

- Console HTTPS: `https://127.0.0.1:18081`
- Gateway HTTP: `http://127.0.0.1:18082`
- Gateway HTTPS: `https://127.0.0.1:18445`
- OCSP HTTP: `http://127.0.0.1:18080`

Protocol roots can return HTTP 404 even when healthy. The initial HTTPS certificate is generated
locally and is not trusted by the host. Retrieve the first-login password and browser client
identity location explicitly:

```bash
./container.sh credentials
```

Sign in to Console as `admin` and select **Quick Start** on the dashboard. After review and
confirmation, XiPKI creates and activates a software-backed RSA-3072 self-signed Business CA, a
10-year root profile, and TLS server/client profiles limited to 397 days. It also registers the
deployment-generated Gateway RA certificate and grants only enrollment, revocation, and
unsuspension for those two TLS profiles. Interrupted initialization can be resumed. Existing
resources are never overwritten or deleted; a conflicting reserved Gateway requestor stops the
workflow instead of being replaced.

Verify health and restart persistence after Quick Start:

```bash
./container.sh smoke --restart
./container.sh status
```

The default login mode supports both the local account and the browser client certificate. Set
`XIPKI_CONSOLE_AUTH_MODE=password` or `XIPKI_CONSOLE_AUTH_MODE=certificate` in `xipki.env` to select
only one mechanism.

## Distributed deployment

Use standalone `./container.sh up` for the one-host evaluation experience. For a formal installation
where CA, Console, Gateway, and OCSP run on separate Docker hosts, use distributed mode. It uses
the same release images and requires an external database prepared by the DBA according to
`database/README.md`.

On a trusted control host, run:

```bash
./container.sh config
./container.sh config show
./container.sh config check
./container.sh prepare
```

In `config`, select `distributed`, choose a lowercase deployment name, and supply a stable DNS name
or IP address for each of the four role hosts. These addresses are embedded in TLS identities and
service URLs and must resolve from inside the containers. Select `external`, choose the database
engine, and enter the DBA-provided initial host and port. Database passwords are entered only on
their matching target nodes during `node.sh setup`; they never enter the control-host state or
generated archive.

`prepare` writes four private node archives and their `SHA256SUMS` file under
`dist/<deployment>/`. Verify checksums and send each archive only to its matching node. For
example, on the CA host:

```bash
tar -xzf xipki-<deployment>-ca-<version>.tar.gz
cd xipki-<deployment>-ca-<version>
./node.sh setup
```

Repeat with the Console, Gateway, and OCSP archives on their respective hosts. Start the database
first and CA second; the remaining application roles may then start. The generated launcher pins
the deployment, role, image version, endpoints, and Compose project and starts only that role.
`setup` asks only for the node-local database password, verifies the DBA handoff, starts the role,
waits for health, and prints the endpoint. Run `node.sh config` before `setup` only when this node
must override a prepared non-secret value. Use `node.sh doctor` for an actionable PASS/WARN/FAIL
report covering settings, Secrets, Docker, images, database access/schema, and runtime health. Each
node archive contains a role-local `README.md`; its administrator does not need access to the
control-host release package.
On the Console node, use `./node.sh credentials` to retrieve the generated first-login password
and browser client P12 only when needed.
Useful node commands are:

```bash
./node.sh doctor
./node.sh status
./node.sh logs
./node.sh smoke
./node.sh restart
./node.sh down
./node.sh reset
./node.sh purge
```

`down` keeps all state. `reset` removes the generated runtime volume but retains the package,
node settings, identity seed, and Secrets; run `setup` afterwards to recreate that role. `purge`
removes all local role material and requires extracting the original node archive before the node
can be installed again.

Open the configured ports only to their intended callers: every role needs database access;
Console and Gateway need the CA HTTPS port; administrators need Console HTTPS; protocol clients
need Gateway and OCSP. Do not place the four role hosts on one shared Compose network.

Every node archive contains private key material and must be transferred and stored as a Secret.
The Gateway archive additionally contains one dedicated REST identity limited to certificate
verification. After completing Quick Start in Console, validate the installation on the Gateway
node:

```bash
./node.sh verify
```

The command enrolls one test certificate through Gateway, verifies OCSP `good`, permanently
revokes it through Gateway, and verifies OCSP `revoked`. Its temporary private key is deleted on
exit. This is a functional OCSP check using `-noverify`; production acceptance must separately
replace the bootstrap responder signer with a Business-CA-issued OCSP-signing certificate and
verify its chain.

This release does not provide a distributed managed-database node, HA, automated failover,
database TLS settings, or password rotation. A node administrator may use `node.sh config` before
first startup to override that role's database host, port, account, and database names. Before
production cutover, verify Quick Start, issuance, revocation, CRL, OCSP, and independent node
restart over the real network.

## External database

Ask the DBA to follow `database/README.md` in this release package. It describes
the fixed database/account contract and includes the matching MariaDB and
PostgreSQL XiPKI schema scripts. The DBA prepares the databases and gives the
operator only the host, port, and four service-account passwords; XiPKI never
needs a database administrator password.

Run `./container.sh config`, select `external` and the database engine, then enter
the connection target and the four passwords when prompted. The passwords are
not echoed. Verify the handoff before starting XiPKI:

```bash
./container.sh config show
./container.sh config check
./container.sh up
```

`config check` uses a short-lived Bootstrap container to test every service
identity and schema without changing the database. External mode does not
start the packaged database image. In standalone external-database mode, the first release
supports fixed database and account names, a DNS name or IPv4 address, and a single host/port for
all databases. Distributed node packages may override the database account and database names
before their first setup. Migration, password rotation, custom JDBC parameters, IPv6 host syntax,
and JDBC TLS configuration are not included; use a trusted private network and a new Compose
project rather than repointing an initialized one.
Re-running `config` retains existing external database passwords. For a typo in
an unused first-time setup, purge that disposable project state and configure
again; this release does not support in-place password rotation.

## Operate

```bash
./container.sh status
./container.sh logs gateway
./container.sh smoke --restart
./container.sh upgrade
./container.sh down
./container.sh purge
```

`down` preserves database files, configuration, credentials, and keys. To intentionally erase the complete installation, run `purge` and enter the exact project-specific confirmation when prompted:

```bash
./container.sh purge
# Type DELETE xipki to continue
```

`purge` removes containers, networks, data volumes, generated passwords, TLS identities, and client certificates. The next `up` starts a clean First-run Initialization. If `XIPKI_COMPOSE_PROJECT` is set, use that project name in the confirmation.
