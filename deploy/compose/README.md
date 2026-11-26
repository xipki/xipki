# XiPKI development deployment

This Compose stack provides an out-of-box XiPKI deployment: MariaDB or PostgreSQL, configuration bootstrap, CA, Gateway, OCSP, and the browser Console. Managed MariaDB is the default; a DBA-prepared external MariaDB or PostgreSQL service is also supported. Release mode pulls prebuilt images from the `docker.io/xipki` Docker Hub namespace, generates local credentials and certificates, initializes persistent service state, and starts every runtime with one command.

## Prerequisites

- Docker with Compose v2
- OpenSSL and curl

JDK 25 and Maven 3.9+ are required only for local development builds.

## Start XiPKI

From the repository root, run:

```bash
./deploy/compose/container.sh up
```

The default needs no configuration. To review or change the database mode,
engine, host, ports, bind address, or Console authentication mode, run:

```bash
./deploy/compose/container.sh config
./deploy/compose/container.sh config show
./deploy/compose/container.sh config check
```

`config` writes non-secret settings to the ignored `deploy/compose/xipki.env`
file. It writes database passwords separately under
`deploy/compose/.state/secrets/`; passwords must never be placed in
`xipki.env`. The parser accepts only the documented `KEY=VALUE` settings and
does not execute the file as shell code. Effective priority is process
environment, `xipki.env`, the release package's `.env`, then built-in defaults.
Copy [`xipki.env.example`](xipki.env.example) when non-interactive preparation
is more convenient, but use `config` to enter external database passwords.

The first run pulls the selected database image, the Bootstrap image, and one shared XiPKI application image, then initializes XiPKI. Compose starts CA, Gateway, OCSP, and Console as four independent containers from `docker.io/xipki/xipki:<version>` and selects each runtime with `XIPKI_ROLE`. Generated passwords and client identities are stored under the ignored `deploy/compose/.state/` directory. Its `secrets` and `client` directories remain owner-only (`0700`). Files mounted as Compose secrets are read-only (`0444`) so the non-root container processes can read Linux bind mounts; host-only private keys, PKCS#12 files, and passwords remain `0600`. Application configuration, certificates, database files, and the CA management client credential are kept in Docker volumes.

The development endpoints bind to localhost by default:

| Service | Endpoint |
| --- | --- |
| Console HTTPS | `https://127.0.0.1:18081` |
| Gateway HTTP (host-local diagnostics only) | `http://127.0.0.1:18082` |
| Gateway HTTPS | `https://127.0.0.1:18445` |
| OCSP HTTP | `http://127.0.0.1:18080` |

These are protocol endpoints, so requesting `/` can return HTTP 404 even when the service is healthy. The HTTPS certificate is locally generated and is not trusted by the host.

Show the generated first-login password and browser client certificate location only when needed:

```bash
./deploy/compose/container.sh credentials
```

The default `both` mode permits the local account for first use and the generated `admin.p12` client certificate for normal sign-in. Set `XIPKI_CONSOLE_AUTH_MODE=password` or `XIPKI_CONSOLE_AUTH_MODE=certificate` in `xipki.env` to restrict the deployment to one mechanism.

Useful commands:

```bash
./deploy/compose/container.sh status
./deploy/compose/container.sh logs gateway
./deploy/compose/container.sh smoke --restart
./deploy/compose/container.sh down
./deploy/compose/container.sh purge
```

The current experimental images use `docker.io/xipki/{mariadb,postgres,bootstrap,xipki}:7.0.0-SNAPSHOT`. A deployment pulls only the selected database, Bootstrap, and `xipki` images. Release archives pin the Maven project version in their packaged `.env`; override `XIPKI_IMAGE_PREFIX` or `XIPKI_VERSION` only when deliberately testing another registry namespace or version. The Docker Hub repositories are public, so end users do not need `docker login`.

## Deploy roles on separate hosts

Distributed mode keeps the same `bootstrap` and `xipki` images but generates four private,
role-scoped archives. The first distributed release requires a DBA-prepared external MariaDB or
PostgreSQL service; it does not expose the managed database container over the network.

On a trusted control host, define the topology and generate the private deployment artifacts:

```bash
./deploy/compose/container.sh config
./deploy/compose/container.sh config show
./deploy/compose/container.sh config check
./deploy/compose/container.sh prepare
```

Choose `distributed`, assign a lowercase deployment name, and enter stable DNS names or IP
addresses for CA, Console, Gateway, and OCSP. The names are embedded in generated service URLs and
TLS identities, so they must be reachable from the role containers and must not be changed after
preparation. The control host records the database engine and initial endpoint but never asks for
or stores a database password. `config check` validates the deployment topology, and `prepare`
reuses the deployment's generated trust material on repeated runs.

The private output is written to `deploy/compose/dist/<deployment>/`:

```text
xipki-<deployment>-ca-<version>.tar.gz
xipki-<deployment>-console-<version>.tar.gz
xipki-<deployment>-gateway-<version>.tar.gz
xipki-<deployment>-ocsp-<version>.tar.gz
SHA256SUMS
```

The DBA then prepares the external database as described in
[`external-db/README.md`](external-db/README.md). Each role archive contains its own concise
`README.md`; a node administrator can configure and start that role without access to the source
checkout or control-host directory.
The Console node owns its first-login password and browser administrator P12; display their paths
and values only when needed with `./node.sh credentials` on that node.

After all four nodes are healthy and the administrator completes **Quick Start** in Console, run
the packaged acceptance command on the Gateway node:

```bash
./node.sh verify
```

The command uses a dedicated, limited REST client identity to enroll a disposable certificate,
observe OCSP `good`, permanently revoke it, and observe OCSP `revoked`. Its private working key is
deleted on exit. The functional OCSP check uses `-noverify`; production acceptance must separately
replace the bootstrap responder signer with a Business-CA-issued `id-kp-OCSPSigning` certificate
and verify its response chain.

Gateway does not depend on a separate reverse proxy: its own Tomcat listener terminates TLS on
port 8445. Preparation creates one deployment-internal trust root and two deliberately separate
Gateway identities. `gateway-server.p12` carries only `serverAuth` plus the configured Gateway
DNS/IP SAN; `ra-sdk-client.p12` carries only `clientAuth` and authorizes Gateway at CA `/ca/ra/`.
The CA HTTPS identity similarly carries `serverAuth`, while the Console CA-management identity
carries `clientAuth`. Preparation rejects a missing SAN, the wrong EKU, a dual-purpose Gateway
identity, or a leaf outside the deployment trust chain before it writes node bundles. Every caller
receives only the root certificate it needs. The internal root private key and its password remain
only in the protected control-host `.state/` and are never copied into a runtime role archive.

To replace either generated server identity before `prepare`, import a PKCS#12 file together with
the trust anchor that validates its chain:

```bash
./deploy/compose/container.sh certificates import ca-server \
  /secure/ca-server.p12 /secure/enterprise-root.pem
./deploy/compose/container.sh certificates import gateway-server \
  /secure/gateway-server.p12 /secure/enterprise-root.pem
./deploy/compose/container.sh certificates show
./deploy/compose/container.sh prepare
```

The command prompts for the PKCS#12 password without echoing it, verifies that the private key and
leaf match, requires an exclusive `serverAuth` purpose, checks the configured DNS/IP SAN and trust
chain, and preserves the last valid override when validation fails. An imported CA trust anchor is
propagated to Console, Gateway, and the Gateway verification client. Server identity import is a pre-deployment
operation; replacing a working node's certificate requires a newly prepared deployment or a future
coordinated rotation workflow.

CA-management and Gateway RA-SDK client identities are intentionally not accepted by this command.
They are application authorization credentials as well as TLS client keys, so changing one also
requires an atomic CA authorization update and cannot be implemented as a local file replacement.

Verify the checksums, transfer exactly one role archive to its target host through an approved
secure channel, extract it, and operate that node with the launcher inside the archive:

```bash
sha256sum -c SHA256SUMS
tar -xzf xipki-<deployment>-ca-<version>.tar.gz
cd xipki-<deployment>-ca-<version>
./node.sh setup
```

Start the external database first, then CA, then Console, Gateway, and OCSP. Every node creates a
private Docker volume from its immutable role seed and starts only its pinned role from the shared
`xipki:<version>` image. `setup` keeps the prepared node settings, asks only for the local database
password, verifies connectivity, authorization and schema, starts the role, waits for health, and
prints its endpoint. Run `node.sh config` before `setup` only when this node's database endpoint,
account, names, bind address, or ports differ from the prepared defaults. Run `node.sh doctor` at
any time for a complete PASS/WARN/FAIL readiness report with recovery actions.

Node commands are `setup`, `doctor`, `config`, `check`, `up`, `pull`, `status`, `logs`, `smoke`,
`restart`, `down`, `reset`, `purge`, and `version`. `down` preserves state. `reset` removes only the
generated runtime volume after the exact `RESET <deployment> <role>` confirmation; the retained
seed, settings, and Secrets allow `setup` to recreate the role. `purge` permanently removes the
node volume and local seed after the exact `DELETE <deployment> <role>` confirmation.

Every role archive uses node bundle format v2. `manifest.env` is the immutable artifact identity:
it pins the format, deployment, role, Compose project, registry, and image version. `node.env`
contains the non-secret node-local ports and endpoints, and `node.env.example` preserves the
generated defaults. The launcher parses both files as data through separate allowlists; it never
executes either file as shell code. The `.state/seed` directory is the immutable private input
used to materialize the role runtime; it is not a user configuration directory.
Use `node.sh config` instead of editing `manifest.env`; the command updates `node.env` and prompts
for exactly that role's database password. The password is written only to the owner-protected
`.state/secrets/` directory on the target node and never to `node.env`. For CA, Gateway, and OCSP,
the first role initialization materializes the local Secret into the private runtime volume;
Console reads its file-backed Secret directly. `config check` and the shorter `check` command
perform the same complete local static validation. `setup` and `doctor` additionally run a
role-scoped JDBC preflight using the role's least-privilege account. When a CA, Gateway, or OCSP
database endpoint/account/name changes, the launcher automatically recreates only that role's
generated configuration volume before startup. External databases, certificates in the bundle,
and every other node remain untouched; operators never need to find or delete a Docker volume.

That validation includes the minimum identity set owned by the pinned role. In particular, a
Gateway node must contain both `gateway-server.p12` and `ra-sdk-client.p12`, its CA trust anchor and
protocol-client trust store, and `gateway.json`. Missing or mixed role material is reported at the
file boundary instead of surfacing later as an opaque Tomcat TLS failure.

Generated or imported private-key passwords are stored as file-backed Secrets under
`.state/secrets/`. The immutable XML and JSON seeds contain only password markers. `role-init`
resolves those markers after copying the seed into the node's private Docker volume; passwords are
never stored in `node.env` or supplied through the container environment.

The Console role receives only the public `ra-sdk-client` certificate. Quick Start registers it as
the reserved `gateway-ra` certificate requestor through the official XiPKI management client and
binds exactly `enroll_cert`, `revoke_cert`, and `unsuspend_cert` for the two Quick Start TLS
profiles. An existing same-name requestor or a broader/different association is reported as a
conflict and is never overwritten. The Gateway private key remains only on the Gateway node.

The database engine is pinned for the deployment, but each role configures its own host, port,
account, and database names. CA has separate caconf, certificate, OCSP, and key-pool names; OCSP
has separate CA and OCSP data names; Gateway and Console each have one. This supports independent
database servers without changing the shared application image.

Protect every role archive as a Secret: CA, Console, Gateway, and OCSP archives contain private
keys, although they contain no database password. The Gateway archive additionally contains the
limited REST identity used by `node.sh verify`; it contains no Console, CA-management, deployment
CA, or recovery credential. Back up the external database and runtime node volumes using the
organization's normal encrypted backup process.

The first milestone does not include a remotely exposed managed-database node, HA, automated
failover, database TLS configuration, or password rotation. The Gateway node launcher automates
the cross-host issuance, permanent revocation, and OCSP status flow, but production
acceptance must still exercise CRL publication, trusted OCSP response signing, backup recovery,
and independent node restart on the target network.

## Local development build

Developers can build the Maven distribution, the shared application image, Bootstrap, and both database images from the current checkout:

```bash
./deploy/compose/container.sh dev-up
```

This combines `compose.yaml` with `compose.build.yaml` and derives local image and artifact versions from the root Maven POM (currently `xipki/{mariadb,bootstrap,xipki}:7.0.0-SNAPSHOT-dev`). It does not pull or overwrite the release tags. Use `dev-build` to build without starting the stack.

`down` preserves data and credentials. `purge` permanently removes the selected Compose project's containers, networks, data volumes, generated credentials, TLS identities, and client certificates. It requires the exact confirmation `DELETE <project-name>`; the default is `DELETE xipki`. After a purge, the next `up` performs a clean first deployment.

## Select a managed database

MariaDB 11.4 LTS is used when no database is specified. To persist PostgreSQL
as the managed database, run `config` and select `managed` and `postgres`.
Automation may instead set the same process environment for every operation:

```bash
XIPKI_DATABASE=postgres ./deploy/compose/container.sh up
XIPKI_DATABASE=postgres ./deploy/compose/container.sh status
XIPKI_DATABASE=postgres ./deploy/compose/container.sh down
```

Database engines use separate Docker volumes, and XiPKI records the engine in its generated configuration. Changing `XIPKI_DATABASE` does not migrate an existing installation. Use a different `XIPKI_COMPOSE_PROJECT` for a parallel installation, or export and migrate the data explicitly before switching.

## Use an external database

External mode deliberately separates DBA and XiPKI operator responsibilities.
The DBA creates the databases, service accounts, grants, and core XiPKI schemas
described in [`external-db/README.md`](external-db/README.md). XiPKI
does not receive or retain an administrator credential. The Console database
starts empty and the `xipki_console` account creates its own versioned schema.

After the DBA supplies the host, port, and four application passwords through
an approved channel, the operator runs:

```bash
./deploy/compose/container.sh config
./deploy/compose/container.sh config show
./deploy/compose/container.sh config check
./deploy/compose/container.sh up
```

Choose `external`, then `mariadb` or `postgres` in the wizard. `config check`
starts only a short-lived Bootstrap container and verifies connectivity,
least-privilege access, all required `DBSCHEMA` markers, and the empty or known
Console schema. It does not initialize or modify the external database. In
external mode Compose starts only Bootstrap, CA, Console, Gateway, and OCSP;
there is no `database` service or database data volume.

Standalone external-database mode uses fixed database and account names and accepts a DNS name or
IPv4 address. Distributed nodes may override their database host, port, account, and database
names before first setup. Neither mode provides database migration, credential rotation, IPv6 host
syntax, custom JDBC parameters, or JDBC TLS configuration. Use a trusted private network. Existing initialized state is
bound to its database engine, mode, host, and port; deploy a separate Compose
project for a different target instead of editing an active installation.
Running `config` again keeps already stored external database passwords. If a
password was mistyped during a disposable first-time setup, purge that unused
project state and configure it again; do not use this as a rotation procedure
for an initialized installation.

Ports and the public listening address can be overridden with `XIPKI_CONSOLE_HTTPS_PORT`,
`XIPKI_GATEWAY_HTTP_PORT`, `XIPKI_GATEWAY_HTTPS_PORT`, `XIPKI_OCSP_HTTP_PORT`, and
`XIPKI_BIND_ADDRESS`. `XIPKI_BIND_ADDRESS` applies to public endpoints, including Gateway HTTPS;
Gateway HTTP always binds to `127.0.0.1` because it is retained only for host-local diagnostics.

Image maintainers should use the separate manual workflow documented in [`../release/README.md`](../release/README.md). Building and testing never push images; `images.sh push` is the only publishing command.

On an empty deployment, the Console dashboard offers **Quick Start** to the super administrator. After the operator reviews and confirms the CA name, organization, and optional country, it creates a software-backed RSA-3072 self-signed Business CA, a 10-year root profile, and TLS server/client profiles limited to 397 days. The workflow uses the official XiPKI management client, activates the CA, and can safely resume after interruption. It never overwrites or deletes an existing resource; a conflicting reserved name is reported for manual resolution. Existing deployments keep the ordinary explicit CA creation/import workflow and do not show Quick Start.
