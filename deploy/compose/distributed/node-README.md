# XiPKI distributed node

This private package installs exactly one XiPKI role. Keep the complete directory owner-only: it
contains the role's internal identity and trust material. Do not copy files from another role
package into this directory.

## 1. Identify this node

```bash
./node.sh version
./node.sh config show
```

Confirm that the deployment name, role, image version, database target, bind address, and service
ports match this host. If the database address, account, database names, bind address, or ports
differ from the prepared defaults, change them before setup:

```bash
./node.sh config
./node.sh config check
```

The database password is requested without echo and stored only under the local
`.state/secrets/` directory. Never put it in `node.env`, a command line, a ticket, or this archive.

## 2. Diagnose and start

The DBA must create the role's databases, least-privilege account, grants, and XiPKI schemas before
this step. The node host also needs Docker with Compose v2 and access to the configured registry.

```bash
./node.sh setup
```

`setup` collects a missing database password, validates the package and Docker, pulls the pinned
images, performs a live database/schema preflight, starts the role, waits for health, and prints
its endpoint. If setup fails, run:

```bash
./node.sh doctor
./node.sh logs
```

Start the CA node first. Start Console, Gateway, and OCSP only after CA is healthy.
On the Console node, retrieve the generated first-login password and browser client identity only
when needed:

```bash
./node.sh credentials
```

## 3. Operate

```bash
./node.sh status
./node.sh smoke
./node.sh restart
./node.sh logs
./node.sh down
```

`down` retains local state. Use `reset` to delete containers and the generated runtime volume while
retaining the node package, identity material, settings, and Secrets. The next `setup` recreates the
runtime from the retained seed:

```bash
./node.sh reset
./node.sh setup
```

`purge` permanently deletes the runtime volume, generated configuration, identity material, and
local Secrets. A purged directory cannot run `setup`; extract the original node archive again.
Purge therefore requires explicit confirmation:

```bash
./node.sh purge
```

After all four roles are healthy, the administrator signs in to Console and completes **Quick
Start**. On the Gateway node, run the packaged end-to-end certificate check:

```bash
./node.sh verify
```

The command obtains the Quick Start CA through Gateway, enrolls a disposable certificate, confirms
OCSP `good`, permanently revokes it through Gateway, and confirms OCSP `revoked`. The temporary
certificate private key is deleted on exit. The Gateway bundle contains one dedicated REST client
identity for this check; it contains no Console password, CA-management identity, deployment CA
private key, recovery archive, or database password.
