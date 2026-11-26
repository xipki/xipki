# XiPKI Distributed Compose Deployment

- **Status:** External-database milestone implemented and manually accepted on separate Linux hosts
- **Date:** 2026-11-26
- **Primary outcome:** Preserve one-command standalone deployment while adding role-scoped,
  multi-host Docker Compose deployment
- **Constraint:** Do not change XiPKI CA, Gateway, or OCSP business logic

## 1. Product Contract

XiPKI has one release and two deployment modes. They use the same application image and generated
runtime configuration; the topology is the only product-level difference.

```text
standalone
  ./container.sh up
  -> database, CA, Console, Gateway, and OCSP on one Docker host

distributed
  control host: ./container.sh config && ./container.sh prepare
  node host:    ./node.sh setup
  -> one pinned role on each Docker host
```

The public control-host interface is deliberately small:

```text
config | config show | config check | prepare
```

Every generated node bundle exposes the same node interface:

```text
setup | doctor | config | config show | config check | check | up | pull | status | logs | smoke
restart | down | reset | purge | credentials | verify | version
```

Role selection, configuration rendering, Secret placement, certificates, and Compose selection are
implementation details behind those interfaces. A node operator must not need to set
`XIPKI_ROLE` manually.

Generated archives use node bundle format v2. `manifest.env` is immutable and pins the deployment,
role, Compose project, and image. `node.env` is the narrowly scoped, non-secret node configuration.
The launcher parses both through independent allowlists and rejects an unsupported bundle format.
The `.state/seed` directory is the immutable role input used by the one-shot materializer. Node
settings and the node-local database password remain separate from it.

## 2. First Distributed Release Scope

The first distributed release supports one node for each application role:

- CA
- Console
- Gateway
- OCSP

A DBA-prepared external MariaDB or PostgreSQL service is required. A remotely exposed managed
database node, multiple instances, load balancing, automated failover, Kubernetes, Vault, HSM
lifecycle, and rolling upgrade are later product levels.

## 3. Verified Current Dependencies

### 3.1 Console to CA

Console reads `XIPKI_CA_URL`, defaulting to an HTTPS CA management URL, and creates XiPKI's official
`org.xipki.ca.mgmt.client.CaMgmtClient` through `OfficialCaMgmtClientFactory`. It uses:

- `client.p12` as the CA management client identity;
- `trustanchors.pem` to authenticate the CA endpoint;
- the password file stored in Console role state;
- the standard hostname verifier;
- bounded connection/read timeouts, redirects disabled, and POST retry disabled.

CA management performs a second authorization check after TLS: the presented client certificate
must exactly match one of the certificates configured in `remoteMgmt.certs`. This means a remote
Console can use the existing management protocol without changing CA business logic.

### 3.2 Gateway to CA

Gateway's generated `gateway.json` configures the SDK client with:

```text
https://<ca-host>:<ca-https-port>/ca/ra/
```

It uses `ra-sdk-client.p12`, trusts `ca-server-cert.pem`, and enables the standard hostname
verifier. The CA TLS connector trusts the RA SDK client identity. A remote Gateway therefore only
requires rendered endpoint names and correctly scoped TLS material.

### 3.3 OCSP

The current OCSP runtime has no direct application call to the CA container. It reads CA and OCSP
data using the `xipki_ocsp` database identity and carries its responder signing material in OCSP
role state. Distributed OCSP therefore requires database reachability, not CA container discovery.

### 3.4 Database access

| Runtime role | Database identity | Databases | Access |
| --- | --- | --- | --- |
| CA | `xipki_ca` | `caconf`, `ca`, `ocsp`, `keypool` | owner/read/write |
| Gateway | `xipki_gateway` | `acme` | owner/read/write |
| OCSP | `xipki_ocsp` | `ca`, `ocsp` | read |
| Console | `xipki_console` | `xipki_console` | schema/read/write |

Distributed node configuration accepts a role-specific host, port, account, and database names.
CA exposes caconf, certificate, OCSP, and key-pool names; OCSP exposes CA and OCSP data names;
Gateway and Console expose one name each. One database engine remains pinned in the immutable
deployment manifest so a deployment cannot silently mix JDBC driver contracts.

## 4. Current Port and Trust Contract

| Role | Container port | Protocol | Intended callers | Current authentication |
| --- | ---: | --- | --- | --- |
| CA | 8444 | HTTPS | Console and Gateway | required TLS client certificate |
| Console | 8443 | HTTPS | administrators | password and/or browser certificate |
| Gateway | 8082 | HTTP | host-local diagnostics | loopback-only publication |
| Gateway | 8445 | HTTPS | protocol clients | optional TLS client certificate |
| OCSP | 8080 | HTTP | relying parties | OCSP protocol |
| MariaDB | 3306 | database | all runtime roles | role password |
| PostgreSQL | 5432 | database | all runtime roles | role password |

Gateway has no required reverse-proxy tier: its Tomcat connector terminates public TLS directly.
Preparation generates a deployment-internal root. CA and Gateway server identities are issued with
only `serverAuth` and the configured DNS/IP subject alternative name. The Console management
identity and the separate Gateway RA SDK identity are issued with only `clientAuth`. Preparation
verifies every leaf against the deployment root, verifies both server SANs, rejects swapped or
dual-purpose EKUs, and confirms that the two Gateway identities are distinct before packaging.
Runtime bundles receive the root certificate but never its private key; the key and password are
retained only in protected control-host state. CA management and RA authorization still match the
presented client leaf certificates after TLS chain validation. A separate-host release acceptance
must repeat hostname verification with the production DNS records.

Before preparation, an operator may import a CA or Gateway server PKCS#12 identity plus its trust
anchor. Import verifies the password, key/leaf match, exclusive `serverAuth`, configured SAN, and
complete chain. A CA trust override is distributed to Console and Gateway; the Gateway public
trust override is also copied to the Gateway verification client. Management and RA client
identity import is deliberately excluded because those certificates are also CA authorization
records and require a coordinated lifecycle rather than file replacement.

## 5. Current Role Artifact Ownership

Bootstrap already creates role-scoped directories internally. This is the correct seam for
distributed export; the missing capability is packaging those directories instead of publishing
all of them through local Docker volumes.

| Artifact owner | Sensitive material currently copied by Bootstrap |
| --- | --- |
| CA | CA TLS server key, CA TLS trust store, accepted management/RA client certificates, DB password placeholder |
| Console | CA management client key, CA server trust anchor, management key password, enrollment state |
| Gateway | Gateway TLS server key, RA SDK client key, CA server trust anchor, protocol client trust stores, DB password placeholder |
| OCSP | bootstrap OCSP signer key, DB password placeholder |
| Control host | Deployment CA and CA-management generation material; never packaged as a node artifact |

Console consumes the generated CA management client identity. The Gateway verification path uses
a separate REST identity limited to enrollment and revocation and never receives CA-management or
deployment-CA private material.

## 6. Resolved Single-Host Assumptions

Distributed mode removes the following assumptions while standalone mode deliberately retains
them for the one-command experience:

1. Bootstrap mounts and publishes to all role volumes in one Compose project.
2. Console uses `https://ca:8444/ca/mgmt` in the base Compose manifest.
3. Generated CA and Gateway configuration defaults to the Compose names `ca` and `gateway`.
4. Application services use Compose `depends_on` for remote startup ordering.
5. The managed database is available through the Compose name `database` and is not published to
   another host.
6. Smoke tests inspect every role through one Compose project.

Standalone mode retains these assumptions because they provide the simplest one-command user
experience.

## 7. Current Preparation Flow

```text
public release bundle (contains no deployment Secret)
  -> config
  -> versioned deployment description + local identity files (no database password)
  -> config check
  -> prepare
  -> immutable deployment manifest + role-scoped node bundles + checksums
  -> secure transfer of exactly one bundle to each node
  -> optional node config override
  -> node setup (node-local database password, preflight, and startup)
  -> Console Quick Start
  -> Gateway node verify
```

`prepare` is idempotent for one deployment ID. Re-running it with the same accepted topology must
reuse identities. A topology or trust change must be explicit and must never silently rotate
working node credentials.

Generated node bundles are private deployment artifacts, not release assets. They use mode `0600`,
must never be committed to Git, and must not contain another role's Secret.

Before materializing a role seed, the node launcher checks the role marker and its minimum runtime
identity set. The Gateway check requires both the server identity and the independently authorized
RA SDK client identity, preventing an incomplete transfer or a manually mixed bundle from reaching
Tomcat startup.

Private-key passwords are extracted from generated configuration during packaging and written as
role-scoped, file-backed Secrets. XML and JSON in the immutable seed carry only explicit markers;
the privileged one-shot role initializer resolves them inside the private runtime volume before
ownership transfers to the fixed non-root service UID. This keeps passwords out of `node.env`,
Compose environment variables, command arguments, and the immutable configuration template.

Distributed preparation renders explicit database-password placeholders instead of credentials.
The control host never receives a role database password. `node.sh config` creates only the local
role's file-backed Secret; on first start, `xipki-role-init` materializes that Secret into the
node's private runtime volume without placing it in an environment variable or command argument.

## 8. Database Modes

Standalone defaults to an XiPKI-managed MariaDB container. Distributed mode requires an external
database in the first milestone. A dedicated managed-database node may be added later for
evaluation and small installations.

A distributed managed database is not the current private Compose database moved unchanged to
another host. Before support is claimed it needs an explicit bind address, firewall guidance,
TLS, remote role grants, health checks, persistent backup guidance, and node-level acceptance.

## 9. Startup and Readiness

Distributed startup order is:

1. database;
2. CA;
3. Console;
4. initial CA configuration or Quick Start;
5. Gateway;
6. OCSP;
7. deployment verification.

Compose `depends_on` is not a cross-host coordinator. Each node performs bounded dependency
preflight and starts only its local role. Runtime dependencies must report focused readiness
failures and retry only operations whose outcome is unambiguous.

## 10. Acceptance Contract

Distributed support is complete only when:

- standalone `./container.sh up` remains unchanged and passes its MariaDB/PostgreSQL tests;
- node bundles share no Docker network or volume;
- every application node runs the same `xipki` image version;
- each bundle contains only the declared role and its Secrets;
- Console manages the remote CA through the official client and mTLS;
- Gateway enrolls through the remote CA SDK endpoint and mTLS;
- OCSP reports good and revoked status through its read-only database identity;
- Quick Start, issuance, download, revocation, CRL, OCSP, and independent node restart pass on
  separate hosts;
- an unauthorized client cannot access CA management;
- recovery material and database/CA backups are documented and tested.

## 11. Implementation Sequence

1. Add the versioned deployment model while retaining standalone defaults. **Implemented.**
2. Separate Bootstrap generation from local role publication. **Implemented.**
3. Materialize role-scoped node directories and archives. **Implemented.**
4. Add the pinned-role node runtime and role Compose manifests. **Implemented.**
5. Render remote endpoints and hostname-valid TLS identities. **Implemented.**
6. Add the optional managed database node. **Not implemented.**
7. Test isolated Compose projects, then separate Linux hosts. **Implemented and manually accepted;
   each release candidate must repeat the documented acceptance flow.**
8. Add release and Gateway verification documentation. **Implemented for the external-database
   milestone.**
