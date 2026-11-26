# XiPKI Container Productization Developer Guide

This guide is the entry point for developers maintaining the experimental container deployment,
browser Console, and release packaging. It does not redefine XiPKI CA, Gateway, or OCSP business
logic. Changes to those core modules are outside this productization layer.

## Documentation map

- `deploy/release/deployment-README.md`: end-user guide packaged as `README.md`.
- `deploy/compose/distributed/node-README.md`: end-user guide packaged into every role archive.
- `deploy/compose/external-db/README.md`: DBA handoff and schema preparation.
- `deploy/compose/README.md`: source-checkout deployment and local development workflow.
- `deploy/docker/README.md`: image stages and runtime role contract.
- `deploy/release/README.md`: build, test, publish, and release-owner runbook.
- `docs/design/xipki-distributed-deployment.md`: topology, trust, and artifact ownership design.

User-facing behavior must be updated in the packaged guides first. Design documents explain why
the contract exists; they must not become a second, conflicting command reference.

## Product boundary

The deployment has two modes and one application runtime:

- Standalone starts a managed or external database plus CA, Console, Gateway, and OCSP on one
  Docker host. The default managed MariaDB path is `./container.sh up` with no prior configuration.
- Distributed preparation creates private CA, Console, Gateway, and OCSP node archives. Each node
  runs one role with its packaged `node.sh`; the first release requires a DBA-prepared external
  MariaDB or PostgreSQL service.

CA, Gateway, OCSP, and Console use the same `xipki` image but run as separate containers selected
by `XIPKI_ROLE`. Bootstrap and the two database engines use separate images. A deployment pulls
only the selected database image, Bootstrap, and the shared application image.

## Source layout

- `console-ui/`: React user interface; English is the default locale.
- `console-server/`: embedded-Tomcat Console API and the official `CaMgmtClient` adapter.
- `deploy/docker/`: shared runtime, Bootstrap, database image definitions, entrypoints, and tests.
- `deploy/compose/`: standalone and distributed launchers, Compose manifests, and shell tests.
- `deploy/release/`: image lifecycle and release archive assembly.

Do not duplicate XiPKI management protocol logic in the Console. Console operations go through
the official management client adapter, and CA authentication remains mutual TLS plus XiPKI's
configured management-certificate authorization.

## State and Secret model

Non-secret operator settings are parsed from allowlisted `KEY=VALUE` files; neither
`container.sh` nor `node.sh` executes those files as shell code. Passwords and private material
are file-backed Secrets below `.state/` and are excluded from Git and release archives.

In distributed mode, the control host creates identities and trust material but never receives a
role database password. Each node administrator enters only that role's password. The immutable
`.state/seed` is copied into a private runtime volume, where the one-shot role initializer resolves
Secret placeholders before the non-root application starts.

Lifecycle commands intentionally have different recovery boundaries:

- `down` stops containers and retains all state.
- `reset` deletes the generated node runtime volume but retains the archive material, settings,
  and Secrets; `setup` can recreate the role.
- `purge` deletes all local deployment material and requires an exact confirmation phrase.

## Development workflow

Use the root Maven version as the only version source. `images.sh` and `container.sh` derive their
tags and artifact names from it; do not add a second version argument or hard-coded release value.

```bash
./deploy/compose/container.sh dev-build
./deploy/compose/container.sh dev-up
./deploy/compose/container.sh smoke --restart
```

`dev-build` builds local `-dev` images. Release images and the deployment archive use:

```bash
./deploy/release/images.sh build
./deploy/release/images.sh test
./deploy/release/images.sh bundle
```

Only `./deploy/release/images.sh push` publishes images. Build, test, and bundle commands must
remain local-only operations.

## Required verification

Run the focused shell tests for every launcher or packaging change:

```bash
./deploy/compose/tests/xipki-config-test.sh
./deploy/compose/tests/xipki-secret-permissions-test.sh
./deploy/compose/tests/xipki-purge-test.sh
./deploy/compose/tests/xipki-distributed-bundle-test.sh
./deploy/compose/tests/xipki-gateway-verification-test.sh
./deploy/docker/tests/bootstrap-check-test.sh
./deploy/docker/tests/role-init-test.sh
./deploy/release/tests/bundle-test.sh
```

Console changes also require its Java tests and UI build. Before publication, follow
`deploy/release/README.md` for both managed database engines, an external-database preflight,
standalone browser acceptance, four-node deployment, Gateway issuance/revocation/OCSP verification,
and clean-host archive acceptance.

## Change checklist

- Preserve the one-command standalone default.
- Keep role containers and their state isolated even though they share one image.
- Never serialize a password into an environment file, image layer, command argument, or log.
- Reject incomplete or unsupported artifact formats instead of guessing old defaults.
- Keep destructive operations explicit and scoped to one named deployment or role.
- Update packaged English user documentation in the same change as its command contract.
- Add or update a focused test for every security, lifecycle, or packaging boundary.
