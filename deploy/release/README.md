# XiPKI container release runbook

This runbook publishes the out-of-box XiPKI deployment to the `docker.io/xipki`
Docker Hub namespace and produces the small deployment archive that is
attached to a GitLab Release. It deliberately separates version preparation,
verification, image publication, and release announcement. A local build or
test never pushes an image.

The release consists of four images and one deployment archive:

- `mariadb`, the default database
- `postgres`, the optional database
- `bootstrap`, the first-run initializer
- `xipki`, the shared CA, Gateway, OCSP, and browser Console runtime
- `xipki-deploy-<version>.tar.gz`

`images.sh` reads the Maven reactor version from the root `pom.xml`; its
commands do not accept a second version argument. Stable published tags are
immutable. The `7.0.0-SNAPSHOT` tag is reserved for the experimental container
feature and may be replaced by a later snapshot build.

## 1. Release prerequisites

Use a clean checkout on a machine with:

- JDK 25
- Maven 3.9 or later
- Docker Engine or Docker Desktop with Compose v2 and Buildx
- `curl`, OpenSSL, Git, and `shasum` or `sha256sum`
- permission to push the release branch and tag to the GitLab `gitlab` remote
- permission to push images to the `xipki` Docker Hub namespace

The `xipki`, `bootstrap`, `mariadb`, and `postgres` Docker Hub repositories must be public for the
out-of-box deployment path. Do not store GitLab or Docker Hub credentials in the repository.

The examples below use `7.0.1`, `feat/containerized-deployment`, and `master`. Replace them
with the approved release values before running the commands:

```bash
VERSION=7.0.1
SOURCE_BRANCH=feat/containerized-deployment
TARGET_BRANCH=master
REGISTRY=docker.io/xipki
```

Formal releases use exactly three numeric components. Experimental builds keep
the repository's `-SNAPSHOT` version; `images.sh` accepts both because the POM
is the single source for artifact names, image tags, and deployment archives.

## 2. Reserve the version

Confirm that the Git tag and all four Docker Hub tags are unused. The following
command prints nothing when the Git tag does not exist:

```bash
git ls-remote --tags gitlab "refs/tags/v${VERSION}"
```

Check Docker Hub for `${VERSION}` on every image repository. The
following command should fail for each unused tag:

```bash
for role in mariadb postgres bootstrap xipki; do
  docker buildx imagetools inspect "${REGISTRY}/${role}:${VERSION}"
done
```

Do not continue when any tag already exists. Select a new version instead of
overwriting or repairing a version in place.

## 3. Prepare the release candidate

Switch to the candidate branch and require a clean tracked worktree:

```bash
git switch "${SOURCE_BRANCH}"
git pull --ff-only gitlab "${SOURCE_BRANCH}"
git status --short
```

For an experimental build, keep the existing Maven `-SNAPSHOT` version and read
it directly:

```bash
VERSION="$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)"
```

For a formal release only, update the Maven reactor version first. This updates
the parent version inherited by the child modules; it does not change the
independent `xicrypto`, `xipkix`, or `xishell` dependency versions.

```bash
mvn versions:set \
  -DnewVersion="${VERSION}" \
  -DgenerateBackupPoms=false
mvn help:evaluate -Dexpression=project.version -q -DforceStdout
```

Do not copy this version into the release script. The build exports the Maven
version to Compose, and the deployment archive contains a generated `.env`
that pins the same value.

Review every remaining old version reference before deciding whether it is an
intentional dependency version or stale packaging metadata:

```bash
rg -n '7\.0\.0|7\.0\.0-dev' \
  --glob 'pom.xml' deploy pom.xml
git diff --check
git diff
```

Replace `7.0.0` in the check with the version from which the new release was
prepared. Commit and push the version change, then open a GitLab merge request
from `${SOURCE_BRANCH}` to `${TARGET_BRANCH}`:

```bash
git add -u
git commit -m "chore: prepare ${VERSION} release"
git push gitlab "${SOURCE_BRANCH}"
```

Do not add `target/`, `.state/`, generated credentials, certificates, or the
deployment archive. They are build/runtime outputs and are ignored by Git.

## 4. Merge and freeze the source commit

Require review and a green GitLab pipeline before merging. After the merge,
build the release from the exact target-branch commit, not from the former
feature-branch commit:

```bash
git switch "${TARGET_BRANCH}"
git pull --ff-only gitlab "${TARGET_BRANCH}"
git status --short
git rev-parse HEAD
```

`git status --short` must be empty in the release checkout. Record the printed
commit SHA in the release notes.

Create an annotated tag locally. It is pushed only after local verification:

```bash
git tag -a "v${VERSION}" -m "XiPKI ${VERSION}"
```

## 5. Build and run automated release verification

Run the normal test suite before the packaging build:

```bash
mvn clean verify
./deploy/compose/tests/xipki-config-test.sh
./deploy/compose/tests/xipki-secret-permissions-test.sh
./deploy/compose/tests/xipki-purge-test.sh
./deploy/compose/tests/xipki-distributed-bundle-test.sh
./deploy/compose/tests/xipki-gateway-verification-test.sh
./deploy/docker/tests/bootstrap-check-test.sh
./deploy/docker/tests/role-init-test.sh
./deploy/release/tests/bundle-test.sh
```

The launcher tests verify strict non-secret configuration parsing, external
database Secret separation and preflight selection, recovery from an incomplete
configuration, native Linux file-backed Compose secret permissions, protection
of host-only private material, permission repair without credential rotation,
exact destructive-action confirmation for reset and purge, and successful idempotent
Console role-state initialization inside the release runtime. The Bootstrap
check-mode test also proves that a successful database preflight exits cleanly
with fresh state, accepts the complete current marker, and rejects unsupported pre-release marker
formats instead of guessing missing values.
The bundle contract tests also ensure that the end-user, node, Gateway-verification, and database
guides and their matching launchers are present in the release archive.

Build the Maven distribution and all current-platform release images:

```bash
./deploy/release/images.sh build
```

`build` runs a full-reactor `mvn clean install -DskipTests`, verifies that
`xipki-setup-<version>.tar.gz` exists, and builds all four images. MariaDB and
PostgreSQL receive separate database images. Bootstrap receives the setup
archive, while the `xipki` application image receives both the setup archive
and Console server JAR. Compose starts four application containers from that
one image and selects each process with `XIPKI_ROLE`.

Test fresh MariaDB and PostgreSQL installations:

```bash
./deploy/release/images.sh test
```

The test uses isolated Compose projects and ports, performs first-run
initialization, runs the smoke test, restarts services, and verifies that the
CA key survives the restart. Successful test projects and their volumes are
removed. A failed project is deliberately left running and its name is printed
for inspection.

The automated image test covers XiPKI-managed databases. Before publishing a
release that changes external database handling, also prepare a disposable
database with the contract in `deploy/compose/external-db/README.md`, then run
the standalone deployment path from a clean directory:

```bash
./container.sh config
./container.sh config check
./container.sh up --no-pull
./container.sh smoke --restart
./container.sh status
```

Confirm that preflight checks every role, all four application containers are
healthy after restart, and `status` contains no `database` service. Test both
engines when schema, driver, or database bootstrap compatibility changed;
otherwise at least one external engine is required for release acceptance.
Use only disposable databases and transfer test passwords through an approved
secret channel.

For a release that changes distributed deployment, use a disposable external
database and four isolated Compose projects (separate hosts are required for final
production acceptance):

```bash
./container.sh config
./container.sh config check
./container.sh prepare --no-pull
```

Verify `SHA256SUMS`, extract every archive on its target test node, then run
`./node.sh setup --no-pull` and `./node.sh doctor` inside each extracted directory.
Confirm the four projects share no network or volume, every application container
uses `${REGISTRY}/xipki:${VERSION}`, and each archive contains only its own role
state. Start CA before Console and Gateway, complete Quick Start, then run
`./node.sh verify` on the Gateway node. Complete the independent restart and CRL checks across
the distributed endpoints before publishing. On one disposable node, run `./node.sh reset`, enter
the exact confirmation, and confirm that a subsequent `./node.sh setup --no-pull` recreates only
that node while its settings, identities, and Secrets remain unchanged.

## 6. Run the Console business acceptance test

The automated smoke test proves deployment and persistence, but not the whole
browser workflow. In a disposable checkout with no existing `.state/`, start
the locally built release images:

```bash
XIPKI_COMPOSE_PROJECT="xipki-release-acceptance-${VERSION//./-}" \
XIPKI_VERSION="${VERSION}" \
./deploy/compose/container.sh up --no-pull

XIPKI_COMPOSE_PROJECT="xipki-release-acceptance-${VERSION//./-}" \
XIPKI_VERSION="${VERSION}" \
./deploy/compose/container.sh credentials
```

Complete and record this minimum acceptance checklist:

- Open `https://127.0.0.1:18081`; HTTPS is enabled and English is the default
  language.
- Sign in once with the generated local administrator password.
- Import the generated `admin.p12` into the browser and sign in with the
  client certificate.
- Confirm the first-run initialization result and inspect the configured CA
  inventory without exposing secrets in screenshots or logs.
- Create or import a disposable business CA, then verify its lifecycle and
  certificate download through the Console.
- Issue a certificate from a CSR and issue one with server-side key
  generation; verify inventory, download, and revocation operations.
- Exercise cross-certificate issuance when it is part of the release scope.
- Confirm that validation errors are understandable and the correlation ID is
  present for server-side failures.
- Run `./deploy/compose/container.sh smoke --restart`, sign in again, and confirm
  that the CA and certificate data persist.

Clean up only the disposable acceptance project. `purge` requires the exact
project-specific confirmation and permanently removes its data and generated
identities:

```bash
XIPKI_COMPOSE_PROJECT="xipki-release-acceptance-${VERSION//./-}" \
XIPKI_VERSION="${VERSION}" \
./deploy/compose/container.sh purge
```

If acceptance fails, do not push the tag or images. Fix the issue on the
candidate branch, merge it, move the unpushed local tag to the new verified
commit, and repeat all release verification.

## 7. Create and verify the deployment archive

```bash
./deploy/release/images.sh bundle
cd deploy/release/target
shasum -a 256 "xipki-deploy-${VERSION}.tar.gz" \
  > "xipki-deploy-${VERSION}.tar.gz.sha256"
shasum -a 256 -c "xipki-deploy-${VERSION}.tar.gz.sha256"
cd -
```

On Linux, use `sha256sum` in place of `shasum -a 256`.

The archive contains standalone and role-scoped Compose manifests, the control-host
and node launchers, the smoke test, deployment and external-database documentation,
the required MariaDB/PostgreSQL deployment schema scripts, the license, and a version-pinned `.env`. Optional
database-audit and OCSP response-cache schemas remain in the XiPKI source tree for expert installations and
are not included in this deployment archive. It does not contain Maven, a JDK,
application binaries, images, or credentials. End users extract it and run
`./container.sh up`; DBAs use only the bundled schema scripts that correspond to
the selected external database.

## 8. Publish the tag and multi-platform images

Push the verified source tag first:

```bash
git push gitlab "v${VERSION}"
```

Authenticate without placing the password in shell history or the repository,
then publish the images:

```bash
docker login --username xipki
./deploy/release/images.sh push
```

`push` uses the Maven project version and builds each image directly for
`linux/amd64` and `linux/arm64`. It is the only release command that uploads
images.

Verify every manifest after the command completes:

```bash
for role in mariadb postgres bootstrap xipki; do
  docker buildx imagetools inspect "${REGISTRY}/${role}:${VERSION}"
done
```

Each output must contain both `linux/amd64` and `linux/arm64`. Do not publish
the deployment archive until all four manifests are present.

## 9. Verify on a clean host

Copy only the archive and checksum to a clean amd64 or arm64 host that is not
logged in to Docker Hub. Verify the checksum and deploy exactly as an end user:

```bash
shasum -a 256 -c "xipki-deploy-${VERSION}.tar.gz.sha256"
tar -xzf "xipki-deploy-${VERSION}.tar.gz"
cd "xipki-deploy-${VERSION}"
./container.sh up
./container.sh status
./container.sh smoke --restart
./container.sh credentials
```

Confirm that anonymous image pull works, all services become healthy, the
Console opens over HTTPS, both login mechanisms work, and restart persistence
passes. Run a short certificate issue/download/revoke workflow. Test
PostgreSQL on the same release when database compatibility changed:

```bash
XIPKI_DATABASE=postgres XIPKI_COMPOSE_PROJECT=xipki-postgres-acceptance \
  ./container.sh up
XIPKI_DATABASE=postgres XIPKI_COMPOSE_PROJECT=xipki-postgres-acceptance \
  ./container.sh smoke --restart
```

Use `purge` with the same environment values after the clean-host acceptance
test if the test data is no longer needed.

## 10. Publish the GitLab Release

Create the GitLab Release from tag `v${VERSION}` and attach:

- `xipki-deploy-${VERSION}.tar.gz`
- `xipki-deploy-${VERSION}.tar.gz.sha256`
- release notes containing the source commit SHA, supported platforms,
  database default, known limitations, upgrade notes, and acceptance results

Include the minimal user path in the release notes:

```bash
tar -xzf "xipki-deploy-${VERSION}.tar.gz"
cd "xipki-deploy-${VERSION}"
./container.sh up
./container.sh credentials
```

Announce the release only after the GitLab assets, all Docker Hub manifests, and
the clean-host result have been checked.

## 11. Failure and rollback policy

- Before publication, fix the release candidate and repeat verification. An
  unpushed local tag may be recreated at the corrected commit.
- If image publication stops after only some images were pushed, do not publish
  the archive or reuse that version publicly. Treat the partial version as
  abandoned, increment the patch version, and run the complete workflow.
- If a published release is defective, keep its tag and images immutable,
  publish a corrected patch version, and mark the defective GitLab Release as
  not recommended.
- For a failed fresh installation, purge it and deploy the last known-good
  bundle.
- For an existing installation, changing `.env` back to an older image version
  is not by itself a safe database rollback. Restore the database and persistent
  volumes from the pre-upgrade backup or snapshot before starting the previous
  version. Do not claim downgrade support without a tested migration path.

## Release checklist

- [ ] Version approved and unused in GitLab and all Docker Hub repositories
- [ ] Maven version is the intended snapshot or approved stable release
- [ ] Release merge request reviewed, pipeline green, and merged
- [ ] Release built from a clean target-branch commit
- [ ] `mvn clean verify` passed
- [ ] Launcher configuration, secret-permission, and purge tests passed
- [ ] `images.sh build` passed
- [ ] MariaDB and PostgreSQL `images.sh test` passed
- [ ] External database preflight, deployment, and restart acceptance passed
- [ ] Gateway issuance, permanent revocation, and OCSP lifecycle verification passed
- [ ] Console business acceptance passed
- [ ] Deployment archive checksum verified
- [ ] Annotated Git tag pushed
- [ ] Four amd64/arm64 image manifests verified in Docker Hub
- [ ] Clean-host deployment and anonymous pull passed
- [ ] GitLab Release assets and notes published

## Script responsibility boundaries

`deploy/release/images.sh` automates Maven packaging, image building, isolated
deployment tests, archive creation, and multi-platform image publication. It
reads but does not choose or update the Maven version, commit or merge code,
create Git tags, generate checksums, perform the browser business acceptance
test, create the GitLab Release, or roll back an existing installation. Those
remain explicit release-owner decisions in this runbook.
