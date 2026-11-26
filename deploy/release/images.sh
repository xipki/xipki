#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/../.." && pwd)"
compose_dir="${project_dir}/deploy/compose"
compose_file="${compose_dir}/compose.yaml"
compose_mariadb_file="${compose_dir}/compose.mariadb.yaml"
compose_postgres_file="${compose_dir}/compose.postgres.yaml"
compose_build_file="${compose_dir}/compose.build.yaml"
launcher="${compose_dir}/container.sh"
image_prefix="${XIPKI_IMAGE_PREFIX:-docker.io/xipki}"
image_prefix="${image_prefix%/}"
platforms="${XIPKI_PLATFORMS:-linux/amd64,linux/arm64}"

usage() {
  cat <<'EOF'
Usage: ./deploy/release/images.sh COMMAND

Commands:
  build   Build Maven artifacts and current-platform release images
  test    Test local release images in an isolated Compose project
  bundle  Create the standalone deployment archive
  push    Build and push linux/amd64 and linux/arm64 release images

Environment:
  XIPKI_IMAGE_PREFIX  Registry/namespace prefix (default: docker.io/xipki)
  XIPKI_PLATFORMS     Push platforms (default: linux/amd64,linux/arm64)
EOF
}

fail() {
  echo "release-images: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

project_version() {
  local line
  local version_pattern='<version>([^<]+)</version>'
  while IFS= read -r line; do
    if [[ "${line}" =~ ${version_pattern} ]]; then
      printf '%s\n' "${BASH_REMATCH[1]}"
      return
    fi
  done < "${project_dir}/pom.xml"
  fail "could not read the Maven project version from pom.xml"
}

# Uses the Maven reactor version as the single source for artifact names, image tags, and bundles.
prepare_version() {
  local version
  version="$(project_version)"
  [[ "${version}" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] \
    || fail "Maven project version is not a valid container tag: ${version}"

  export XIPKI_SOURCE_VERSION="${version}"
  export XIPKI_SETUP_ARCHIVE="assemblies/xipki-setup/target/xipki-setup-${version}.tar.gz"
  export XIPKI_CONSOLE_JAR="console-server/target/xipki-console-server-${version}.jar"
  export XIPKI_IMAGE_PREFIX="${image_prefix}"
  export XIPKI_VERSION="${version}"
  export XIPKI_DEV_IMAGE_PREFIX="${image_prefix}"
  export XIPKI_DEV_VERSION="${version}"
}

assert_setup_archive() {
  local archive_path="${project_dir}/${XIPKI_SETUP_ARCHIVE}"
  if [[ ! -f "${archive_path}" ]]; then
    printf 'Expected Maven release archive was not created: %s\n' \
      "${XIPKI_SETUP_ARCHIVE}" >&2
    printf 'Check the reactor build and ensure every module references parent version %s.\n' \
      "${XIPKI_SOURCE_VERSION}" >&2
    fail "Maven setup archive is missing"
  fi
}

build_images() {
  prepare_version
  require_command docker
  require_command mvn

  (
    cd "${project_dir}"
    # xipki-setup copies reactor artifacts through Maven plugins, so Maven cannot
    # discover every required module via -am. Build and install the full reactor.
    mvn clean install -DskipTests
    assert_setup_archive
    XIPKI_DATABASE=mariadb docker compose \
      -f "${compose_file}" -f "${compose_mariadb_file}" -f "${compose_build_file}" build
    XIPKI_DATABASE=postgres docker compose \
      -f "${compose_file}" -f "${compose_postgres_file}" -f "${compose_build_file}" build database
  )
}

assert_local_images() {
  local version="$1"
  local role
  for role in mariadb postgres bootstrap xipki; do
    docker image inspect "${image_prefix}/${role}:${version}" >/dev/null 2>&1 \
      || fail "local image is missing; run build first: ${image_prefix}/${role}:${version}"
  done
}

test_images() {
  local version database test_project test_version database_compose_file
  prepare_version
  version="${XIPKI_VERSION}"
  test_version="$(printf '%s' "${version//./-}" | tr '[:upper:]' '[:lower:]')"
  require_command docker
  assert_local_images "${version}"

  export XIPKI_GATEWAY_HTTP_PORT="${XIPKI_RELEASE_TEST_GATEWAY_HTTP_PORT:-28082}"
  export XIPKI_GATEWAY_HTTPS_PORT="${XIPKI_RELEASE_TEST_GATEWAY_HTTPS_PORT:-28445}"
  export XIPKI_OCSP_HTTP_PORT="${XIPKI_RELEASE_TEST_OCSP_HTTP_PORT:-28080}"
  export XIPKI_CONSOLE_HTTPS_PORT="${XIPKI_RELEASE_TEST_CONSOLE_HTTPS_PORT:-28081}"

  for database in mariadb postgres; do
    test_project="xipki-release-test-${database}-${test_version}"
    database_compose_file="${compose_dir}/compose.${database}.yaml"
    export XIPKI_DATABASE="${database}"
    export XIPKI_COMPOSE_PROJECT="${test_project}"

    # Each database test owns a uniquely named Compose project. Clearing its
    # volumes proves a real first install without touching a developer's stack.
    docker compose --project-name "${test_project}" \
      -f "${compose_file}" -f "${database_compose_file}" \
      down --volumes --remove-orphans

    if ! "${launcher}" up --no-pull; then
      fail "${database} startup failed; project ${test_project} was left running for inspection"
    fi
    if ! "${launcher}" smoke --restart; then
      fail "${database} persistence test failed; project ${test_project} was left running for inspection"
    fi

    docker compose --project-name "${test_project}" \
      -f "${compose_file}" -f "${database_compose_file}" \
      down --volumes --remove-orphans
  done
  echo "Release images passed MariaDB and PostgreSQL deployment tests."
}

# Copies only schemas used by the supported container deployment contract. XiPKI's source tree
# retains optional audit and OCSP response-cache schemas for expert installations, but placing them
# beside required deployment scripts would incorrectly imply that DBAs must initialize them.
copy_deployment_database_scripts() {
  local source_dir="$1"
  local target_dir="$2"
  local suffix="$3"
  local schema source_file

  for schema in caconf ca ocsp keypool acme; do
    source_file="${source_dir}/${schema}-init.${suffix}.sql"
    [[ -f "${source_file}" ]] \
      || fail "required ${suffix} deployment schema is missing: ${source_file}"
    cp "${source_file}" "${target_dir}/"
  done
}

build_bundle() {
  local version
  local target_dir="${project_dir}/deploy/release/target"
  local bundle_name
  local work_dir
  prepare_version
  version="${XIPKI_VERSION}"
  bundle_name="xipki-deploy-${version}"
  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/xipki-deploy.XXXXXX")"

  mkdir -p "${target_dir}" "${work_dir}/${bundle_name}"
  cp "${compose_file}" "${work_dir}/${bundle_name}/compose.yaml"
  cp "${compose_mariadb_file}" "${work_dir}/${bundle_name}/compose.mariadb.yaml"
  cp "${compose_postgres_file}" "${work_dir}/${bundle_name}/compose.postgres.yaml"
  cp "${compose_dir}/compose.external-db.yaml" \
    "${work_dir}/${bundle_name}/compose.external-db.yaml"
  cp "${compose_dir}/xipki.env.example" "${work_dir}/${bundle_name}/xipki.env.example"
  cp "${compose_dir}/container.sh" "${work_dir}/${bundle_name}/container.sh"
  cp "${compose_dir}/smoke-test.sh" "${work_dir}/${bundle_name}/smoke-test.sh"
  mkdir -p "${work_dir}/${bundle_name}/distributed"
  cp "${compose_dir}/distributed/"*.yaml \
    "${compose_dir}/distributed/node.sh" \
    "${compose_dir}/distributed/gateway-verify.sh" \
    "${compose_dir}/distributed/node-README.md" \
    "${compose_dir}/distributed/README.md" \
    "${work_dir}/${bundle_name}/distributed/"
  mkdir -p \
    "${work_dir}/${bundle_name}/database/mariadb" \
    "${work_dir}/${bundle_name}/database/postgres"
  cp "${compose_dir}/external-db/README.md" \
    "${work_dir}/${bundle_name}/database/README.md"
  copy_deployment_database_scripts \
    "${project_dir}/assemblies/xipki-setup/src/assembly/unfiltered/xipki-mgmt-cli/xipki/sql/mysql" \
    "${work_dir}/${bundle_name}/database/mariadb" mysql
  copy_deployment_database_scripts \
    "${project_dir}/assemblies/xipki-setup/src/assembly/unfiltered/xipki-mgmt-cli/xipki/sql/postgresql" \
    "${work_dir}/${bundle_name}/database/postgres" postgresql
  cp "${script_dir}/deployment-README.md" "${work_dir}/${bundle_name}/README.md"
  cp "${project_dir}/LICENSE" "${work_dir}/${bundle_name}/LICENSE"
  printf 'XIPKI_IMAGE_PREFIX=%s\nXIPKI_VERSION=%s\nXIPKI_DEPLOYMENT_MODE=standalone\nXIPKI_DATABASE=mariadb\nXIPKI_DATABASE_MODE=managed\n' \
    "${image_prefix}" "${version}" > "${work_dir}/${bundle_name}/.env"
  # macOS bsdtar otherwise serializes extended attributes as hidden AppleDouble
  # entries (._*), which GNU tar exposes as noisy, unnecessary files on Linux.
  COPYFILE_DISABLE=1 tar --no-xattrs -czf "${target_dir}/${bundle_name}.tar.gz" \
    -C "${work_dir}" "${bundle_name}"
  rm -rf "${work_dir}"
  echo "Created ${target_dir}/${bundle_name}.tar.gz"
}

push_role() {
  local role="$1"
  local version="$2"
  local target_args=()

  if [[ "${role}" != "postgres" && "${role}" != "mariadb" ]]; then
    target_args=(
      --file "${project_dir}/deploy/docker/Dockerfile"
      --target "${role}"
      --build-arg "XIPKI_SETUP_ARCHIVE=${XIPKI_SETUP_ARCHIVE}"
    )
    if [[ "${role}" == "xipki" ]]; then
      target_args+=(--build-arg "XIPKI_CONSOLE_JAR=${XIPKI_CONSOLE_JAR}")
    fi
  else
    target_args=(--file "${project_dir}/deploy/docker/${role}/Dockerfile")
  fi

  docker buildx build \
    --platform "${platforms}" \
    "${target_args[@]}" \
    --tag "${image_prefix}/${role}:${version}" \
    --provenance=false \
    --push \
    "${project_dir}"
}

push_images() {
  local version
  local role
  prepare_version
  version="${XIPKI_VERSION}"
  require_command docker
  docker buildx version >/dev/null 2>&1 || fail "Docker Buildx is required"
  docker buildx inspect --bootstrap >/dev/null
  assert_setup_archive

  for role in mariadb postgres bootstrap xipki; do
    push_role "${role}" "${version}"
  done
}

main() {
  local command="${1:-}"
  [[ -n "${command}" && $# -eq 1 ]] || {
    usage >&2
    exit 2
  }

  case "${command}" in
    build)
      build_images
      ;;
    test)
      test_images
      ;;
    bundle)
      build_bundle
      ;;
    push)
      push_images
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
