#!/usr/bin/env bash

set -euo pipefail

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_dir="$(cd "${test_dir}/.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/xipki-secret-permissions-test.XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT

fixture_dir="${work_dir}/compose"
fake_bin="${work_dir}/bin"
docker_log="${work_dir}/docker.log"
mkdir -p "${fixture_dir}" "${fake_bin}"
cp "${compose_dir}/container.sh" \
  "${compose_dir}/compose.yaml" \
  "${compose_dir}/compose.mariadb.yaml" \
  "${compose_dir}/compose.postgres.yaml" \
  "${compose_dir}/compose.external-db.yaml" \
  "${fixture_dir}/"
cp "${test_dir}/fixtures/docker" "${fake_bin}/docker"
cp "${test_dir}/fixtures/smoke-test.sh" "${fixture_dir}/smoke-test.sh"
touch "${docker_log}"

# Returns a file's numeric permission bits on both BSD and GNU stat.
file_mode() {
  local path="$1"
  if stat -f '%Lp' "${path}" >/dev/null 2>&1; then
    stat -f '%Lp' "${path}"
  else
    stat -c '%a' "${path}"
  fi
}

# Fails with a focused diagnostic when a generated file has the wrong mode.
assert_mode() {
  local expected="$1"
  local path="$2"
  local actual
  actual="$(file_mode "${path}")"
  [[ "${actual}" == "${expected}" ]] || {
    printf 'expected mode %s for %s, got %s\n' "${expected}" "${path}" "${actual}" >&2
    exit 1
  }
}

PATH="${fake_bin}:${PATH}" \
XIPKI_TEST_DOCKER_LOG="${docker_log}" \
"${fixture_dir}/container.sh" up --no-pull

assert_mode 700 "${fixture_dir}/.state/secrets"
assert_mode 700 "${fixture_dir}/.state/client"

# File-backed Compose secrets must be readable by the non-root UID used by the
# containers. Their owner-only parent directories preserve host confidentiality.
for secret in \
  postgres_admin_password \
  mariadb_admin_password \
  ca_db_password \
  console_db_password \
  console_admin_password \
  console_enrollment_key \
  console_tls_cert.pem \
  console_tls_key.pem \
  gateway_db_password \
  ocsp_db_password; do
  assert_mode 444 "${fixture_dir}/.state/secrets/${secret}"
done
assert_mode 444 "${fixture_dir}/.state/client/console-client-ca.crt"
assert_mode 444 "${fixture_dir}/.state/client/admin.crt"

# Host-only authentication material must remain owner-readable only.
assert_mode 600 "${fixture_dir}/.state/secrets/console_admin_client_password"
assert_mode 600 "${fixture_dir}/.state/client/console-client-ca.key"
assert_mode 600 "${fixture_dir}/.state/client/admin.key"
assert_mode 600 "${fixture_dir}/.state/client/admin.p12"

console_password_checksum="$(cksum <"${fixture_dir}/.state/secrets/console_db_password")"
chmod 0600 "${fixture_dir}/.state/secrets/"* "${fixture_dir}/.state/client/"*.crt

PATH="${fake_bin}:${PATH}" \
XIPKI_TEST_DOCKER_LOG="${docker_log}" \
"${fixture_dir}/container.sh" up --no-pull

# Startup must repair operator-altered permissions without rotating credentials that are already
# stored in the database.
for secret in \
  postgres_admin_password \
  mariadb_admin_password \
  ca_db_password \
  console_db_password \
  console_admin_password \
  console_enrollment_key \
  console_tls_cert.pem \
  console_tls_key.pem \
  gateway_db_password \
  ocsp_db_password; do
  assert_mode 444 "${fixture_dir}/.state/secrets/${secret}"
done
assert_mode 444 "${fixture_dir}/.state/client/console-client-ca.crt"
assert_mode 444 "${fixture_dir}/.state/client/admin.crt"
[[ "$(cksum <"${fixture_dir}/.state/secrets/console_db_password")" \
    == "${console_password_checksum}" ]] || {
  echo "repairing secret permissions rotated the Console database password" >&2
  exit 1
}

echo "xipki secret permission tests passed"
