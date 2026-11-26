#!/usr/bin/env bash

set -euo pipefail

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_dir="$(cd "${test_dir}/.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/xipki-config-test.XXXXXX")"
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

# Fails with a focused diagnostic when a generated configuration artifact has the wrong mode.
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

# The source launcher and generated release package must agree on the public image namespace.
output="$("${fixture_dir}/container.sh" version)"
[[ "${output}" == *"release=docker.io/xipki/{mariadb,postgres,bootstrap,xipki}:"* ]] \
  || { echo "default Docker Hub image namespace was not reported" >&2; exit 1; }

output="$("${fixture_dir}/container.sh" config show)"
[[ "${output}" == *"database.mode=managed"* \
  && "${output}" == *"deployment.mode=standalone"* \
  && "${output}" == *"database.engine=mariadb"* \
  && "${output}" == *"database.host=database"* ]] \
  || { echo "default configuration was not reported" >&2; exit 1; }

printf '%s\n' \
  standalone external postgres db.example.com '' \
  ca-pass ca-pass \
  ocsp-pass ocsp-pass \
  gateway-pass gateway-pass \
  console-pass console-pass \
  | "${fixture_dir}/container.sh" config >/dev/null

config_file="${fixture_dir}/xipki.env"
grep -q '^XIPKI_DATABASE_MODE=external$' "${config_file}"
grep -q '^XIPKI_DATABASE=postgres$' "${config_file}"
grep -q '^XIPKI_DB_HOST=db.example.com$' "${config_file}"
grep -q '^XIPKI_DB_PORT=5432$' "${config_file}"
! grep -q -- '-pass' "${config_file}" \
  || { echo "xipki.env contains a database password" >&2; exit 1; }

assert_mode 600 "${config_file}"
assert_mode 700 "${fixture_dir}/.state/secrets"
for name in ca_db_password ocsp_db_password gateway_db_password console_db_password; do
  assert_mode 444 "${fixture_dir}/.state/secrets/${name}"
done

output="$("${fixture_dir}/container.sh" config show)"
[[ "${output}" == *"database.mode=external"* \
  && "${output}" == *"database.host=db.example.com"* \
  && "${output}" == *"secret.ca_db_password=configured"* ]] \
  || { echo "external configuration was not reported" >&2; exit 1; }
[[ "${output}" != *"ca-pass"* ]] \
  || { echo "config show exposed a password" >&2; exit 1; }

ca_password_checksum="$(cksum <"${fixture_dir}/.state/secrets/ca_db_password")"
printf '%s\n' standalone external postgres db.example.com '' \
  | "${fixture_dir}/container.sh" config >/dev/null
[[ "$(cksum <"${fixture_dir}/.state/secrets/ca_db_password")" \
    == "${ca_password_checksum}" ]] || {
  echo "reconfiguring external mode rotated an embedded database password" >&2
  exit 1
}

PATH="${fake_bin}:${PATH}" \
XIPKI_TEST_DOCKER_LOG="${docker_log}" \
"${fixture_dir}/container.sh" config check >/dev/null
[[ "$(<"${docker_log}")" == *"compose --project-name xipki"* \
  && "$(<"${docker_log}")" == *"compose.external-db.yaml run --rm --no-deps"* \
  && "$(<"${docker_log}")" == *"XIPKI_BOOTSTRAP_MODE=check bootstrap"* ]] \
  || { echo "config check did not run the external database preflight" >&2; exit 1; }

cp "${config_file}" "${config_file}.valid"

printf '%s\n' \
  distributed production \
  ca.internal.example.com console.internal.example.com \
  gateway.example.com ocsp.example.com \
  external postgres db.example.com '' \
  | "${fixture_dir}/container.sh" config >/dev/null
output="$("${fixture_dir}/container.sh" config show)"
[[ "${output}" == *"deployment.mode=distributed"* \
  && "${output}" == *"deployment.name=production"* \
  && "${output}" == *"node.ca=ca.internal.example.com"* \
  && "${output}" == *"node.console=console.internal.example.com"* \
  && "${output}" == *"node.gateway=gateway.example.com"* \
  && "${output}" == *"node.ocsp=ocsp.example.com"* \
  && "${output}" == *"database.passwords=configured-on-role-nodes"* ]] \
  || { echo "distributed topology was not reported" >&2; exit 1; }
for name in ca_db_password ocsp_db_password gateway_db_password console_db_password; do
  [[ ! -e "${fixture_dir}/.state/deployments/production/secrets/${name}" ]] \
    || { echo "distributed config stored ${name} on the control host" >&2; exit 1; }
done
"${fixture_dir}/container.sh" config check >/dev/null

set +e
output="$(PATH="${fake_bin}:${PATH}" \
  XIPKI_TEST_DOCKER_LOG="${docker_log}" \
  "${fixture_dir}/container.sh" up --no-pull 2>&1)"
status=$?
set -e
[[ ${status} -ne 0 && "${output}" == *"distributed deployments start from generated node bundles"* ]] \
  || { echo "distributed topology fell through to standalone startup" >&2; exit 1; }

cp "${config_file}" "${config_file}.distributed"
sed 's/^XIPKI_DATABASE_MODE=external$/XIPKI_DATABASE_MODE=managed/' \
  "${config_file}.distributed" > "${config_file}"
set +e
output="$("${fixture_dir}/container.sh" config show 2>&1)"
status=$?
set -e
[[ ${status} -ne 0 && "${output}" == *"distributed deployment currently requires"* ]] \
  || { echo "unsupported distributed managed database was accepted" >&2; exit 1; }

# The wizard is the recovery interface for a partially written external
# configuration, so it must start even when the required host is missing.
cp "${config_file}.valid" "${config_file}"
grep -v '^XIPKI_DB_HOST=' "${config_file}.valid" > "${config_file}"
printf '%s\n' standalone managed mariadb \
  | "${fixture_dir}/container.sh" config >/dev/null
grep -q '^XIPKI_DATABASE_MODE=managed$' "${config_file}"

cp "${config_file}.valid" "${config_file}"
printf 'XIPKI_CA_DB_PASSWORD=must-not-be-accepted\n' >> "${config_file}"
set +e
output="$("${fixture_dir}/container.sh" config show 2>&1)"
status=$?
set -e
[[ ${status} -ne 0 && "${output}" == *"unsupported setting XIPKI_CA_DB_PASSWORD"* ]] \
  || { echo "secret values were accepted in xipki.env" >&2; exit 1; }
[[ "${output}" != *"must-not-be-accepted"* ]] \
  || { echo "configuration error exposed a rejected secret" >&2; exit 1; }

echo "xipki configuration tests passed"
