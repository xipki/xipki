#!/usr/bin/env bash

set -euo pipefail

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_dir="$(cd "${test_dir}/.." && pwd)"
project_dir="$(cd "${compose_dir}/../.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/xipki-distributed-test.XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT

# Keeps archive assertions aligned with the Maven version used by the deployment launcher.
version="$({
  while IFS= read -r line; do
    if [[ "${line}" =~ \<version\>[^\<]+\</version\> ]]; then
      line="${line#*<version>}"
      printf '%s\n' "${line%%</version>*}"
      break
    fi
  done < "${project_dir}/pom.xml"
})"
[[ -n "${version}" ]] || { echo 'could not read Maven project version' >&2; exit 1; }
export XIPKI_VERSION="${version}"

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
cp -R "${compose_dir}/distributed" "${fixture_dir}/distributed"
cp "${test_dir}/fixtures/docker" "${fake_bin}/docker"
touch "${docker_log}"

printf '%s\n' \
  distributed production \
  ca.internal.example.com console.internal.example.com \
  gateway.example.com ocsp.example.com \
  external mariadb db.internal.example.com '' \
  | "${fixture_dir}/container.sh" config >/dev/null

# Injects a forbidden control-host database Secret to prove packaging cannot leak it into a node
# archive even when unrelated deployment state exists beside the generated Console material.
control_secret_dir="${fixture_dir}/.state/deployments/production/secrets"
mkdir -p "${control_secret_dir}"
printf 'must-not-be-packaged' > "${control_secret_dir}/ca_db_password"

PATH="${fake_bin}:${PATH}" \
XIPKI_TEST_DOCKER_LOG="${docker_log}" \
XIPKI_BOOTSTRAP_IMAGE=fake/bootstrap:test \
"${fixture_dir}/container.sh" prepare --no-pull >/dev/null

output_dir="${fixture_dir}/dist/production"
for role in ca console gateway ocsp; do
  archive="${output_dir}/xipki-production-${role}-${version}.tar.gz"
  [[ -f "${archive}" ]] || {
    echo "distributed prepare did not create ${role} bundle" >&2
    exit 1
  }
  tar -tzf "${archive}" | grep -q "/.state/seed/.initialized$"
  tar -tzf "${archive}" | grep -q "/manifest.env$"
  tar -tzf "${archive}" | grep -q "/node.env$"
  tar -tzf "${archive}" | grep -q "/node.env.example$"
  tar -tzf "${archive}" | grep -q "/README.md$"
  ! tar -tzf "${archive}" | grep -q '/\.env$' \
    || { echo "${role} bundle contains the retired .env contract" >&2; exit 1; }
done

# Requires one role archive to contain exactly its supported root database configurations. This
# catches both optional schemas and backend-specific source directories leaking into node state.
assert_role_database_files() {
  local role="$1"
  local relative_directory="$2"
  shift 2
  local archive="${output_dir}/xipki-production-${role}-${version}.tar.gz"
  local archive_root="xipki-production-${role}-${version}/.state/seed/${relative_directory}"
  local actual expected filename
  actual="$(
    tar -tzf "${archive}" \
      | grep "^${archive_root}/.*-db\\.properties$" \
      | sort
  )"
  expected="$(
    for filename in "$@"; do
      printf '%s/%s\n' "${archive_root}" "${filename}"
    done | sort
  )"
  [[ "${actual}" == "${expected}" ]] \
    || { echo "${role} bundle contains unsupported database configuration" >&2; exit 1; }
}

assert_role_database_files ca xipki/etc/ca/database \
  caconf-db.properties ca-db.properties ocsp-db.properties keypool-db.properties
assert_role_database_files gateway xipki/etc/acme/database acme-db.properties
assert_role_database_files ocsp xipki/etc/ocsp/database \
  ca-db.properties ocsp-db.properties

gateway_compose="$(
  tar -xOf "${output_dir}/xipki-production-gateway-${version}.tar.gz" \
    "xipki-production-gateway-${version}/compose.yaml"
)"
[[ "${gateway_compose}" == *'127.0.0.1:${XIPKI_GATEWAY_HTTP_PORT:-18082}:8082'* ]] \
  || { echo 'Gateway HTTP is not restricted to the node loopback interface' >&2; exit 1; }
[[ "${gateway_compose}" == *'${XIPKI_BIND_ADDRESS:-0.0.0.0}:${XIPKI_GATEWAY_HTTPS_PORT:-18445}:8445'* ]] \
  || { echo 'Gateway HTTPS no longer follows the reviewed public bind address' >&2; exit 1; }

tar -tzf "${output_dir}/xipki-production-ca-${version}.tar.gz" \
  | grep -q '/.state/secrets/ca_tls_keystore_password$' \
  || { echo 'CA bundle does not contain its file-backed TLS password' >&2; exit 1; }
tar -tzf "${output_dir}/xipki-production-console-${version}.tar.gz" \
  | grep -q '/.state/secrets/console_db_password$' \
  && { echo "Console bundle contains a database password" >&2; exit 1; }
for archive in "${output_dir}"/*.tar.gz; do
  ! tar -tzf "${archive}" | grep -q '/.state/secrets/.*_db_password$' \
    || { echo "$(basename "${archive}") contains a database password" >&2; exit 1; }
done
ca_server_template="$(
  tar -xOf "${output_dir}/xipki-production-ca-${version}.tar.gz" \
    "xipki-production-ca-${version}/.state/seed/conf/server.xml"
)"
[[ "${ca_server_template}" == *'__XIPKI_CA_TLS_KEYSTORE_PASSWORD__'* \
  && "${ca_server_template}" != *'fixture-ca-tls'* ]] \
  || { echo 'CA TLS password was not externalized from server.xml' >&2; exit 1; }
gateway_server_template="$(
  tar -xOf "${output_dir}/xipki-production-gateway-${version}.tar.gz" \
    "xipki-production-gateway-${version}/.state/seed/conf/server.xml"
)"
gateway_client_template="$(
  tar -xOf "${output_dir}/xipki-production-gateway-${version}.tar.gz" \
    "xipki-production-gateway-${version}/.state/seed/xipki/etc/gateway.json"
)"
[[ "${gateway_server_template}" == *'__XIPKI_GATEWAY_TLS_KEYSTORE_PASSWORD__'* \
  && "${gateway_server_template}" != *'fixture-gateway-tls'* \
  && "${gateway_client_template}" == *'__XIPKI_GATEWAY_RA_CLIENT_KEYSTORE_PASSWORD__'* \
  && "${gateway_client_template}" != *'fixture-gateway-ra'* ]] \
  || { echo 'Gateway identity passwords were not externalized from runtime configuration' >&2; exit 1; }
ca_database_template="$(
  tar -xOf "${output_dir}/xipki-production-ca-${version}.tar.gz" \
    "xipki-production-ca-${version}/.state/seed/xipki/etc/ca/database/ca-db.properties"
)"
[[ "${ca_database_template}" == *'__XIPKI_DB_HOST__'* \
  && "${ca_database_template}" == *'__XIPKI_DB_USER__'* \
  && "${ca_database_template}" == *'__XIPKI_CA_DB_NAME__'* \
  && "${ca_database_template}" == *'__XIPKI_CA_DB_PASSWORD__'* ]] \
  || { echo "CA bundle does not contain the complete node database template" >&2; exit 1; }

gateway_archive="${output_dir}/xipki-production-gateway-${version}.tar.gz"
gateway_root="xipki-production-gateway-${version}"
[[ -f "${output_dir}/SHA256SUMS" && ! -e "${output_dir}/operator" ]] \
  || { echo "distributed output retained the retired operator package" >&2; exit 1; }
gateway_verification_files="$(
  tar -tzf "${gateway_archive}" \
    | sed -n "s#^${gateway_root}/verification/##p" \
    | grep -v '^$' \
    | sort
)"
expected_gateway_verification_files="$(printf '%s\n' \
  gateway-server-trustanchors.pem \
  rest-client.p12 \
  rest-client.p12.password \
  verify.sh \
  | sort)"
[[ "${gateway_verification_files}" == "${expected_gateway_verification_files}" ]] \
  || { echo "Gateway bundle contains an unexpected verification material set" >&2; exit 1; }
for role in ca console ocsp; do
  ! tar -tzf "${output_dir}/xipki-production-${role}-${version}.tar.gz" \
    | grep -q '/verification/' \
    || { echo "${role} bundle contains Gateway verification material" >&2; exit 1; }
done

extract_dir="${work_dir}/node"
mkdir -p "${extract_dir}"
tar -xzf "${output_dir}/xipki-production-console-${version}.tar.gz" -C "${extract_dir}"
node_dir="${extract_dir}/xipki-production-console-${version}"
grep -q '^XIPKI_DEPLOYMENT_FORMAT=2$' "${node_dir}/manifest.env"
grep -q '^XIPKI_NODE_ROLE=console$' "${node_dir}/manifest.env"
grep -q '^XIPKI_DATABASE=mariadb$' "${node_dir}/manifest.env"
grep -q '^XIPKI_CA_URL=https://ca.internal.example.com:8444/ca/mgmt$' \
  "${node_dir}/node.env"
tar -tzf "${output_dir}/xipki-production-console-${version}.tar.gz" \
  | grep -q '/.state/seed/client/gateway-ra-cert.pem$' \
  || { echo "Console bundle does not contain the Gateway RA public certificate" >&2; exit 1; }
for path in .state/client/admin.p12 .state/client/admin.p12.password; do
  tar -tzf "${output_dir}/xipki-production-console-${version}.tar.gz" \
    | grep -q "/${path}$" \
    || { echo "Console bundle is missing ${path}" >&2; exit 1; }
done
console_credentials="$("${node_dir}/node.sh" credentials)"
[[ "${console_credentials}" == *'Username: admin'* \
  && "${console_credentials}" == *'.state/client/admin.p12'* ]] \
  || { echo "Console node did not report its first-login credentials" >&2; exit 1; }
if PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
  "${node_dir}/node.sh" check >/dev/null 2>&1; then
  echo "node check accepted a missing local database Secret" >&2
  exit 1
fi

printf '%s\n' \
  127.0.0.1 console-db.internal.example.com 3307 console_user console_data \
  19443 password \
  https://ca.internal.example.com:8444/ca/mgmt node-db-pass node-db-pass \
  | PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
    "${node_dir}/node.sh" config >/dev/null
grep -q '^XIPKI_BIND_ADDRESS=127.0.0.1$' "${node_dir}/node.env"
grep -q '^XIPKI_CONSOLE_HTTPS_PORT=19443$' "${node_dir}/node.env"
grep -q '^XIPKI_CONSOLE_AUTH_MODE=password$' "${node_dir}/node.env"
grep -q '^XIPKI_DB_HOST=console-db.internal.example.com$' "${node_dir}/node.env"
grep -q '^XIPKI_DB_PORT=3307$' "${node_dir}/node.env"
grep -q '^XIPKI_DB_USER=console_user$' "${node_dir}/node.env"
grep -q '^XIPKI_CONSOLE_DB_NAME=console_data$' "${node_dir}/node.env"
[[ "$(<"${node_dir}/.state/secrets/console_db_password")" == node-db-pass ]] \
  || { echo "node config did not store the local database Secret" >&2; exit 1; }
! grep -q '^XIPKI_GATEWAY_HTTP_PORT=' "${node_dir}/node.env" \
  || { echo "Console node config contains another role's port" >&2; exit 1; }
node_config="$(${node_dir}/node.sh config show)"
[[ "${node_config}" == *$'console.https.port=19443'* \
  && "${node_config}" == *$'console.auth.mode=password'* \
  && "${node_config}" == *$'console.database.url=jdbc:mariadb://console-db.internal.example.com:3307/console_data'* ]] \
  || { echo "node config show did not report updated values" >&2; exit 1; }
PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
  "${node_dir}/node.sh" config check >/dev/null
doctor_output="$(
  PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
    "${node_dir}/node.sh" doctor
)"
[[ "${doctor_output}" == *'[PASS] database connectivity, authorization, and schema'* \
  && "${doctor_output}" == *'Diagnosis complete: 0 failure(s)'* ]] \
  || { echo "node doctor did not report an actionable successful diagnosis" >&2; exit 1; }
sed -i.bak 's/^XIPKI_CONSOLE_HTTPS_PORT=19443$/XIPKI_CONSOLE_HTTPS_PORT=70000/' \
  "${node_dir}/node.env"
if PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
  "${node_dir}/node.sh" config check >/dev/null 2>&1; then
  echo "node config check accepted an invalid port" >&2
  exit 1
fi
mv "${node_dir}/node.env.bak" "${node_dir}/node.env"

ca_extract_dir="${work_dir}/ca-node"
mkdir -p "${ca_extract_dir}"
tar -xzf "${output_dir}/xipki-production-ca-${version}.tar.gz" -C "${ca_extract_dir}"
ca_node_dir="${ca_extract_dir}/xipki-production-ca-${version}"
printf '%s\n' \
  0.0.0.0 ca-db.internal.example.com 3308 ca_user \
  ca_config ca_cert ca_status ca_keys 8444 \
  'ca-node-pass' 'ca-node-pass' \
  | PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
    "${ca_node_dir}/node.sh" config >/dev/null
PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
  "${ca_node_dir}/node.sh" config check >/dev/null
[[ "$(<"${ca_node_dir}/.state/secrets/ca_db_password")" == ca-node-pass ]] \
  || { echo "CA node did not keep its database Secret locally" >&2; exit 1; }

# The first-run interface must hide the check/pull/preflight/init/up/smoke sequence. A later
# materialized database change must rebuild only generated role state before restarting.
PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
  "${ca_node_dir}/node.sh" setup --no-pull >/dev/null
[[ -s "${ca_node_dir}/.state/materialized-config.cksum" ]] \
  || { echo "node setup did not record its applied runtime configuration" >&2; exit 1; }
grep -q 'XIPKI_DB_CHECK_ROLE=ca' "${docker_log}" \
  || { echo "node setup did not run the role-scoped database preflight" >&2; exit 1; }

# Reset is the repeatable acceptance-test cleanup path: it removes only generated runtime state,
# while an incorrect acknowledgement and a successful reset both preserve package-owned material.
if printf 'WRONG\n' \
  | PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
    "${ca_node_dir}/node.sh" reset >/dev/null 2>&1; then
  echo "node reset accepted an incorrect confirmation" >&2
  exit 1
fi
[[ -s "${ca_node_dir}/.state/seed/.initialized" \
  && -s "${ca_node_dir}/.state/secrets/ca_db_password" ]] \
  || { echo "rejected node reset changed retained material" >&2; exit 1; }
printf 'RESET production ca\n' \
  | PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
    "${ca_node_dir}/node.sh" reset >/dev/null
[[ -s "${ca_node_dir}/.state/seed/.initialized" \
  && -s "${ca_node_dir}/.state/secrets/ca_db_password" ]] \
  || { echo "node reset deleted package-owned material" >&2; exit 1; }
[[ ! -e "${ca_node_dir}/.state/materialized-config.cksum" ]] \
  || { echo "node reset retained a checksum for the deleted runtime volume" >&2; exit 1; }
PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
  "${ca_node_dir}/node.sh" setup --no-pull >/dev/null
[[ -s "${ca_node_dir}/.state/materialized-config.cksum" ]] \
  || { echo "node setup did not recreate runtime state after reset" >&2; exit 1; }
reconciliations_before="$(grep -c 'down --volumes --remove-orphans' "${docker_log}" || true)"
sed -i.bak \
  's/^XIPKI_DB_HOST=ca-db.internal.example.com$/XIPKI_DB_HOST=ca-db-new.internal.example.com/' \
  "${ca_node_dir}/node.env"
PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
  "${ca_node_dir}/node.sh" up --no-pull >/dev/null
reconciliations_after="$(grep -c 'down --volumes --remove-orphans' "${docker_log}" || true)"
(( reconciliations_after > reconciliations_before )) \
  || { echo "node up did not reconcile changed materialized database settings" >&2; exit 1; }
rm "${ca_node_dir}/node.env.bak"

gateway_extract_dir="${work_dir}/gateway-node"
mkdir -p "${gateway_extract_dir}"
tar -xzf "${output_dir}/xipki-production-gateway-${version}.tar.gz" -C "${gateway_extract_dir}"
gateway_node_dir="${gateway_extract_dir}/xipki-production-gateway-${version}"
printf '%s\n' \
  0.0.0.0 gateway-db.internal.example.com 3309 gateway_user \
  gateway_acme gateway.example.com 18082 18445 ocsp.example.com 18080 \
  'gateway-node-pass' 'gateway-node-pass' \
  | PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
    "${gateway_node_dir}/node.sh" config >/dev/null
PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
  "${gateway_node_dir}/node.sh" config check >/dev/null
gateway_node_help="$("${gateway_node_dir}/node.sh" help)"
[[ "${gateway_node_help}" == *'verify          On a Gateway node'* ]] \
  || { echo 'Gateway node bundle does not expose certificate verification' >&2; exit 1; }
rm "${gateway_node_dir}/.state/seed/xipki/keycerts/ra-sdk-client.p12"
if PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
  "${gateway_node_dir}/node.sh" config check >/dev/null 2>&1; then
  echo 'Gateway node check accepted a missing RA SDK client identity' >&2
  exit 1
fi

node_version="$(
  PATH="${fake_bin}:${PATH}" \
  XIPKI_TEST_DOCKER_LOG="${docker_log}" \
  XIPKI_NODE_ROLE=ca \
  "${node_dir}/node.sh" version
)"
[[ "${node_version}" == *$'format=2'* && "${node_version}" == *$'role=console'* ]] \
  || { echo "ambient environment overrode the bundle's pinned role" >&2; exit 1; }

sed -i.bak 's/^XIPKI_DEPLOYMENT_FORMAT=2$/XIPKI_DEPLOYMENT_FORMAT=1/' \
  "${node_dir}/manifest.env"
if PATH="${fake_bin}:${PATH}" XIPKI_TEST_DOCKER_LOG="${docker_log}" \
  "${node_dir}/node.sh" version >/dev/null 2>&1; then
  echo "node launcher accepted an unsupported bundle format" >&2
  exit 1
fi

# A server certificate accidentally generated with clientAuth must stop preparation before the
# invalid role bundles replace the last known-good output.
if PATH="${fake_bin}:${PATH}" \
  XIPKI_TEST_DOCKER_LOG="${docker_log}" \
  XIPKI_BOOTSTRAP_IMAGE=fake/bootstrap:test \
  XIPKI_TEST_BAD_GATEWAY_CERT=true \
  "${fixture_dir}/container.sh" prepare --no-pull >/dev/null 2>&1; then
  echo 'distributed prepare accepted a Gateway server certificate without serverAuth' >&2
  exit 1
fi

import_dir="${work_dir}/imported-identities"
mkdir -p "${import_dir}"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -sha256 \
  -subj '/CN=Imported deployment root' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "${import_dir}/root.key" -out "${import_dir}/root.pem" >/dev/null 2>&1

make_imported_server() {
  local name="$1"
  local host="$2"
  local password="$3"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' \
    "${host}" > "${import_dir}/${name}.ext"
  openssl req -new -newkey rsa:2048 -nodes -sha256 -subj "/CN=${host}" \
    -keyout "${import_dir}/${name}.key" -out "${import_dir}/${name}.csr" >/dev/null 2>&1
  openssl x509 -req -days 30 -sha256 -in "${import_dir}/${name}.csr" \
    -CA "${import_dir}/root.pem" -CAkey "${import_dir}/root.key" -CAcreateserial \
    -extfile "${import_dir}/${name}.ext" -out "${import_dir}/${name}.pem" >/dev/null 2>&1
  openssl pkcs12 -export -name "${name}" -inkey "${import_dir}/${name}.key" \
    -in "${import_dir}/${name}.pem" -certfile "${import_dir}/root.pem" \
    -passout "pass:${password}" -out "${import_dir}/${name}.p12" >/dev/null 2>&1
}

make_imported_server ca-server ca.internal.example.com import-ca-pass-1
make_imported_server gateway-server gateway.example.com import-gateway-pass-1
printf '%s\n' import-ca-pass-1 import-ca-pass-1 \
  | "${fixture_dir}/container.sh" certificates import ca-server \
    "${import_dir}/ca-server.p12" "${import_dir}/root.pem" >/dev/null
printf '%s\n' import-gateway-pass-1 import-gateway-pass-1 \
  | "${fixture_dir}/container.sh" certificates import gateway-server \
    "${import_dir}/gateway-server.p12" "${import_dir}/root.pem" >/dev/null
make_imported_server wrong-gateway wrong.example.com rejected-pass-1
gateway_override_checksum="$(cksum \
  < "${fixture_dir}/.state/deployments/production/certificate-overrides/gateway-server/identity.p12")"
if printf '%s\n' rejected-pass-1 rejected-pass-1 \
  | "${fixture_dir}/container.sh" certificates import gateway-server \
    "${import_dir}/wrong-gateway.p12" "${import_dir}/root.pem" >/dev/null 2>&1; then
  echo 'certificate import accepted a Gateway SAN for another host' >&2
  exit 1
fi
[[ "$(cksum \
  < "${fixture_dir}/.state/deployments/production/certificate-overrides/gateway-server/identity.p12")" \
  == "${gateway_override_checksum}" ]] \
  || { echo 'failed certificate import replaced the previous valid identity' >&2; exit 1; }
if compgen -G "${fixture_dir}/.state/deployments/production/certificate-overrides/.gateway-server.*" \
    >/dev/null; then
  echo 'failed certificate import left private temporary material behind' >&2
  exit 1
fi
certificate_modes="$("${fixture_dir}/container.sh" certificates show)"
[[ "${certificate_modes}" == *$'ca-server=imported'* \
  && "${certificate_modes}" == *$'gateway-server=imported'* ]] \
  || { echo 'certificate override state was not reported' >&2; exit 1; }
PATH="${fake_bin}:${PATH}" \
XIPKI_TEST_DOCKER_LOG="${docker_log}" \
XIPKI_BOOTSTRAP_IMAGE=fake/bootstrap:test \
"${fixture_dir}/container.sh" prepare --no-pull >/dev/null

imported_gateway_cert="$(
  tar -xOf "${output_dir}/xipki-production-gateway-${version}.tar.gz" \
    "xipki-production-gateway-${version}/.state/seed/xipki/keycerts/gateway-server-cert.pem" \
    | openssl x509 -noout -fingerprint -sha256
)"
source_gateway_cert="$(
  openssl x509 -in "${import_dir}/gateway-server.pem" -noout -fingerprint -sha256
)"
[[ "${imported_gateway_cert}" == "${source_gateway_cert}" ]] \
  || { echo 'imported Gateway server identity was not packaged' >&2; exit 1; }
[[ "$(tar -xOf "${output_dir}/xipki-production-ca-${version}.tar.gz" \
  "xipki-production-ca-${version}/.state/secrets/ca_tls_keystore_password")" \
  == import-ca-pass-1 ]] \
  || { echo 'imported CA password was not packaged as a file-backed Secret' >&2; exit 1; }
packaged_ca_anchor="$(
  tar -xOf "${output_dir}/xipki-production-console-${version}.tar.gz" \
    "xipki-production-console-${version}/.state/seed/client/trustanchors.pem" \
    | openssl x509 -noout -fingerprint -sha256
)"
source_ca_anchor="$(openssl x509 -in "${import_dir}/root.pem" -noout -fingerprint -sha256)"
[[ "${packaged_ca_anchor}" == "${source_ca_anchor}" ]] \
  || { echo 'imported CA trust anchor was not propagated to Console' >&2; exit 1; }
gateway_verification_anchor="$(
  tar -xOf "${output_dir}/xipki-production-gateway-${version}.tar.gz" \
    "xipki-production-gateway-${version}/verification/gateway-server-trustanchors.pem" \
    | openssl x509 -noout -fingerprint -sha256
)"
[[ "${gateway_verification_anchor}" == "${source_ca_anchor}" ]] \
  || { echo 'imported Gateway trust anchor was not propagated to verification' >&2; exit 1; }

echo "xipki distributed bundle tests passed"
