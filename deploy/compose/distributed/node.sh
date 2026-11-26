#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest_file="${script_dir}/manifest.env"
node_config_file="${script_dir}/node.env"
state_dir="${script_dir}/.state"

fail() {
  printf 'xipki-node: %s\n' "$*" >&2
  exit 1
}

# Loads a generated settings file without executing it as shell code. Manifest values are always
# authoritative, while node settings are isolated to the explicitly supported runtime surface.
load_settings() {
  local settings_file="$1"
  local scope="$2"
  local line key value line_number=0
  [[ -r "${settings_file}" ]] || fail "node settings are missing: ${settings_file}"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line_number=$((line_number + 1))
    line="${line%$'\r'}"
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    [[ "${line}" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] \
      || fail "${settings_file}:${line_number}: expected KEY=VALUE"
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    case "${scope}:${key}" in
      manifest:XIPKI_DEPLOYMENT_FORMAT|manifest:XIPKI_DEPLOYMENT_NAME|\
      manifest:XIPKI_NODE_ROLE|manifest:XIPKI_COMPOSE_PROJECT|\
      manifest:XIPKI_IMAGE_PREFIX|manifest:XIPKI_VERSION|manifest:XIPKI_DATABASE|\
      node:XIPKI_BIND_ADDRESS|node:XIPKI_DB_HOST|node:XIPKI_DB_PORT|node:XIPKI_DB_USER|\
      node:XIPKI_CACONF_DB_NAME|node:XIPKI_CA_DB_NAME|node:XIPKI_OCSP_DB_NAME|\
      node:XIPKI_KEYPOOL_DB_NAME|node:XIPKI_ACME_DB_NAME|node:XIPKI_CONSOLE_DB_NAME|\
      node:XIPKI_CA_HTTPS_PORT|\
      node:XIPKI_GATEWAY_HOST|node:XIPKI_OCSP_HOST|\
      node:XIPKI_CONSOLE_HTTPS_PORT|node:XIPKI_GATEWAY_HTTP_PORT|\
      node:XIPKI_GATEWAY_HTTPS_PORT|node:XIPKI_OCSP_HTTP_PORT|\
      node:XIPKI_CONSOLE_AUTH_MODE|node:XIPKI_CA_URL) ;;
      *) fail "${settings_file}:${line_number}: unsupported ${scope} setting ${key}" ;;
    esac
    # Bundle files are authoritative so ambient shell values cannot silently change a reviewed
    # role, image, endpoint, or port for only one invocation.
    printf -v "${key}" '%s' "${value}"
    export "${key}"
  done < "${settings_file}"
}

load_settings "${manifest_file}" manifest
load_settings "${node_config_file}" node
readonly deployment_format="${XIPKI_DEPLOYMENT_FORMAT:?missing XIPKI_DEPLOYMENT_FORMAT}"
readonly deployment_name="${XIPKI_DEPLOYMENT_NAME:?missing XIPKI_DEPLOYMENT_NAME}"
readonly role="${XIPKI_NODE_ROLE:?missing XIPKI_NODE_ROLE}"
readonly project_name="${XIPKI_COMPOSE_PROJECT:-${deployment_name}-${role}}"
readonly database="${XIPKI_DATABASE:?missing XIPKI_DATABASE}"
[[ "${deployment_format}" == "2" ]] \
  || fail "unsupported node bundle format: ${deployment_format} (expected 2)"
case "${role}" in
  ca|console|gateway|ocsp) ;;
  *) fail "unsupported node role: ${role}" ;;
esac
case "${database}" in
  mariadb)
    readonly database_jdbc_scheme=mariadb
    ;;
  postgres)
    readonly database_jdbc_scheme=postgresql
    ;;
  *) fail "unsupported database engine: ${database}" ;;
esac
if [[ "${role}" == "console" ]]; then
  export XIPKI_CONSOLE_DB_URL="jdbc:${database_jdbc_scheme}://${XIPKI_DB_HOST}:${XIPKI_DB_PORT}/${XIPKI_CONSOLE_DB_NAME}"
fi
readonly compose_file="${script_dir}/compose.yaml"
readonly bootstrap_image="${XIPKI_IMAGE_PREFIX}/bootstrap:${XIPKI_VERSION}"
compose=(docker compose --project-name "${project_name}" -f "${compose_file}")

usage() {
  cat <<'EOF'
Usage: ./node.sh COMMAND [ARGS]

Commands:
  setup [--no-pull]
                  Configure the missing Secret, verify the database, and start this node
  doctor          Diagnose configuration, Docker, database, image, and runtime readiness
  config          Interactively update this node's non-secret settings
  config show     Show the effective manifest and non-secret settings
  config check    Validate settings, role material, and Docker Compose
  check           Validate this role bundle and Docker Compose
  up [--no-pull]  Verify the database, then pull images and start this node
  pull            Pull the pinned application and database-check images
  status          Show this node's containers
  credentials     On a Console node, show the generated first-login credentials
  logs            Follow this node's logs
  smoke           Wait for the role container to become healthy
  verify          On a Gateway node, issue and revoke a certificate and verify both OCSP states
  restart         Restart this role and wait for health
  down            Stop this node while retaining its volume and seed
  reset           Delete this node's generated runtime volume, retaining its package and Secrets
  purge           Permanently erase this node's volume and local role material
  version         Show the pinned deployment, role, and image
EOF
}

require_compose() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
}

# Prompts for one non-secret node setting, retaining the current value on empty input.
prompt_value() {
  local label="$1"
  local current_value="$2"
  local entered
  printf '%s [%s]: ' "${label}" "${current_value}" >&2
  IFS= read -r entered || fail "configuration input was cancelled"
  prompt_result="${entered:-${current_value}}"
}

# Prompts until a closed setting matches one of its supported values.
prompt_choice() {
  local label="$1"
  local current_value="$2"
  shift 2
  local allowed
  while true; do
    prompt_value "${label} ($*)" "${current_value}"
    for allowed in "$@"; do
      [[ "${prompt_result}" == "${allowed}" ]] && return
    done
    printf 'Unsupported value: %s. Expected one of: %s\n' "${prompt_result}" "$*" >&2
  done
}

# Creates the role's database Secret locally. Existing credentials are kept because coordinated
# password rotation of an already materialized role volume is outside the first-release contract.
configure_database_secret() {
  local secret_dir="${state_dir}/secrets"
  local target="${secret_dir}/${role}_db_password"
  local first second temporary
  install -d -m 0700 "${secret_dir}"
  if [[ -s "${target}" ]]; then
    printf '%s database password is already configured and was kept.\n' "${role}" >&2
    return
  fi
  while true; do
    printf '%s database password: ' "${role}" >&2
    IFS= read -r -s first || fail "configuration input was cancelled"
    printf '\nConfirm %s database password: ' "${role}" >&2
    IFS= read -r -s second || fail "configuration input was cancelled"
    printf '\n' >&2
    if [[ -z "${first}" ]]; then
      echo 'Password must not be empty.' >&2
    elif [[ "${first}" != "${second}" ]]; then
      echo 'Passwords did not match; try again.' >&2
    else
      break
    fi
  done
  temporary="$(mktemp "${secret_dir}/.${role}_db_password.XXXXXX")"
  printf '%s' "${first}" > "${temporary}"
  # The owner-only directory protects the host copy; read-only world access lets the fixed
  # non-root container UID consume Docker Compose's file-backed Secret on Linux hosts.
  chmod 0444 "${temporary}"
  mv "${temporary}" "${target}"
}

# Rejects malformed port values before Compose interpolates them into a published-port mapping.
validate_port() {
  local name="$1"
  local value="$2"
  [[ "${value}" =~ ^[0-9]+$ && "${value}" -ge 1 && "${value}" -le 65535 ]] \
    || fail "${name} must be a number from 1 to 65535"
}

# Keeps identifiers portable across MariaDB and PostgreSQL and safe for generated JDBC settings.
validate_database_identifier() {
  local name="$1"
  local value="$2"
  [[ "${value}" =~ ^[A-Za-z][A-Za-z0-9_]{0,62}$ ]] \
    || fail "${name} must start with a letter and contain at most 63 letters, digits, or underscores"
}

# Accepts the DNS-name or IPv4 endpoint forms supported by generated TLS and node settings.
validate_host() {
  local name="$1"
  local value="$2"
  [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
    || fail "${name} must be a DNS name or IPv4 address"
}

# Validates only the node-local settings consumed by this role.
validate_node_configuration() {
  local octet
  [[ "${XIPKI_BIND_ADDRESS:-}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] \
    || fail "XIPKI_BIND_ADDRESS must be an IPv4 address"
  local IFS=.
  for octet in ${XIPKI_BIND_ADDRESS}; do
    (( 10#${octet} <= 255 )) || fail "XIPKI_BIND_ADDRESS must be an IPv4 address"
  done
  [[ "${XIPKI_DB_HOST:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
    || fail "XIPKI_DB_HOST must be a DNS name or IPv4 address"
  validate_port XIPKI_DB_PORT "${XIPKI_DB_PORT:-}"
  validate_database_identifier XIPKI_DB_USER "${XIPKI_DB_USER:-}"
  case "${role}" in
    ca)
      validate_database_identifier XIPKI_CACONF_DB_NAME "${XIPKI_CACONF_DB_NAME:-}"
      validate_database_identifier XIPKI_CA_DB_NAME "${XIPKI_CA_DB_NAME:-}"
      validate_database_identifier XIPKI_OCSP_DB_NAME "${XIPKI_OCSP_DB_NAME:-}"
      validate_database_identifier XIPKI_KEYPOOL_DB_NAME "${XIPKI_KEYPOOL_DB_NAME:-}"
      validate_port XIPKI_CA_HTTPS_PORT "${XIPKI_CA_HTTPS_PORT:-}"
      ;;
    console)
      validate_port XIPKI_CONSOLE_HTTPS_PORT "${XIPKI_CONSOLE_HTTPS_PORT:-}"
      case "${XIPKI_CONSOLE_AUTH_MODE:-}" in
        password|certificate|both) ;;
        *) fail "XIPKI_CONSOLE_AUTH_MODE must be password, certificate, or both" ;;
      esac
      validate_database_identifier XIPKI_CONSOLE_DB_NAME "${XIPKI_CONSOLE_DB_NAME:-}"
      [[ "${XIPKI_CA_URL:-}" == https://*/ca/mgmt ]] \
        || fail "XIPKI_CA_URL must be an HTTPS /ca/mgmt URL"
      [[ "${XIPKI_CA_URL}" != *[[:space:]]* ]] \
        || fail "XIPKI_CA_URL must not contain whitespace"
      ;;
    gateway)
      validate_database_identifier XIPKI_ACME_DB_NAME "${XIPKI_ACME_DB_NAME:-}"
      validate_host XIPKI_GATEWAY_HOST "${XIPKI_GATEWAY_HOST:-}"
      validate_port XIPKI_GATEWAY_HTTP_PORT "${XIPKI_GATEWAY_HTTP_PORT:-}"
      validate_port XIPKI_GATEWAY_HTTPS_PORT "${XIPKI_GATEWAY_HTTPS_PORT:-}"
      validate_host XIPKI_OCSP_HOST "${XIPKI_OCSP_HOST:-}"
      validate_port XIPKI_OCSP_HTTP_PORT "${XIPKI_OCSP_HTTP_PORT:-}"
      ;;
    ocsp)
      validate_database_identifier XIPKI_CA_DB_NAME "${XIPKI_CA_DB_NAME:-}"
      validate_database_identifier XIPKI_OCSP_DB_NAME "${XIPKI_OCSP_DB_NAME:-}"
      validate_port XIPKI_OCSP_HTTP_PORT "${XIPKI_OCSP_HTTP_PORT:-}"
      ;;
  esac
}

# Atomically stores the supported settings for this role; Secret values never enter node.env.
write_node_configuration() {
  local temporary
  temporary="$(mktemp "${script_dir}/.node.env.XXXXXX")"
  {
    echo '# Generated by ./node.sh config. Secrets are stored under .state/secrets/.'
    printf 'XIPKI_BIND_ADDRESS=%s\n' "${XIPKI_BIND_ADDRESS}"
    printf 'XIPKI_DB_HOST=%s\n' "${XIPKI_DB_HOST}"
    printf 'XIPKI_DB_PORT=%s\n' "${XIPKI_DB_PORT}"
    printf 'XIPKI_DB_USER=%s\n' "${XIPKI_DB_USER}"
    case "${role}" in
      ca)
        printf 'XIPKI_CACONF_DB_NAME=%s\n' "${XIPKI_CACONF_DB_NAME}"
        printf 'XIPKI_CA_DB_NAME=%s\n' "${XIPKI_CA_DB_NAME}"
        printf 'XIPKI_OCSP_DB_NAME=%s\n' "${XIPKI_OCSP_DB_NAME}"
        printf 'XIPKI_KEYPOOL_DB_NAME=%s\n' "${XIPKI_KEYPOOL_DB_NAME}"
        printf 'XIPKI_CA_HTTPS_PORT=%s\n' "${XIPKI_CA_HTTPS_PORT}"
        ;;
      console)
        printf 'XIPKI_CONSOLE_DB_NAME=%s\n' "${XIPKI_CONSOLE_DB_NAME}"
        printf 'XIPKI_CONSOLE_HTTPS_PORT=%s\n' "${XIPKI_CONSOLE_HTTPS_PORT}"
        printf 'XIPKI_CONSOLE_AUTH_MODE=%s\n' "${XIPKI_CONSOLE_AUTH_MODE}"
        printf 'XIPKI_CA_URL=%s\n' "${XIPKI_CA_URL}"
        ;;
      gateway)
        printf 'XIPKI_ACME_DB_NAME=%s\n' "${XIPKI_ACME_DB_NAME}"
        printf 'XIPKI_GATEWAY_HOST=%s\n' "${XIPKI_GATEWAY_HOST}"
        printf 'XIPKI_GATEWAY_HTTP_PORT=%s\n' "${XIPKI_GATEWAY_HTTP_PORT}"
        printf 'XIPKI_GATEWAY_HTTPS_PORT=%s\n' "${XIPKI_GATEWAY_HTTPS_PORT}"
        printf 'XIPKI_OCSP_HOST=%s\n' "${XIPKI_OCSP_HOST}"
        printf 'XIPKI_OCSP_HTTP_PORT=%s\n' "${XIPKI_OCSP_HTTP_PORT}"
        ;;
      ocsp)
        printf 'XIPKI_CA_DB_NAME=%s\n' "${XIPKI_CA_DB_NAME}"
        printf 'XIPKI_OCSP_DB_NAME=%s\n' "${XIPKI_OCSP_DB_NAME}"
        printf 'XIPKI_OCSP_HTTP_PORT=%s\n' "${XIPKI_OCSP_HTTP_PORT}"
        ;;
    esac
  } > "${temporary}"
  chmod 0600 "${temporary}"
  mv "${temporary}" "${node_config_file}"
}

# Provides the node operator's interactive configuration flow without exposing identity fields.
configure_node() {
  prompt_value "Bind address" "${XIPKI_BIND_ADDRESS}"
  XIPKI_BIND_ADDRESS="${prompt_result}"
  prompt_value "Database host" "${XIPKI_DB_HOST}"
  XIPKI_DB_HOST="${prompt_result}"
  prompt_value "Database port" "${XIPKI_DB_PORT}"
  XIPKI_DB_PORT="${prompt_result}"
  prompt_value "Database user" "${XIPKI_DB_USER}"
  XIPKI_DB_USER="${prompt_result}"
  case "${role}" in
    ca)
      prompt_value "CA configuration database name" "${XIPKI_CACONF_DB_NAME}"
      XIPKI_CACONF_DB_NAME="${prompt_result}"
      prompt_value "CA certificate database name" "${XIPKI_CA_DB_NAME}"
      XIPKI_CA_DB_NAME="${prompt_result}"
      prompt_value "OCSP database name" "${XIPKI_OCSP_DB_NAME}"
      XIPKI_OCSP_DB_NAME="${prompt_result}"
      prompt_value "Key pool database name" "${XIPKI_KEYPOOL_DB_NAME}"
      XIPKI_KEYPOOL_DB_NAME="${prompt_result}"
      prompt_value "CA HTTPS port" "${XIPKI_CA_HTTPS_PORT}"
      XIPKI_CA_HTTPS_PORT="${prompt_result}"
      ;;
    console)
      prompt_value "Console database name" "${XIPKI_CONSOLE_DB_NAME}"
      XIPKI_CONSOLE_DB_NAME="${prompt_result}"
      prompt_value "Console HTTPS port" "${XIPKI_CONSOLE_HTTPS_PORT}"
      XIPKI_CONSOLE_HTTPS_PORT="${prompt_result}"
      prompt_choice "Console authentication mode" "${XIPKI_CONSOLE_AUTH_MODE}" \
        password certificate both
      XIPKI_CONSOLE_AUTH_MODE="${prompt_result}"
      prompt_value "CA management URL" "${XIPKI_CA_URL}"
      XIPKI_CA_URL="${prompt_result}"
      ;;
    gateway)
      prompt_value "ACME database name" "${XIPKI_ACME_DB_NAME}"
      XIPKI_ACME_DB_NAME="${prompt_result}"
      prompt_value "Gateway verification host" "${XIPKI_GATEWAY_HOST}"
      XIPKI_GATEWAY_HOST="${prompt_result}"
      prompt_value "Gateway HTTP port" "${XIPKI_GATEWAY_HTTP_PORT}"
      XIPKI_GATEWAY_HTTP_PORT="${prompt_result}"
      prompt_value "Gateway HTTPS port" "${XIPKI_GATEWAY_HTTPS_PORT}"
      XIPKI_GATEWAY_HTTPS_PORT="${prompt_result}"
      prompt_value "OCSP verification host" "${XIPKI_OCSP_HOST}"
      XIPKI_OCSP_HOST="${prompt_result}"
      prompt_value "OCSP HTTP port" "${XIPKI_OCSP_HTTP_PORT}"
      XIPKI_OCSP_HTTP_PORT="${prompt_result}"
      ;;
    ocsp)
      prompt_value "CA certificate database name" "${XIPKI_CA_DB_NAME}"
      XIPKI_CA_DB_NAME="${prompt_result}"
      prompt_value "OCSP database name" "${XIPKI_OCSP_DB_NAME}"
      XIPKI_OCSP_DB_NAME="${prompt_result}"
      prompt_value "OCSP HTTP port" "${XIPKI_OCSP_HTTP_PORT}"
      XIPKI_OCSP_HTTP_PORT="${prompt_result}"
      ;;
  esac
  validate_node_configuration
  write_node_configuration
  configure_database_secret
  printf 'XiPKI %s node configuration was updated. Run ./node.sh setup to apply it.\n' "${role}"
}

# Displays immutable identity and non-secret runtime values without reading Secret files.
show_node_configuration() {
  printf 'format=%s\ndeployment=%s\nrole=%s\nimage=%s/xipki:%s\n' \
    "${deployment_format}" "${deployment_name}" "${role}" \
    "${XIPKI_IMAGE_PREFIX}" "${XIPKI_VERSION}"
  printf 'bind.address=%s\n' "${XIPKI_BIND_ADDRESS}"
  printf 'database.engine=%s\ndatabase.host=%s\ndatabase.port=%s\ndatabase.user=%s\n' \
    "${database}" "${XIPKI_DB_HOST}" "${XIPKI_DB_PORT}" "${XIPKI_DB_USER}"
  if [[ -s "${state_dir}/secrets/${role}_db_password" ]]; then
    echo 'database.password=configured'
  else
    echo 'database.password=missing'
  fi
  case "${role}" in
    ca)
      printf 'database.caconf=%s\ndatabase.ca=%s\ndatabase.ocsp=%s\ndatabase.keypool=%s\nca.https.port=%s\n' \
        "${XIPKI_CACONF_DB_NAME}" "${XIPKI_CA_DB_NAME}" "${XIPKI_OCSP_DB_NAME}" \
        "${XIPKI_KEYPOOL_DB_NAME}" "${XIPKI_CA_HTTPS_PORT}"
      ;;
    console)
      printf 'database.console=%s\nconsole.https.port=%s\nconsole.auth.mode=%s\nconsole.database.url=%s\nca.url=%s\n' \
        "${XIPKI_CONSOLE_DB_NAME}" \
        "${XIPKI_CONSOLE_HTTPS_PORT}" "${XIPKI_CONSOLE_AUTH_MODE}" \
        "${XIPKI_CONSOLE_DB_URL}" "${XIPKI_CA_URL}"
      ;;
    gateway)
      printf 'database.acme=%s\ngateway.host=%s\ngateway.http.port=%s\ngateway.https.port=%s\nocsp.host=%s\nocsp.http.port=%s\n' \
        "${XIPKI_ACME_DB_NAME}" "${XIPKI_GATEWAY_HOST}" \
        "${XIPKI_GATEWAY_HTTP_PORT}" "${XIPKI_GATEWAY_HTTPS_PORT}" \
        "${XIPKI_OCSP_HOST}" "${XIPKI_OCSP_HTTP_PORT}"
      ;;
    ocsp)
      printf 'database.ca=%s\ndatabase.ocsp=%s\nocsp.http.port=%s\n' \
        "${XIPKI_CA_DB_NAME}" "${XIPKI_OCSP_DB_NAME}" "${XIPKI_OCSP_HTTP_PORT}"
      ;;
  esac
}

# Requires one role-owned runtime artifact before Compose can materialize the immutable seed into
# its private volume. This reports incomplete or mixed bundles before a container starts.
require_role_material() {
  local relative_path="$1"
  [[ -s "${state_dir}/seed/${relative_path}" ]] \
    || fail "${role} role material is missing: ${relative_path}"
}

# Requires one role-owned Secret without reading or reporting its value.
require_role_secret() {
  local secret_name="$1"
  [[ -s "${state_dir}/secrets/${secret_name}" ]] \
    || fail "${role} role Secret is missing: ${secret_name}"
}

# Checks the minimum identity and configuration set owned by the role. Private keys are checked
# only for presence here; their EKU, SAN, separation, and trust chain were verified by prepare.
validate_role_material() {
  case "${role}" in
    ca)
      require_role_material conf/server.xml
      require_role_material xipki/keycerts/ca-server.p12
      require_role_material xipki/keycerts/ca-client-certstore.p12
      require_role_material xipki/keycerts/ca-mgmt-client-cert.pem
      require_role_secret ca_tls_keystore_password
      ;;
    console)
      local required
      for required in \
        secrets/console_admin_password \
        secrets/console_enrollment_key secrets/console_tls_cert.pem \
        secrets/console_tls_key.pem client/console-client-ca.crt client/admin.crt \
        client/admin.p12 client/admin.p12.password; do
        [[ -s "${state_dir}/${required}" ]] || fail "Console material is missing: ${required}"
      done
      require_role_material client/client.p12
      require_role_material client/trustanchors.pem
      require_role_material client/password
      require_role_material client/gateway-ra-cert.pem
      ;;
    gateway)
      require_role_material conf/server.xml
      require_role_material xipki/etc/gateway.json
      require_role_material xipki/keycerts/gateway-server.p12
      require_role_material xipki/keycerts/ra-sdk-client.p12
      require_role_material xipki/keycerts/ca-server-cert.pem
      require_role_material xipki/keycerts/gateway-client-ca-certstore.p12
      require_role_secret gateway_tls_keystore_password
      require_role_secret gateway_ra_client_keystore_password
      ;;
    ocsp)
      require_role_material conf/server.xml
      require_role_material xipki/keycerts/ocsp1.p12
      ;;
  esac
}

# Validates the immutable role seed and every additional Secret required by this role.
check_node() {
  local recorded_format recorded_role
  validate_node_configuration
  [[ -s "${state_dir}/secrets/${role}_db_password" ]] \
    || fail "database Secret is missing; run ./node.sh config"
  [[ -r "${state_dir}/seed/.initialized" ]] || fail "role seed marker is missing"
  recorded_format="$(sed -n 's/^format=//p' "${state_dir}/seed/.initialized")"
  [[ "${recorded_format}" == "1" ]] \
    || fail "unsupported role seed format: ${recorded_format:-missing}"
  recorded_role="$(sed -n 's/^role=//p' "${state_dir}/seed/.initialized")"
  [[ "${recorded_role}" == "${role}" ]] \
    || fail "role seed contains ${recorded_role:-no role}, expected ${role}"
  validate_role_material
  require_compose
  "${compose[@]}" config --quiet
  printf 'XiPKI %s node bundle is valid.\n' "${role}"
}

# Uses the existing Bootstrap JDBC checker against only this role's databases and credential.
# The Secret is mounted as a file and never copied into the environment or command arguments.
database_preflight() {
  local secret_file="${state_dir}/secrets/${role}_db_password"
  local -a arguments
  [[ -s "${secret_file}" ]] || fail "database Secret is missing; run ./node.sh setup"
  arguments=(
    docker run --rm --pull never
    -e XIPKI_BOOTSTRAP_MODE=check
    -e XIPKI_DEPLOYMENT_MODE=distributed
    -e XIPKI_DATABASE_MODE=external
    -e "XIPKI_DATABASE=${database}"
    -e "XIPKI_DB_CHECK_ROLE=${role}"
    -e "XIPKI_DB_HOST=${XIPKI_DB_HOST}"
    -e "XIPKI_DB_PORT=${XIPKI_DB_PORT}"
    -e "XIPKI_DB_USER=${XIPKI_DB_USER}"
    --mount "type=bind,source=${secret_file},target=/run/secrets/${role}_db_password,readonly"
  )
  case "${role}" in
    ca)
      arguments+=(
        -e "XIPKI_CACONF_DB_NAME=${XIPKI_CACONF_DB_NAME}"
        -e "XIPKI_CA_DB_NAME=${XIPKI_CA_DB_NAME}"
        -e "XIPKI_OCSP_DB_NAME=${XIPKI_OCSP_DB_NAME}"
        -e "XIPKI_KEYPOOL_DB_NAME=${XIPKI_KEYPOOL_DB_NAME}")
      ;;
    console)
      arguments+=(-e "XIPKI_CONSOLE_DB_NAME=${XIPKI_CONSOLE_DB_NAME}")
      ;;
    gateway)
      arguments+=(-e "XIPKI_ACME_DB_NAME=${XIPKI_ACME_DB_NAME}")
      ;;
    ocsp)
      arguments+=(
        -e "XIPKI_CA_DB_NAME=${XIPKI_CA_DB_NAME}"
        -e "XIPKI_OCSP_DB_NAME=${XIPKI_OCSP_DB_NAME}")
      ;;
  esac
  arguments+=("${bootstrap_image}")
  "${arguments[@]}"
}

# Produces a non-secret fingerprint of values materialized into the private role volume. Runtime
# settings such as bind ports are intentionally excluded because Compose applies them directly.
materialized_configuration_fingerprint() {
  case "${role}" in
    ca)
      printf '%s\n' "${role}" "${XIPKI_DB_HOST}" "${XIPKI_DB_PORT}" "${XIPKI_DB_USER}" \
        "${XIPKI_CACONF_DB_NAME}" "${XIPKI_CA_DB_NAME}" "${XIPKI_OCSP_DB_NAME}" \
        "${XIPKI_KEYPOOL_DB_NAME}"
      ;;
    gateway)
      printf '%s\n' "${role}" "${XIPKI_DB_HOST}" "${XIPKI_DB_PORT}" "${XIPKI_DB_USER}" \
        "${XIPKI_ACME_DB_NAME}"
      ;;
    ocsp)
      printf '%s\n' "${role}" "${XIPKI_DB_HOST}" "${XIPKI_DB_PORT}" "${XIPKI_DB_USER}" \
        "${XIPKI_CA_DB_NAME}" "${XIPKI_OCSP_DB_NAME}"
      ;;
  esac | cksum | awk '{print $1 ":" $2}'
}

# Recreates only generated runtime configuration when a materialized database setting changes.
# Certificate seeds and the external business databases remain untouched; Console consumes its
# database settings directly and therefore never needs this reconciliation.
reconcile_materialized_state() {
  local fingerprint_file="${state_dir}/materialized-config.cksum"
  local expected recorded=""
  [[ "${role}" != "console" ]] || return 0
  expected="$(materialized_configuration_fingerprint)"
  [[ -r "${fingerprint_file}" ]] && recorded="$(<"${fingerprint_file}")"
  [[ "${recorded}" == "${expected}" ]] && return 0

  if [[ -n "${recorded}" ]]; then
    printf 'Database configuration changed; rebuilding generated %s runtime state.\n' "${role}"
  else
    printf 'Preparing generated %s runtime state.\n' "${role}"
  fi
  # The role volume contains generated configuration, not the external CA/OCSP business data.
  # Taking the role down first prevents a running process from observing a partially replaced tree.
  "${compose[@]}" down --volumes --remove-orphans
  rm -f -- "${fingerprint_file}"
}

# Records the applied materialized configuration only after the role becomes healthy. A failed
# startup therefore remains retryable and cannot make stale state appear current.
record_materialized_state() {
  local fingerprint_file="${state_dir}/materialized-config.cksum"
  local temporary
  [[ "${role}" != "console" ]] || return 0
  temporary="$(mktemp "${state_dir}/.materialized-config.XXXXXX")"
  materialized_configuration_fingerprint > "${temporary}"
  chmod 0600 "${temporary}"
  mv "${temporary}" "${fingerprint_file}"
}

# Prints the role endpoint after a successful setup so a first-time operator knows what to do next.
show_next_step() {
  case "${role}" in
    ca) printf 'CA management endpoint: https://%s:%s/ca/mgmt\n' \
      "${XIPKI_BIND_ADDRESS}" "${XIPKI_CA_HTTPS_PORT}" ;;
    console) printf 'Open Console: https://%s:%s/\n' \
      "${XIPKI_BIND_ADDRESS}" "${XIPKI_CONSOLE_HTTPS_PORT}" ;;
    gateway) printf 'Gateway HTTPS endpoint: https://%s:%s/\n' \
      "${XIPKI_BIND_ADDRESS}" "${XIPKI_GATEWAY_HTTPS_PORT}" ;;
    ocsp) printf 'OCSP endpoint: http://%s:%s/ocsp/\n' \
      "${XIPKI_BIND_ADDRESS}" "${XIPKI_OCSP_HTTP_PORT}" ;;
  esac
}

# Waits for the local role's image health check and reports terminal container failures early.
wait_for_health() {
  local deadline=$((SECONDS + ${XIPKI_NODE_START_TIMEOUT:-180}))
  local container_id health state
  while (( SECONDS < deadline )); do
    container_id="$("${compose[@]}" ps -q "${role}")"
    if [[ -n "${container_id}" ]]; then
      health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' \
        "${container_id}")"
      state="$(docker inspect --format '{{.State.Status}}' "${container_id}")"
      [[ "${health}" == "healthy" ]] && {
        printf 'XiPKI %s node is healthy.\n' "${role}"
        return
      }
      [[ "${state}" == "exited" || "${state}" == "dead" ]] \
        && fail "${role} container entered terminal state ${state}"
    fi
    sleep 2
  done
  fail "${role} did not become healthy within ${XIPKI_NODE_START_TIMEOUT:-180} seconds"
}

# Exposes the Gateway bundle's complete issuance-to-revocation check behind one node command.
verify_gateway_certificate_lifecycle() {
  local verifier="${script_dir}/verification/verify.sh"
  [[ "${role}" == "gateway" ]] || fail "verify is available only in the Gateway node bundle"
  validate_node_configuration
  [[ -x "${verifier}" ]] || fail "Gateway verification script is missing or not executable"
  require_compose
  wait_for_health
  "${verifier}"
}

# Shows the Console handoff values without copying them into another node or generated package.
show_console_credentials() {
  [[ "${role}" == "console" ]] || fail "credentials are available only in the Console node bundle"
  printf 'Console URL: https://%s:%s/\n' "${XIPKI_BIND_ADDRESS}" "${XIPKI_CONSOLE_HTTPS_PORT}"
  printf 'Username: admin\nPassword: '
  cat "${state_dir}/secrets/console_admin_password"
  printf '\nClient certificate: %s\nClient certificate password: ' \
    "${state_dir}/client/admin.p12"
  cat "${state_dir}/client/admin.p12.password"
  printf '\n'
}

# Starts exactly the role pinned in this bundle; role-init copies the seed into its private volume.
start_node() {
  local pull_images=true
  if [[ "${1:-}" == "--no-pull" ]]; then
    pull_images=false
    shift
  fi
  [[ $# -eq 0 ]] || fail "unknown up option: $1"
  check_node
  if [[ "${pull_images}" == "true" ]]; then
    "${compose[@]}" pull
    docker pull "${bootstrap_image}"
  fi
  # Validate the proposed database target before replacing generated runtime configuration. A
  # typo therefore leaves the last healthy role volume and process available for inspection.
  database_preflight
  reconcile_materialized_state
  "${compose[@]}" up -d --no-build --pull never
  wait_for_health
  record_materialized_state
}

# Provides the first-run happy path: keep the prepared node settings, ask only for the missing
# role database Secret, prove the DBA handoff, then start and explain the resulting endpoint.
setup_node() {
  local -a start_options=()
  if [[ "${1:-}" == "--no-pull" ]]; then
    start_options+=(--no-pull)
    shift
  fi
  [[ $# -eq 0 ]] || fail "unknown setup option: $1"

  if [[ ! -s "${state_dir}/secrets/${role}_db_password" ]]; then
    printf 'Using the prepared %s node settings below. Run ./node.sh config first to change them.\n' \
      "${role}"
    show_node_configuration
    configure_database_secret
  fi
  start_node "${start_options[@]}"
  printf 'XiPKI %s node setup completed.\n' "${role}"
  show_next_step
}

doctor_failures=0
doctor_warnings=0

# Runs one diagnostic in isolation so a focused validation failure does not hide later findings.
doctor_check() {
  local label="$1"
  shift
  local output
  if output="$("$@" 2>&1)"; then
    printf '[PASS] %s\n' "${label}"
  else
    printf '[FAIL] %s\n' "${label}"
    [[ -z "${output}" ]] || printf '       %s\n' "${output//$'\n'/$'\n       '}"
    doctor_failures=$((doctor_failures + 1))
  fi
}

# Adds a non-blocking finding with a concrete recovery action.
doctor_warn() {
  local label="$1"
  local action="$2"
  printf '[WARN] %s\n       %s\n' "${label}" "${action}"
  doctor_warnings=$((doctor_warnings + 1))
}

# Reports whether the role container is absent, unhealthy, or ready without requiring it to be
# running during pre-installation diagnosis.
diagnose_runtime() {
  local container_id health state
  container_id="$("${compose[@]}" ps -q "${role}")"
  if [[ -z "${container_id}" ]]; then
    doctor_warn "${role} is not running" "Run ./node.sh setup to install and start it."
    return
  fi
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' \
    "${container_id}")"
  state="$(docker inspect --format '{{.State.Status}}' "${container_id}")"
  if [[ "${health}" == "healthy" ]]; then
    printf '[PASS] %s container is healthy\n' "${role}"
  else
    doctor_warn "${role} container state=${state}, health=${health:-none}" \
      "Run ./node.sh logs to inspect the startup failure."
  fi
}

# Produces one operator-oriented readiness report. Missing images or a stopped role are warnings;
# malformed settings, missing Secrets, and an invalid database handoff are blocking failures.
doctor_node() {
  local application_image="${XIPKI_IMAGE_PREFIX}/xipki:${XIPKI_VERSION}"
  doctor_failures=0
  doctor_warnings=0
  printf 'XiPKI %s node diagnosis\n' "${role}"
  doctor_check "node settings" validate_node_configuration
  doctor_check "role material and Secrets" validate_role_material
  doctor_check "database Secret" require_role_secret "${role}_db_password"
  doctor_check "Docker Compose v2" require_compose
  if (( doctor_failures == 0 )); then
    doctor_check "Compose model" "${compose[@]}" config --quiet
  fi

  if docker image inspect "${application_image}" >/dev/null 2>&1; then
    printf '[PASS] application image is available\n'
  else
    doctor_warn "application image is not available: ${application_image}" \
      "Run ./node.sh pull or ./node.sh setup."
  fi
  if docker image inspect "${bootstrap_image}" >/dev/null 2>&1; then
    doctor_check "database connectivity, authorization, and schema" database_preflight
  else
    doctor_warn "database checker image is not available: ${bootstrap_image}" \
      "Run ./node.sh setup to pull it and verify the database."
  fi
  if (( doctor_failures == 0 )); then
    diagnose_runtime
  fi

  printf 'Diagnosis complete: %d failure(s), %d warning(s).\n' \
    "${doctor_failures}" "${doctor_warnings}"
  (( doctor_failures == 0 ))
}

# Requires a deployment-and-role-specific acknowledgement before rebuilding local runtime state.
reset_node() {
  local expected="RESET ${deployment_name} ${role}"
  local confirmation
  printf 'This deletes deployment %s role %s containers and generated runtime volume.\n' \
    "${deployment_name}" "${role}" >&2
  printf 'The node package, identity material, settings, and Secrets will be retained.\n' >&2
  printf 'Type %s to continue: ' "${expected}" >&2
  IFS= read -r confirmation || fail "reset confirmation is required"
  [[ "${confirmation}" == "${expected}" ]] || fail "reset confirmation did not match"
  "${compose[@]}" down --volumes --remove-orphans
  # The checksum describes the deleted role volume. Removing it makes the next setup explicitly
  # materialize the retained seed again instead of claiming that generated runtime state exists.
  rm -f -- "${state_dir}/materialized-config.cksum"
  printf 'XiPKI %s role %s runtime was reset. Run ./node.sh setup to start it again.\n' \
    "${deployment_name}" "${role}"
}

# Requires a deployment-and-role-specific acknowledgement before deleting local node material.
purge_node() {
  local expected="DELETE ${deployment_name} ${role}"
  local confirmation
  printf 'This permanently deletes deployment %s role %s on this node.\n' \
    "${deployment_name}" "${role}" >&2
  printf 'Type %s to continue: ' "${expected}" >&2
  IFS= read -r confirmation || fail "purge confirmation is required"
  [[ "${confirmation}" == "${expected}" ]] || fail "purge confirmation did not match"
  "${compose[@]}" down --volumes --remove-orphans
  [[ "${state_dir}" == "${script_dir}/.state" && "${state_dir}" != "/" ]] \
    || fail "refusing to remove an unsafe state path"
  rm -rf -- "${state_dir}"
  printf 'XiPKI %s role %s was permanently erased.\n' "${deployment_name}" "${role}"
}

command="${1:-}"
shift || true
case "${command}" in
  -h|--help|help)
    usage
    ;;
  config)
    case "${1:-}" in
      '') configure_node ;;
      show)
        [[ $# -eq 1 ]] || fail "config show does not accept arguments"
        show_node_configuration
        ;;
      check)
        [[ $# -eq 1 ]] || fail "config check does not accept arguments"
        check_node
        ;;
      *) fail "unknown config command: $1" ;;
    esac
    ;;
  check)
    [[ $# -eq 0 ]] || fail "check does not accept arguments"
    check_node
    ;;
  setup)
    setup_node "$@"
    ;;
  doctor)
    [[ $# -eq 0 ]] || fail "doctor does not accept arguments"
    doctor_node
    ;;
  up)
    start_node "$@"
    ;;
  pull)
    [[ $# -eq 0 ]] || fail "pull does not accept arguments"
    require_compose
    "${compose[@]}" pull
    docker pull "${bootstrap_image}"
    ;;
  status)
    [[ $# -eq 0 ]] || fail "status does not accept arguments"
    require_compose
    "${compose[@]}" ps -a
    ;;
  credentials)
    [[ $# -eq 0 ]] || fail "credentials does not accept arguments"
    show_console_credentials
    ;;
  logs)
    require_compose
    "${compose[@]}" logs -f "$@"
    ;;
  smoke)
    [[ $# -eq 0 ]] || fail "smoke does not accept arguments"
    require_compose
    wait_for_health
    ;;
  verify)
    [[ $# -eq 0 ]] || fail "verify does not accept arguments"
    verify_gateway_certificate_lifecycle
    ;;
  restart)
    [[ $# -eq 0 ]] || fail "restart does not accept arguments"
    require_compose
    "${compose[@]}" restart "${role}"
    wait_for_health
    ;;
  down)
    [[ $# -eq 0 ]] || fail "down does not accept arguments"
    require_compose
    "${compose[@]}" down
    ;;
  reset)
    [[ $# -eq 0 ]] || fail "reset does not accept arguments"
    require_compose
    reset_node
    ;;
  purge)
    [[ $# -eq 0 ]] || fail "purge does not accept arguments"
    require_compose
    purge_node
    ;;
  version)
    [[ $# -eq 0 ]] || fail "version does not accept arguments"
    printf 'format=%s\ndeployment=%s\nrole=%s\nimage=%s/xipki:%s\n' \
      "${deployment_format}" "${deployment_name}" "${role}" \
      "${XIPKI_IMAGE_PREFIX}" "${XIPKI_VERSION}"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
