#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/../.." && pwd)"
compose_file="${script_dir}/compose.yaml"
compose_build_file="${script_dir}/compose.build.yaml"
user_config_file="${script_dir}/xipki.env"
state_root="${script_dir}/.state"
secret_dir="${state_root}/secrets"
console_client_dir="${state_root}/client"
interactive_configuration=false
if [[ "${1:-}" == "config" && $# -eq 1 ]]; then
  interactive_configuration=true
fi

fail() {
  echo "xipki: $*" >&2
  exit 1
}

# Returns the Maven reactor version in a source checkout. Packaged deployments do not contain a
# root POM and instead receive the same version through their generated .env file.
repository_version() {
  local line
  local version_pattern='<version>([^<]+)</version>'
  [[ -f "${project_dir}/pom.xml" ]] || return 1
  while IFS= read -r line; do
    if [[ "${line}" =~ ${version_pattern} ]]; then
      printf '%s\n' "${BASH_REMATCH[1]}"
      return
    fi
  done < "${project_dir}/pom.xml"
  return 1
}

# Selects the local state scope. Distributed deployments never reuse standalone credentials,
# which prevents topology changes from silently carrying localhost identities into node bundles.
set_state_paths() {
  local mode="$1"
  local name="$2"
  if [[ "${mode}" == "distributed" ]]; then
    secret_dir="${state_root}/deployments/${name}/secrets"
    console_client_dir="${state_root}/deployments/${name}/client"
  else
    secret_dir="${state_root}/secrets"
    console_client_dir="${state_root}/client"
  fi
}

# Declares the intentionally small deployment interface accepted from each settings file.
setting_is_allowed() {
  local scope="$1"
  local key="$2"
  case "${scope}:${key}" in
    packaged:XIPKI_IMAGE_PREFIX|packaged:XIPKI_VERSION|packaged:XIPKI_DATABASE|\
    packaged:XIPKI_DATABASE_MODE|packaged:XIPKI_DEPLOYMENT_MODE) return 0 ;;
    user:XIPKI_DEPLOYMENT_FORMAT|user:XIPKI_DEPLOYMENT_MODE|user:XIPKI_DEPLOYMENT_NAME|\
    user:XIPKI_CA_HOST|user:XIPKI_CONSOLE_HOST|user:XIPKI_GATEWAY_HOST|user:XIPKI_OCSP_HOST|\
    user:XIPKI_DATABASE_MODE|user:XIPKI_DATABASE|user:XIPKI_DB_HOST|user:XIPKI_DB_PORT|\
    user:XIPKI_ORGANIZATION|user:XIPKI_BIND_ADDRESS|user:XIPKI_CONSOLE_HTTPS_PORT|\
    user:XIPKI_CA_HTTPS_PORT|user:XIPKI_GATEWAY_HTTP_PORT|\
    user:XIPKI_GATEWAY_HTTPS_PORT|user:XIPKI_OCSP_HTTP_PORT|\
    user:XIPKI_CONSOLE_AUTH_MODE) return 0 ;;
    *) return 1 ;;
  esac
}

# Parses KEY=VALUE data without evaluating it as shell code. Existing process environment values
# win, so automation can override user and packaged defaults for one invocation.
load_settings_file() {
  local path="$1"
  local scope="$2"
  local line key value line_number=0
  [[ -f "${path}" ]] || return 0

  while IFS= read -r line || [[ -n "${line}" ]]; do
    line_number=$((line_number + 1))
    line="${line%$'\r'}"
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    [[ "${line}" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] \
      || fail "${path}:${line_number}: expected KEY=VALUE"
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    setting_is_allowed "${scope}" "${key}" \
      || fail "${path}:${line_number}: unsupported setting ${key}"
    if [[ -z "${!key:-}" ]]; then
      printf -v "${key}" '%s' "${value}"
      export "${key}"
    fi
  done < "${path}"
}

load_settings_file "${user_config_file}" user
load_settings_file "${script_dir}/.env" packaged
source_version="$(repository_version || true)"
default_version="${source_version:-7.0.0-SNAPSHOT}"
default_archive="assemblies/xipki-setup/target/xipki-setup-${default_version}.tar.gz"
setup_archive="${XIPKI_SETUP_ARCHIVE:-${default_archive}}"
default_console_jar="console-server/target/xipki-console-server-${default_version}.jar"
console_jar="${XIPKI_CONSOLE_JAR:-${default_console_jar}}"
project_name="${XIPKI_COMPOSE_PROJECT:-xipki}"
image_prefix="${XIPKI_IMAGE_PREFIX:-docker.io/xipki}"
image_prefix="${image_prefix%/}"
version="${XIPKI_VERSION:-${default_version}}"
dev_image_prefix="${XIPKI_DEV_IMAGE_PREFIX:-xipki}"
dev_image_prefix="${dev_image_prefix%/}"
dev_version="${XIPKI_DEV_VERSION:-${default_version}-dev}"
database="${XIPKI_DATABASE:-mariadb}"
database_mode="${XIPKI_DATABASE_MODE:-managed}"
deployment_format="${XIPKI_DEPLOYMENT_FORMAT:-1}"
deployment_mode="${XIPKI_DEPLOYMENT_MODE:-standalone}"
deployment_name="${XIPKI_DEPLOYMENT_NAME:-xipki}"
ca_host="${XIPKI_CA_HOST:-ca}"
console_host="${XIPKI_CONSOLE_HOST:-console}"
gateway_host="${XIPKI_GATEWAY_HOST:-gateway}"
ocsp_host="${XIPKI_OCSP_HOST:-ocsp}"
[[ "${deployment_format}" == "1" ]] \
  || fail "unsupported XIPKI_DEPLOYMENT_FORMAT: ${deployment_format} (expected 1)"
case "${deployment_mode}" in
  standalone|distributed) ;;
  *) fail "unsupported XIPKI_DEPLOYMENT_MODE: ${deployment_mode} (expected standalone or distributed)" ;;
esac
[[ "${deployment_name}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] \
  || fail "XIPKI_DEPLOYMENT_NAME must be a lowercase DNS label of at most 63 characters"
set_state_paths "${deployment_mode}" "${deployment_name}"
case "${database}" in
  mariadb|postgres) ;;
  *)
    echo "xipki: unsupported XIPKI_DATABASE: ${database} (expected mariadb or postgres)" >&2
    exit 1
    ;;
esac
case "${database_mode}" in
  managed|external) ;;
  *) fail "unsupported XIPKI_DATABASE_MODE: ${database_mode} (expected managed or external)" ;;
esac
if [[ "${deployment_mode}" == "distributed" \
    && "${database_mode}" != "external" \
    && "${interactive_configuration}" != "true" ]]; then
  fail "distributed deployment currently requires XIPKI_DATABASE_MODE=external"
fi
if [[ "${database}" == "mariadb" ]]; then
  default_database_port=3306
  console_database_scheme=mariadb
else
  default_database_port=5432
  console_database_scheme=postgresql
fi
database_host="${XIPKI_DB_HOST:-database}"
database_port="${XIPKI_DB_PORT:-${default_database_port}}"
# The interactive command must remain usable to repair an incomplete external
# configuration. Every command that consumes the settings still validates them here.
if [[ "${interactive_configuration}" != "true" ]]; then
  [[ "${database_port}" =~ ^[0-9]+$ \
    && "${database_port}" -ge 1 \
    && "${database_port}" -le 65535 ]] \
    || fail "XIPKI_DB_PORT must be between 1 and 65535"
fi
if [[ "${deployment_mode}" == "distributed" && "${interactive_configuration}" != "true" ]]; then
  for host_setting in XIPKI_CA_HOST XIPKI_CONSOLE_HOST XIPKI_GATEWAY_HOST XIPKI_OCSP_HOST; do
    host_value="${!host_setting:-}"
    [[ -n "${host_value}" ]] \
      || fail "${host_setting} is required when XIPKI_DEPLOYMENT_MODE=distributed; run ./container.sh config"
    [[ "${host_value}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
      || fail "${host_setting} must be a DNS name or IPv4 address"
  done
fi
if [[ "${database_mode}" == "external" || "${deployment_mode}" == "distributed" ]]; then
  if [[ "${interactive_configuration}" != "true" ]]; then
    [[ -n "${XIPKI_DB_HOST:-}" ]] \
      || fail "XIPKI_DB_HOST is required for an external or distributed database; run ./container.sh config"
    [[ "${database_host}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
      || fail "XIPKI_DB_HOST must be a DNS name or IPv4 address"
  fi
  database_compose_file="${script_dir}/compose.external-db.yaml"
else
  [[ "${database_host}" == "database" ]] \
    || fail "XIPKI_DB_HOST is only configurable when XIPKI_DATABASE_MODE=external"
  database_compose_file="${script_dir}/compose.${database}.yaml"
fi
console_database_url="jdbc:${console_database_scheme}://${database_host}:${database_port}/xipki_console"
for port_setting in \
  XIPKI_CA_HTTPS_PORT XIPKI_CONSOLE_HTTPS_PORT XIPKI_GATEWAY_HTTP_PORT \
  XIPKI_GATEWAY_HTTPS_PORT XIPKI_OCSP_HTTP_PORT; do
  port_value="${!port_setting:-}"
  if [[ -n "${port_value}" ]]; then
    [[ "${port_value}" =~ ^[0-9]+$ \
      && "${port_value}" -ge 1 \
      && "${port_value}" -le 65535 ]] \
      || fail "${port_setting} must be between 1 and 65535"
  fi
done
case "${XIPKI_CONSOLE_AUTH_MODE:-both}" in
  both|password|certificate) ;;
  *) fail "XIPKI_CONSOLE_AUTH_MODE must be both, password, or certificate" ;;
esac
compose=(docker compose --project-name "${project_name}" -f "${compose_file}" -f "${database_compose_file}")
compose_dev=(docker compose --project-name "${project_name}" -f "${compose_file}" -f "${database_compose_file}" -f "${compose_build_file}")

usage() {
  cat <<'EOF'
Usage: ./container.sh COMMAND [ARGS]

Release commands:
  up [--no-pull]  Pull release images and start the stack
  pull            Pull release images without starting the stack
  upgrade         Pull release images and recreate the stack

Development commands:
  dev-up          Build XiPKI and local development images, then start the stack
  dev-build       Build XiPKI and local development images without starting
  build           Alias for dev-build

Operations:
  config [show|check]
                  Configure XiPKI interactively, show effective settings, or validate them
  certificates import IDENTITY P12 TRUST_ANCHOR
                  Import ca-server or gateway-server before distributed prepare
  certificates show
                  Show whether each distributed server identity is generated or imported
  prepare [--no-pull]
                  Generate role-scoped node bundles for a distributed deployment
  down            Stop the stack while retaining all data and credentials
  purge           Permanently erase the stack, data volumes, and local credentials
  restart         Restart the long-running services
  status          Show container status
  logs [SERVICE]  Follow all logs, or the selected service logs
  smoke [--restart]
                  Verify health and port connectivity; optionally test restart persistence
  credentials     Show the generated first-login Console credentials
  version         Show release and development image settings

Database selection:
  MariaDB is the default. Run './container.sh config' to select a managed or external database.

Deployment modes:
  Standalone is the default. Distributed mode generates one private node bundle for each role;
  every node is then operated with the node.sh contained in its bundle.
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_compose() {
  require_command docker
  docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
}

# Creates one stable random text secret atomically without exposing its value.
ensure_secret() {
  local name="$1"
  local target="${secret_dir}/${name}"
  local temporary

  if [[ -s "${target}" ]]; then
    return
  fi

  # Generate each database credential locally and atomically. Secrets must never
  # appear in Compose defaults, image layers, process arguments, or terminal output.
  temporary="$(mktemp "${secret_dir}/.${name}.XXXXXX")"
  openssl rand -hex 32 >"${temporary}"
  chmod 0600 "${temporary}"
  mv "${temporary}" "${target}"
}

# Requires DBA-provided application credentials in external mode instead of generating values
# that could not match the already provisioned database identities.
require_external_database_secrets() {
  local name path
  for name in ca_db_password console_db_password gateway_db_password ocsp_db_password; do
    path="${secret_dir}/${name}"
    [[ -f "${path}" && -r "${path}" && -s "${path}" ]] \
      || fail "external database Secret is missing: ${path}; run ./container.sh config"
  done
}

# Generates binary application key material without exposing it in arguments or logs.
ensure_binary_secret() {
  local name="$1"
  local bytes="$2"
  local target="${secret_dir}/${name}"
  local temporary

  if [[ -s "${target}" ]]; then
    return
  fi

  temporary="$(mktemp "${secret_dir}/.${name}.XXXXXX")"
  openssl rand "${bytes}" >"${temporary}"
  chmod 0600 "${temporary}"
  mv "${temporary}" "${target}"
}

# Creates the local HTTPS identity once so upgrades and container restarts keep
# the same endpoint certificate. Operators can replace both files before startup.
ensure_console_tls_identity() {
  local key="${secret_dir}/console_tls_key.pem"
  local certificate="${secret_dir}/console_tls_cert.pem"
  local temporary_key temporary_certificate cert_cn san

  if [[ -s "${key}" && -s "${certificate}" ]]; then
    return
  fi

  temporary_key="$(mktemp "${secret_dir}/.console_tls_key.XXXXXX")"
  temporary_certificate="$(mktemp "${secret_dir}/.console_tls_cert.XXXXXX")"
  if [[ "${deployment_mode}" == "standalone" ]]; then
    cert_cn=localhost
    san="DNS:localhost,DNS:console,IP:127.0.0.1"
  elif [[ "${console_host}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    cert_cn="${console_host}"
    san="IP:${console_host}"
  else
    cert_cn="${console_host}"
    san="DNS:${console_host}"
  fi
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 \
    -subj "/CN=${cert_cn}/O=XiPKI Local Deployment" \
    -addext "subjectAltName=${san}" \
    -keyout "${temporary_key}" -out "${temporary_certificate}" >/dev/null 2>&1
  chmod 0600 "${temporary_key}" "${temporary_certificate}"
  mv "${temporary_key}" "${key}"
  mv "${temporary_certificate}" "${certificate}"
}

# Creates a dedicated browser-login CA and initial admin identity. This identity
# is intentionally separate from the CA management client used by Console itself.
ensure_console_client_identity() {
  local ca_key="${console_client_dir}/console-client-ca.key"
  local ca_certificate="${console_client_dir}/console-client-ca.crt"
  local admin_key="${console_client_dir}/admin.key"
  local admin_certificate="${console_client_dir}/admin.crt"
  local admin_bundle="${console_client_dir}/admin.p12"
  local work_dir

  if [[ -s "${ca_key}" && -s "${ca_certificate}" && -s "${admin_key}" \
      && -s "${admin_certificate}" && -s "${admin_bundle}" ]]; then
    return
  fi

  work_dir="$(mktemp -d "${console_client_dir}/.identity.XXXXXX")"
  openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
    -subj "/CN=XiPKI Console Client CA/O=XiPKI Local Deployment" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "${work_dir}/ca.key" -out "${work_dir}/ca.crt" >/dev/null 2>&1
  openssl req -newkey rsa:3072 -nodes \
    -subj "/CN=admin/O=XiPKI Local Deployment" \
    -addext "extendedKeyUsage=clientAuth" \
    -keyout "${work_dir}/admin.key" -out "${work_dir}/admin.csr" >/dev/null 2>&1
  openssl x509 -req -days 825 -sha256 -copy_extensions copy \
    -in "${work_dir}/admin.csr" -CA "${work_dir}/ca.crt" -CAkey "${work_dir}/ca.key" \
    -CAcreateserial -out "${work_dir}/admin.crt" >/dev/null 2>&1
  openssl pkcs12 -export -name "XiPKI Console admin" \
    -inkey "${work_dir}/admin.key" -in "${work_dir}/admin.crt" \
    -certfile "${work_dir}/ca.crt" -passout "file:${secret_dir}/console_admin_client_password" \
    -out "${work_dir}/admin.p12"
  chmod 0600 "${work_dir}"/*
  mv "${work_dir}/ca.key" "${ca_key}"
  mv "${work_dir}/ca.crt" "${ca_certificate}"
  mv "${work_dir}/admin.key" "${admin_key}"
  mv "${work_dir}/admin.crt" "${admin_certificate}"
  mv "${work_dir}/admin.p12" "${admin_bundle}"
  rm -rf "${work_dir}"
}

# Makes only file-backed Compose secrets readable by the non-root container UID.
# The owner-only parent directories still prevent other host users from reaching them.
set_container_secret_permissions() {
  local readable_secrets=(
    "${secret_dir}/console_admin_password"
    "${secret_dir}/console_enrollment_key"
    "${secret_dir}/console_tls_cert.pem"
    "${secret_dir}/console_tls_key.pem"
    "${console_client_dir}/console-client-ca.crt"
    "${console_client_dir}/admin.crt"
  )
  if [[ "${deployment_mode}" != "distributed" ]]; then
    readable_secrets+=(
      "${secret_dir}/ca_db_password"
      "${secret_dir}/console_db_password"
      "${secret_dir}/gateway_db_password"
      "${secret_dir}/ocsp_db_password"
    )
  fi
  if [[ "${deployment_mode}" != "distributed" && "${database_mode}" == "managed" ]]; then
    readable_secrets+=(
      "${secret_dir}/postgres_admin_password"
      "${secret_dir}/mariadb_admin_password"
    )
  fi
  chmod 0444 "${readable_secrets[@]}"
}

# Ensures the complete local identity set exists and is readable by its intended consumers.
ensure_secrets() {
  require_command openssl
  install -d -m 0700 "${secret_dir}"
  install -d -m 0700 "${console_client_dir}"
  if [[ "${deployment_mode}" == "distributed" ]]; then
    : # Database Secrets are created independently by node.sh on each target host.
  elif [[ "${database_mode}" == "managed" ]]; then
    ensure_secret postgres_admin_password
    ensure_secret mariadb_admin_password
    ensure_secret ca_db_password
    ensure_secret console_db_password
    ensure_secret gateway_db_password
    ensure_secret ocsp_db_password
  else
    require_external_database_secrets
  fi
  ensure_secret console_admin_password
  ensure_secret console_admin_client_password
  ensure_binary_secret console_enrollment_key 32
  ensure_console_tls_identity
  ensure_console_client_identity
  set_container_secret_permissions
}

# Returns the private control-host directory used for pre-deployment server identity overrides.
certificate_override_directory() {
  printf '%s/deployments/%s/certificate-overrides' "${state_root}" "${deployment_name}"
}

# Extracts and validates an imported PKCS#12 server identity without exposing its password in a
# process argument. The normalized public leaf is retained for later bundle materialization.
validate_imported_server_identity() {
  local identity="$1"
  local p12_file="$2"
  local password_file="$3"
  local trust_anchor="$4"
  local expected_host="$5"
  local output_leaf="$6"
  local output_chain="$7"
  local work_dir raw_leaf chain private_key cert_public key_public

  work_dir="${output_leaf%/*}/.validation"
  install -d -m 0700 "${work_dir}"
  raw_leaf="${work_dir}/leaf.pem"
  chain="${work_dir}/chain.pem"
  private_key="${work_dir}/key.pem"
  if ! openssl pkcs12 -in "${p12_file}" -clcerts -nokeys \
      -passin "file:${password_file}" -out "${raw_leaf}" >/dev/null 2>&1; then
    rm -rf "${work_dir}"
    fail "unable to open ${identity} PKCS#12 with the supplied password"
  fi
  openssl x509 -in "${raw_leaf}" -out "${output_leaf}" \
    || { rm -rf "${work_dir}"; fail "${identity} PKCS#12 has no readable leaf certificate"; }
  openssl pkcs12 -in "${p12_file}" -cacerts -nokeys \
    -passin "file:${password_file}" -out "${chain}" >/dev/null 2>&1 || true
  if [[ -s "${chain}" ]]; then
    cp "${chain}" "${output_chain}"
    chmod 0600 "${output_chain}"
  fi
  if ! openssl pkcs12 -in "${p12_file}" -nocerts -nodes \
      -passin "file:${password_file}" -out "${private_key}" >/dev/null 2>&1; then
    rm -rf "${work_dir}"
    fail "${identity} PKCS#12 has no readable private key"
  fi
  cert_public="$(openssl x509 -in "${output_leaf}" -pubkey -noout \
    | openssl pkey -pubin -outform DER 2>/dev/null | openssl sha256)"
  key_public="$(openssl pkey -in "${private_key}" -pubout -outform DER 2>/dev/null \
    | openssl sha256)"
  [[ -n "${cert_public}" && "${cert_public}" == "${key_public}" ]] \
    || { rm -rf "${work_dir}"; fail "${identity} certificate does not match its private key"; }
  validate_leaf_certificate "${output_leaf}" "${trust_anchor}" \
    sslserver sslclient "${expected_host}" "${chain}"
  rm -rf "${work_dir}"
}

# Prompts for and stores one imported server identity in the deployment's private control state.
# Client identities are excluded because replacing them also requires coordinated CA authorization.
import_server_identity() {
  local identity="$1"
  local source_p12="$2"
  local source_trust_anchor="$3"
  local expected_host override_root pending first second replaced=false

  [[ "${deployment_mode}" == "distributed" ]] \
    || fail "certificate import currently requires a distributed deployment"
  case "${identity}" in
    ca-server) expected_host="${ca_host}" ;;
    gateway-server) expected_host="${gateway_host}" ;;
    *) fail "unsupported server identity: ${identity} (expected ca-server or gateway-server)" ;;
  esac
  [[ -r "${source_p12}" && -s "${source_p12}" ]] \
    || fail "PKCS#12 file is not readable: ${source_p12}"
  [[ -r "${source_trust_anchor}" && -s "${source_trust_anchor}" ]] \
    || fail "trust anchor file is not readable: ${source_trust_anchor}"
  while true; do
    printf '%s PKCS#12 password: ' "${identity}" >&2
    IFS= read -r -s first || fail "certificate password input was cancelled"
    printf '\nConfirm %s PKCS#12 password: ' "${identity}" >&2
    IFS= read -r -s second || fail "certificate password input was cancelled"
    printf '\n' >&2
    if [[ -z "${first}" ]]; then
      echo 'Password must not be empty.' >&2
    elif [[ "${first}" != "${second}" ]]; then
      echo 'Passwords did not match; try again.' >&2
    elif [[ ! "${first}" =~ ^[A-Za-z0-9._~!@#%+=:,/-]+$ ]]; then
      echo 'Password contains characters unsupported by the first-release XML/JSON materializer.' >&2
    else
      break
    fi
  done

  require_command openssl
  override_root="$(certificate_override_directory)"
  install -d -m 0700 "${override_root}"
  pending="$(mktemp -d "${override_root}/.${identity}.XXXXXX")"
  trap '[[ -z "${pending:-}" ]] || rm -rf -- "${pending}"' EXIT
  cp "${source_p12}" "${pending}/identity.p12"
  cp "${source_trust_anchor}" "${pending}/trustanchors.pem"
  printf '%s' "${first}" > "${pending}/password"
  chmod 0600 "${pending}/"*
  validate_imported_server_identity "${identity}" \
    "${pending}/identity.p12" "${pending}/password" "${pending}/trustanchors.pem" \
    "${expected_host}" "${pending}/identity-cert.pem" "${pending}/identity-chain.pem"
  chmod 0600 "${pending}/identity-cert.pem"
  if [[ -d "${override_root}/${identity}" ]]; then
    replaced=true
    rm -rf "${override_root:?}/${identity}"
  fi
  mv "${pending}" "${override_root}/${identity}"
  pending=""
  trap - EXIT
  printf 'Imported %s for %s. Run ./container.sh prepare to rebuild node bundles.\n' \
    "${identity}" "${expected_host}"
  if [[ "${replaced}" == "true" ]]; then
    printf 'The previous %s override was replaced and permanently removed.\n' "${identity}"
  fi
}

# Reports only import state and paths; certificate passwords are never read for display.
show_certificate_overrides() {
  local identity override_root mode
  [[ "${deployment_mode}" == "distributed" ]] \
    || fail "certificate overrides currently apply only to distributed deployments"
  override_root="$(certificate_override_directory)"
  for identity in ca-server gateway-server; do
    if [[ -s "${override_root}/${identity}/identity.p12" ]]; then
      mode=imported
    else
      mode=generated
    fi
    printf '%s=%s\n' "${identity}" "${mode}"
  done
}

# Prompts for one non-secret configuration value and returns it in prompt_result.
prompt_value() {
  local label="$1"
  local default_value="$2"
  local entered
  if [[ -n "${default_value}" ]]; then
    printf '%s [%s]: ' "${label}" "${default_value}" >&2
  else
    printf '%s: ' "${label}" >&2
  fi
  IFS= read -r entered || fail "configuration input was cancelled"
  prompt_result="${entered:-${default_value}}"
}

# Prompts until the user selects one of the supported values for a closed setting.
prompt_choice() {
  local label="$1"
  local default_value="$2"
  shift 2
  local choice allowed
  while true; do
    prompt_value "${label} ($*)" "${default_value}"
    choice="${prompt_result}"
    for allowed in "$@"; do
      if [[ "${choice}" == "${allowed}" ]]; then
        prompt_result="${choice}"
        return
      fi
    done
    printf 'Unsupported value: %s. Expected one of: %s\n' "${choice}" "$*" >&2
  done
}

# Reads and confirms one password without echoing it, then atomically stores the Compose Secret.
# Existing external credentials are immutable because generated role state embeds them and this
# release does not implement coordinated database password rotation.
configure_database_secret() {
  local name="$1"
  local label="$2"
  local preserve_existing="$3"
  local first second target temporary
  target="${secret_dir}/${name}"

  if [[ "${preserve_existing}" == "true" && -s "${target}" ]]; then
    printf '%s is already configured and was kept.\n' "${label}" >&2
    return
  fi

  while true; do
    printf '%s: ' "${label}" >&2
    IFS= read -r -s first || fail "configuration input was cancelled"
    printf '\nConfirm %s: ' "${label}" >&2
    IFS= read -r -s second || fail "configuration input was cancelled"
    printf '\n' >&2
    if [[ -z "${first}" ]]; then
      echo "Password must not be empty." >&2
    elif [[ "${first}" != "${second}" ]]; then
      echo "Passwords did not match; try again." >&2
    else
      break
    fi
  done

  temporary="$(mktemp "${secret_dir}/.${name}.XXXXXX")"
  printf '%s' "${first}" > "${temporary}"
  chmod 0444 "${temporary}"
  mv "${temporary}" "${target}"
}

# Writes normalized non-secret settings; Secret values are deliberately never serialized here.
write_user_configuration() {
  local selected_deployment_mode="$1"
  local selected_deployment_name="$2"
  local selected_ca_host="$3"
  local selected_console_host="$4"
  local selected_gateway_host="$5"
  local selected_ocsp_host="$6"
  local selected_mode="$7"
  local selected_database="$8"
  local selected_host="$9"
  local selected_port="${10}"
  local selected_bind_address temporary
  if [[ "${selected_deployment_mode}" == "distributed" \
      && "${deployment_mode}" != "distributed" ]]; then
    selected_bind_address=0.0.0.0
  elif [[ -n "${XIPKI_BIND_ADDRESS:-}" ]]; then
    selected_bind_address="${XIPKI_BIND_ADDRESS}"
  elif [[ "${selected_deployment_mode}" == "distributed" ]]; then
    selected_bind_address=0.0.0.0
  else
    selected_bind_address=127.0.0.1
  fi
  temporary="$(mktemp "${script_dir}/.xipki.env.XXXXXX")"
  {
    echo '# Generated by ./container.sh config. Passwords are stored under .state/secrets/.'
    echo 'XIPKI_DEPLOYMENT_FORMAT=1'
    printf 'XIPKI_DEPLOYMENT_MODE=%s\n' "${selected_deployment_mode}"
    printf 'XIPKI_DEPLOYMENT_NAME=%s\n' "${selected_deployment_name}"
    if [[ "${selected_deployment_mode}" == "distributed" ]]; then
      printf 'XIPKI_CA_HOST=%s\n' "${selected_ca_host}"
      printf 'XIPKI_CONSOLE_HOST=%s\n' "${selected_console_host}"
      printf 'XIPKI_GATEWAY_HOST=%s\n' "${selected_gateway_host}"
      printf 'XIPKI_OCSP_HOST=%s\n' "${selected_ocsp_host}"
    fi
    printf 'XIPKI_DATABASE_MODE=%s\n' "${selected_mode}"
    printf 'XIPKI_DATABASE=%s\n' "${selected_database}"
    if [[ "${selected_mode}" == "external" \
        || "${selected_deployment_mode}" == "distributed" ]]; then
      printf 'XIPKI_DB_HOST=%s\n' "${selected_host}"
      printf 'XIPKI_DB_PORT=%s\n' "${selected_port}"
    fi
    printf 'XIPKI_ORGANIZATION=%s\n' "${XIPKI_ORGANIZATION:-XiPKI Evaluation}"
    printf 'XIPKI_BIND_ADDRESS=%s\n' "${selected_bind_address}"
    printf 'XIPKI_CA_HTTPS_PORT=%s\n' "${XIPKI_CA_HTTPS_PORT:-8444}"
    printf 'XIPKI_CONSOLE_HTTPS_PORT=%s\n' "${XIPKI_CONSOLE_HTTPS_PORT:-18081}"
    printf 'XIPKI_GATEWAY_HTTP_PORT=%s\n' "${XIPKI_GATEWAY_HTTP_PORT:-18082}"
    printf 'XIPKI_GATEWAY_HTTPS_PORT=%s\n' "${XIPKI_GATEWAY_HTTPS_PORT:-18445}"
    printf 'XIPKI_OCSP_HTTP_PORT=%s\n' "${XIPKI_OCSP_HTTP_PORT:-18080}"
    printf 'XIPKI_CONSOLE_AUTH_MODE=%s\n' "${XIPKI_CONSOLE_AUTH_MODE:-both}"
  } > "${temporary}"
  chmod 0600 "${temporary}"
  mv "${temporary}" "${user_config_file}"
}

# Provides the primary human interface for selecting the database mode and entering its Secrets.
configure_deployment() {
  local selected_deployment_mode selected_deployment_name
  local selected_ca_host="" selected_console_host="" selected_gateway_host="" selected_ocsp_host=""
  local selected_mode selected_database selected_host="" selected_port
  local preserve_existing_secrets=false selected_node_host suggested_host suggested_port
  local suggested_ca_host="" suggested_console_host="" suggested_gateway_host="" suggested_ocsp_host=""

  prompt_choice "Deployment mode" "${deployment_mode}" standalone distributed
  selected_deployment_mode="${prompt_result}"
  if [[ "${selected_deployment_mode}" == "distributed" ]]; then
    prompt_value "Deployment name" "${deployment_name}"
    selected_deployment_name="${prompt_result}"
    [[ "${selected_deployment_name}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] \
      || fail "deployment name must be a lowercase DNS label of at most 63 characters"

    if [[ "${deployment_mode}" == "distributed" ]]; then
      suggested_ca_host="${ca_host}"
      suggested_console_host="${console_host}"
      suggested_gateway_host="${gateway_host}"
      suggested_ocsp_host="${ocsp_host}"
    fi
    prompt_value "CA host" "${suggested_ca_host}"
    selected_ca_host="${prompt_result}"
    prompt_value "Console host" "${suggested_console_host}"
    selected_console_host="${prompt_result}"
    prompt_value "Gateway host" "${suggested_gateway_host}"
    selected_gateway_host="${prompt_result}"
    prompt_value "OCSP host" "${suggested_ocsp_host}"
    selected_ocsp_host="${prompt_result}"
    for selected_node_host in \
      "${selected_ca_host}" "${selected_console_host}" \
      "${selected_gateway_host}" "${selected_ocsp_host}"; do
      [[ "${selected_node_host}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
        || fail "each distributed node host must be a DNS name or IPv4 address"
    done
  else
    selected_deployment_name="${deployment_name}"
  fi

  # Passwords and generated identities belong to the topology being configured, not to the
  # launcher's previous mode. This also makes multiple named distributed deployments coexist.
  set_state_paths "${selected_deployment_mode}" "${selected_deployment_name}"

  if [[ "${selected_deployment_mode}" == "distributed" ]]; then
    # A managed database is intentionally private to the standalone Compose network. Do not offer
    # it for multi-host use until database TLS, remote grants, backup, and firewall policy exist.
    prompt_choice "Database mode" external external
  else
    prompt_choice "Database mode" "${database_mode}" managed external
  fi
  selected_mode="${prompt_result}"
  prompt_choice "Database engine" "${database}" mariadb postgres
  selected_database="${prompt_result}"

  if [[ "${selected_database}" == "mariadb" ]]; then
    suggested_port=3306
  else
    suggested_port=5432
  fi
  if [[ "${database_mode}" == "external" || "${deployment_mode}" == "distributed" ]]; then
    suggested_host="${database_host}"
  else
    suggested_host=""
  fi

  if [[ "${selected_mode}" == "external" \
      || "${selected_deployment_mode}" == "distributed" ]]; then
    prompt_value "Database host" "${suggested_host}"
    selected_host="${prompt_result}"
    [[ "${selected_host}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
      || fail "database host must be a DNS name or IPv4 address"
    prompt_value "Database port" "${suggested_port}"
    selected_port="${prompt_result}"
    [[ "${selected_port}" =~ ^[0-9]+$ \
      && "${selected_port}" -ge 1 \
      && "${selected_port}" -le 65535 ]] \
      || fail "database port must be between 1 and 65535"

    if [[ "${selected_mode}" == "external" \
        && "${selected_deployment_mode}" == "standalone" ]]; then
      install -d -m 0700 "${secret_dir}"
      if [[ "${database_mode}" == "external" ]]; then
        preserve_existing_secrets=true
      fi
      configure_database_secret ca_db_password "CA database password" \
        "${preserve_existing_secrets}"
      configure_database_secret ocsp_db_password "OCSP database password" \
        "${preserve_existing_secrets}"
      configure_database_secret gateway_db_password "Gateway database password" \
        "${preserve_existing_secrets}"
      configure_database_secret console_db_password "Console database password" \
        "${preserve_existing_secrets}"
    fi
  else
    selected_port="${suggested_port}"
  fi

  write_user_configuration \
    "${selected_deployment_mode}" "${selected_deployment_name}" \
    "${selected_ca_host}" "${selected_console_host}" \
    "${selected_gateway_host}" "${selected_ocsp_host}" \
    "${selected_mode}" "${selected_database}" "${selected_host}" "${selected_port}"
  printf 'XiPKI configuration was written to %s\n' "${user_config_file}"
  if [[ "${selected_mode}" == "external" \
      && "${selected_deployment_mode}" == "standalone" ]]; then
    printf 'Database Secrets were written under %s\n' "${secret_dir}"
  elif [[ "${selected_deployment_mode}" == "distributed" ]]; then
    echo 'Database passwords will be entered independently on each role node.'
  fi
  echo "Run './container.sh config check' to validate it."
}

# Displays the effective non-secret settings and only the presence of database Secrets.
show_configuration() {
  local name status
  printf 'deployment.format=%s\n' "${deployment_format}"
  printf 'deployment.mode=%s\n' "${deployment_mode}"
  printf 'deployment.name=%s\n' "${deployment_name}"
  if [[ "${deployment_mode}" == "distributed" ]]; then
    printf 'node.ca=%s\n' "${ca_host}"
    printf 'node.console=%s\n' "${console_host}"
    printf 'node.gateway=%s\n' "${gateway_host}"
    printf 'node.ocsp=%s\n' "${ocsp_host}"
  fi
  printf 'node.ca.https-port=%s\n' "${XIPKI_CA_HTTPS_PORT:-8444}"
  printf 'database.mode=%s\n' "${database_mode}"
  printf 'database.engine=%s\n' "${database}"
  printf 'database.host=%s\n' "${database_host}"
  printf 'database.port=%s\n' "${database_port}"
  if [[ "${deployment_mode}" == "distributed" ]]; then
    printf 'console.url=https://%s:%s\n' \
      "${console_host}" "${XIPKI_CONSOLE_HTTPS_PORT:-18081}"
  else
    printf 'console.url=https://%s:%s\n' \
      "${XIPKI_BIND_ADDRESS:-127.0.0.1}" "${XIPKI_CONSOLE_HTTPS_PORT:-18081}"
  fi
  if [[ "${deployment_mode}" == "distributed" ]]; then
    echo 'database.passwords=configured-on-role-nodes'
  else
    for name in ca_db_password ocsp_db_password gateway_db_password console_db_password; do
      if [[ -s "${secret_dir}/${name}" ]]; then
        status=configured
      else
        status=missing
      fi
      printf 'secret.%s=%s\n' "${name}" "${status}"
    done
  fi
}

# Validates local settings and, for an external database, runs the image's JDBC preflight only.
check_configuration() {
  if [[ "${deployment_mode}" == "distributed" ]]; then
    printf 'XiPKI distributed topology configuration is valid. Database credentials are supplied on each role node.\n'
    return
  fi
  if [[ "${database_mode}" == "managed" ]]; then
    printf 'XiPKI %s deployment configuration with a managed %s database is valid.\n' \
      "${deployment_mode}" "${database}"
    return
  fi
  require_external_database_secrets
  chmod 0444 \
    "${secret_dir}/ca_db_password" \
    "${secret_dir}/console_db_password" \
    "${secret_dir}/gateway_db_password" \
    "${secret_dir}/ocsp_db_password"
  require_compose
  export_settings
  "${compose[@]}" run --rm --no-deps -e XIPKI_BOOTSTRAP_MODE=check bootstrap
}

# Writes the immutable identity of a generated node bundle. Node operators may change node.env,
# but changing this manifest would turn the archive into a different deployment artifact.
write_node_manifest() {
  local role="$1"
  local target="$2"
  {
    printf 'XIPKI_DEPLOYMENT_FORMAT=2\n'
    printf 'XIPKI_DEPLOYMENT_NAME=%s\n' "${deployment_name}"
    printf 'XIPKI_NODE_ROLE=%s\n' "${role}"
    printf 'XIPKI_COMPOSE_PROJECT=%s-%s\n' "${deployment_name}" "${role}"
    printf 'XIPKI_IMAGE_PREFIX=%s\n' "${image_prefix}"
    printf 'XIPKI_VERSION=%s\n' "${version}"
    printf 'XIPKI_DATABASE=%s\n' "${database}"
  } > "${target}"
  chmod 0444 "${target}"
}

# Writes the non-secret, node-local settings that may be adjusted before the role starts.
write_node_configuration() {
  local role="$1"
  local target="$2"
  {
    printf 'XIPKI_BIND_ADDRESS=%s\n' "${XIPKI_BIND_ADDRESS:-0.0.0.0}"
    printf 'XIPKI_DB_HOST=%s\n' "${database_host}"
    printf 'XIPKI_DB_PORT=%s\n' "${database_port}"
    case "${role}" in
      ca)
        printf 'XIPKI_DB_USER=xipki_ca\n'
        printf 'XIPKI_CACONF_DB_NAME=caconf\n'
        printf 'XIPKI_CA_DB_NAME=ca\n'
        printf 'XIPKI_OCSP_DB_NAME=ocsp\n'
        printf 'XIPKI_KEYPOOL_DB_NAME=keypool\n'
        printf 'XIPKI_CA_HTTPS_PORT=%s\n' "${XIPKI_CA_HTTPS_PORT:-8444}"
        ;;
      console)
        printf 'XIPKI_DB_USER=xipki_console\n'
        printf 'XIPKI_CONSOLE_DB_NAME=xipki_console\n'
        printf 'XIPKI_CONSOLE_HTTPS_PORT=%s\n' "${XIPKI_CONSOLE_HTTPS_PORT:-18081}"
        printf 'XIPKI_CONSOLE_AUTH_MODE=%s\n' "${XIPKI_CONSOLE_AUTH_MODE:-both}"
        printf 'XIPKI_CA_URL=https://%s:%s/ca/mgmt\n' \
          "${ca_host}" "${XIPKI_CA_HTTPS_PORT:-8444}"
        ;;
      gateway)
        printf 'XIPKI_DB_USER=xipki_gateway\n'
        printf 'XIPKI_ACME_DB_NAME=acme\n'
        printf 'XIPKI_GATEWAY_HOST=%s\n' "${gateway_host}"
        printf 'XIPKI_GATEWAY_HTTP_PORT=%s\n' "${XIPKI_GATEWAY_HTTP_PORT:-18082}"
        printf 'XIPKI_GATEWAY_HTTPS_PORT=%s\n' "${XIPKI_GATEWAY_HTTPS_PORT:-18445}"
        printf 'XIPKI_OCSP_HOST=%s\n' "${ocsp_host}"
        printf 'XIPKI_OCSP_HTTP_PORT=%s\n' "${XIPKI_OCSP_HTTP_PORT:-18080}"
        ;;
      ocsp)
        printf 'XIPKI_DB_USER=xipki_ocsp\n'
        printf 'XIPKI_CA_DB_NAME=ca\n'
        printf 'XIPKI_OCSP_DB_NAME=ocsp\n'
        printf 'XIPKI_OCSP_HTTP_PORT=%s\n' "${XIPKI_OCSP_HTTP_PORT:-18080}"
        ;;
    esac
  } > "${target}"
  chmod 0600 "${target}"
}

# Copies only the host Secrets that Console consumes outside its Bootstrap-generated role state.
copy_console_node_material() {
  local target="$1"
  local name
  install -d -m 0700 "${target}/.state/secrets" "${target}/.state/client"
  for name in \
    console_admin_password console_enrollment_key \
    console_tls_cert.pem console_tls_key.pem; do
    cp "${secret_dir}/${name}" "${target}/.state/secrets/${name}"
  done
  cp "${console_client_dir}/console-client-ca.crt" \
    "${target}/.state/client/console-client-ca.crt"
  cp "${console_client_dir}/admin.crt" "${target}/.state/client/admin.crt"
  cp "${console_client_dir}/admin.p12" "${target}/.state/client/admin.p12"
  cp "${secret_dir}/console_admin_client_password" \
    "${target}/.state/client/admin.p12.password"
  chmod 0444 "${target}/.state/secrets/"* \
    "${target}/.state/client/console-client-ca.crt" \
    "${target}/.state/client/admin.crt"
  chmod 0600 \
    "${target}/.state/client/admin.p12" \
    "${target}/.state/client/admin.p12.password"
}

# Adds only the credential and public trust needed to prove Gateway issuance and revocation. The
# verification files stay on the Gateway host and are never mounted into the runtime container.
copy_gateway_verification_material() {
  local exported_roles="$1"
  local target="$2"
  local gateway_anchor="${exported_roles}/gateway/xipki/keycerts/gateway-server-trustanchors.pem"
  install -d -m 0700 "${target}/verification"
  cp "${script_dir}/distributed/gateway-verify.sh" "${target}/verification/verify.sh"
  cp "${exported_roles}/admin/verification/rest-client.p12" \
    "${target}/verification/rest-client.p12"
  cp "${exported_roles}/admin/verification/rest-client.p12.password" \
    "${target}/verification/rest-client.p12.password"
  if [[ -s "${gateway_anchor}" ]]; then
    cp "${gateway_anchor}" "${target}/verification/gateway-server-trustanchors.pem"
  else
    cp "${exported_roles}/admin/deployment-ca/deployment-internal-ca-cert.pem" \
      "${target}/verification/gateway-server-trustanchors.pem"
  fi
  chmod 0700 "${target}/verification/verify.sh"
  chmod 0400 \
    "${target}/verification/rest-client.p12" \
    "${target}/verification/rest-client.p12.password" \
    "${target}/verification/gateway-server-trustanchors.pem"
}

# Replaces one generated password with a marker while preserving all surrounding XML or JSON.
# Generated service passwords are random hexadecimal strings, so literal Bash replacement avoids
# the quoting and delimiter hazards of feeding a Secret through sed.
externalize_identity_password() {
  local configuration_file="$1"
  local password="$2"
  local placeholder="$3"
  local secret_file="$4"
  local content temporary

  [[ -n "${password}" ]] || fail "identity password is empty in ${configuration_file}"
  content="$(<"${configuration_file}")"
  [[ "${content}" == *"${password}"* ]] \
    || fail "identity password was not found in ${configuration_file}"
  shopt -u patsub_replacement 2>/dev/null || true
  temporary="${configuration_file}.externalizing"
  printf '%s\n' "${content//${password}/${placeholder}}" > "${temporary}"
  chmod 0600 "${temporary}"
  mv "${temporary}" "${configuration_file}"
  printf '%s' "${password}" > "${secret_file}"
  chmod 0400 "${secret_file}"
}

# Moves generated private-key passwords out of runtime configuration and into file-backed node
# Secrets. role-init resolves the markers only inside the role's private runtime volume.
externalize_role_identity_secrets() {
  local role="$1"
  local bundle_dir="$2"
  local server_xml="${bundle_dir}/.state/seed/conf/server.xml"
  local gateway_json="${bundle_dir}/.state/seed/xipki/etc/gateway.json"
  local password

  case "${role}" in
    ca)
      password="$(sed -n 's/.*certificateKeystorePassword="\([^"]*\)".*/\1/p' \
        "${server_xml}")"
      externalize_identity_password "${server_xml}" "${password}" \
        __XIPKI_CA_TLS_KEYSTORE_PASSWORD__ \
        "${bundle_dir}/.state/secrets/ca_tls_keystore_password"
      ;;
    gateway)
      password="$(sed -n 's/.*certificateKeystorePassword="\([^"]*\)".*/\1/p' \
        "${server_xml}")"
      if [[ -f "${bundle_dir}/.state/seed/xipki/etc/cmp-gateway.json" ]]; then
        replace_identity_configuration_password \
          "${bundle_dir}/.state/seed/xipki/etc/cmp-gateway.json" "${password}" \
          __XIPKI_GATEWAY_TLS_KEYSTORE_PASSWORD__
      fi
      externalize_identity_password "${server_xml}" "${password}" \
        __XIPKI_GATEWAY_TLS_KEYSTORE_PASSWORD__ \
        "${bundle_dir}/.state/secrets/gateway_tls_keystore_password"
      password="$(sed -n 's/.*"keystorePassword"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        "${gateway_json}")"
      externalize_identity_password "${gateway_json}" "${password}" \
        __XIPKI_GATEWAY_RA_CLIENT_KEYSTORE_PASSWORD__ \
        "${bundle_dir}/.state/secrets/gateway_ra_client_keystore_password"
      ;;
  esac
}

# Replaces a generated password in one private configuration file before that value is split into
# the role bundle's file-backed Secret. Imported passwords are restricted to literal-safe text.
replace_identity_configuration_password() {
  local configuration_file="$1"
  local old_password="$2"
  local new_password="$3"
  local content temporary

  [[ -n "${old_password}" && -n "${new_password}" ]] \
    || fail "cannot replace an empty identity password in ${configuration_file}"
  content="$(<"${configuration_file}")"
  [[ "${content}" == *"${old_password}"* ]] \
    || fail "generated identity password was not found in ${configuration_file}"
  shopt -u patsub_replacement 2>/dev/null || true
  temporary="${configuration_file}.replacing"
  printf '%s\n' "${content//${old_password}/${new_password}}" > "${temporary}"
  chmod 0600 "${temporary}"
  mv "${temporary}" "${configuration_file}"
}

# Applies validated control-host server identity overrides to exported role state. CA trust changes
# are propagated to every internal CA caller; Gateway's public trust anchor remains role-scoped.
apply_server_certificate_overrides() {
  local roles_dir="$1"
  local override_root identity source password old_password required
  local server_xml cmp_gateway
  override_root="$(certificate_override_directory)"

  for identity in ca-server gateway-server; do
    source="${override_root}/${identity}"
    [[ -d "${source}" ]] || continue
    for required in identity.p12 identity-cert.pem trustanchors.pem password; do
      [[ -s "${source}/${required}" ]] \
        || fail "incomplete ${identity} override: ${source}/${required}"
    done
    password="$(tr -d '\r\n' < "${source}/password")"
    case "${identity}" in
      ca-server)
        server_xml="${roles_dir}/ca/conf/server.xml"
        old_password="$(sed -n 's/.*certificateKeystorePassword="\([^"]*\)".*/\1/p' \
          "${server_xml}")"
        replace_identity_configuration_password "${server_xml}" "${old_password}" "${password}"
        cp "${source}/identity.p12" \
          "${roles_dir}/ca/xipki/keycerts/ca-server.p12"
        cp "${source}/identity-cert.pem" \
          "${roles_dir}/ca/xipki/keycerts/ca-server-cert.pem"
        cp "${source}/trustanchors.pem" \
          "${roles_dir}/admin/xipki/keycerts/ca-server-cert.pem"
        cp "${source}/trustanchors.pem" \
          "${roles_dir}/console/client/trustanchors.pem"
        cp "${source}/trustanchors.pem" \
          "${roles_dir}/gateway/xipki/keycerts/ca-server-cert.pem"
        cp "${source}/trustanchors.pem" \
          "${roles_dir}/admin/deployment-ca/ca-server-trustanchors.pem"
        if [[ -s "${source}/identity-chain.pem" ]]; then
          cp "${source}/identity-chain.pem" \
            "${roles_dir}/admin/deployment-ca/ca-server-chain.pem"
        fi
        ;;
      gateway-server)
        server_xml="${roles_dir}/gateway/conf/server.xml"
        old_password="$(sed -n 's/.*certificateKeystorePassword="\([^"]*\)".*/\1/p' \
          "${server_xml}")"
        replace_identity_configuration_password "${server_xml}" "${old_password}" "${password}"
        cmp_gateway="${roles_dir}/gateway/xipki/etc/cmp-gateway.json"
        if [[ -f "${cmp_gateway}" ]]; then
          replace_identity_configuration_password \
            "${cmp_gateway}" "${old_password}" "${password}"
        fi
        cp "${source}/identity.p12" \
          "${roles_dir}/gateway/xipki/keycerts/gateway-server.p12"
        cp "${source}/identity-cert.pem" \
          "${roles_dir}/gateway/xipki/keycerts/gateway-server-cert.pem"
        cp "${source}/trustanchors.pem" \
          "${roles_dir}/gateway/xipki/keycerts/gateway-server-trustanchors.pem"
        if [[ -s "${source}/identity-chain.pem" ]]; then
          cp "${source}/identity-chain.pem" \
            "${roles_dir}/gateway/xipki/keycerts/gateway-server-chain.pem"
        fi
        ;;
    esac
  done
}

# Reduces a copied role seed to the database properties supported by the distributed deployment
# contract. Bootstrap exports XiPKI's expert templates as well, but node operators must not be
# forced to configure optional schemas or retain inactive backend directories in runtime state.
filter_role_database_configuration() {
  local role="$1"
  local seed_dir="$2"
  local database_dir file directory allowed_file keep
  local -a allowed_files

  case "${role}" in
    ca)
      database_dir="${seed_dir}/xipki/etc/ca/database"
      allowed_files=(
        caconf-db.properties ca-db.properties ocsp-db.properties keypool-db.properties
      )
      ;;
    console)
      return 0
      ;;
    gateway)
      database_dir="${seed_dir}/xipki/etc/acme/database"
      allowed_files=(acme-db.properties)
      ;;
    ocsp)
      database_dir="${seed_dir}/xipki/etc/ocsp/database"
      allowed_files=(ca-db.properties ocsp-db.properties)
      ;;
    *)
      fail "unsupported role database contract: ${role}"
      ;;
  esac

  [[ -d "${database_dir}" ]] \
    || fail "${role} runtime database directory is missing: ${database_dir}"
  for allowed_file in "${allowed_files[@]}"; do
    [[ -f "${database_dir}/${allowed_file}" ]] \
      || fail "${role} runtime database configuration is missing: ${allowed_file}"
  done

  while IFS= read -r -d '' file; do
    keep=false
    for allowed_file in "${allowed_files[@]}"; do
      if [[ "$(basename "${file}")" == "${allowed_file}" ]]; then
        keep=true
        break
      fi
    done
    if [[ "${keep}" != "true" ]]; then
      rm -- "${file}"
    fi
  done < <(find "${database_dir}" -maxdepth 1 -type f -name '*-db.properties' -print0)

  while IFS= read -r -d '' directory; do
    rm -rf -- "${directory}"
  done < <(find "${database_dir}" -mindepth 1 -maxdepth 1 -type d -print0)
}

# Materializes one self-contained node directory and archives it without another role's state.
create_role_bundle() {
  local role="$1"
  local exported_roles="$2"
  local staging="$3"
  local bundle_name="xipki-${deployment_name}-${role}-${version}"
  local bundle_dir="${staging}/${bundle_name}"
  install -d -m 0700 "${bundle_dir}/.state/seed" "${bundle_dir}/.state/secrets"
  cp -a "${exported_roles}/${role}/." "${bundle_dir}/.state/seed/"
  filter_role_database_configuration "${role}" "${bundle_dir}/.state/seed"
  cp "${script_dir}/distributed/compose.${role}.yaml" "${bundle_dir}/compose.yaml"
  cp "${script_dir}/distributed/node.sh" "${bundle_dir}/node.sh"
  cp "${script_dir}/distributed/node-README.md" "${bundle_dir}/README.md"
  chmod 0755 "${bundle_dir}/node.sh"
  write_node_manifest "${role}" "${bundle_dir}/manifest.env"
  write_node_configuration "${role}" "${bundle_dir}/node.env"
  cp "${bundle_dir}/node.env" "${bundle_dir}/node.env.example"
  chmod 0444 "${bundle_dir}/node.env.example"
  externalize_role_identity_secrets "${role}" "${bundle_dir}"
  if [[ "${role}" == "console" ]]; then
    copy_console_node_material "${bundle_dir}"
  elif [[ "${role}" == "gateway" ]]; then
    copy_gateway_verification_material "${exported_roles}" "${bundle_dir}"
  fi
  tar -czf "${staging}/${bundle_name}.tar.gz" -C "${staging}" "${bundle_name}"
  chmod 0600 "${staging}/${bundle_name}.tar.gz"
  rm -rf "${bundle_dir}"
}

# Writes portable SHA-256 checksums for every generated node archive.
write_bundle_checksums() {
  local directory="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${directory}" && sha256sum ./*.tar.gz > SHA256SUMS)
  else
    (cd "${directory}" && shasum -a 256 ./*.tar.gz > SHA256SUMS)
  fi
  chmod 0600 "${directory}/SHA256SUMS"
}

# Verifies one generated leaf certificate's chain, exclusive TLS purpose, and optional endpoint
# name. Failing during preparation prevents a malformed identity from reaching another host.
validate_leaf_certificate() {
  local certificate="$1"
  local trust_anchor="$2"
  local required_purpose="$3"
  local forbidden_purpose="$4"
  local expected_host="${5:-}"
  local untrusted_chain="${6:-}"
  local -a verify_arguments

  [[ -s "${certificate}" ]] || fail "generated certificate is missing: ${certificate}"
  [[ -s "${trust_anchor}" ]] || fail "deployment trust anchor is missing: ${trust_anchor}"
  verify_arguments=(-CAfile "${trust_anchor}")
  if [[ -n "${untrusted_chain}" && -s "${untrusted_chain}" ]]; then
    verify_arguments+=(-untrusted "${untrusted_chain}")
  fi
  openssl verify "${verify_arguments[@]}" "${certificate}" >/dev/null \
    || fail "generated certificate does not verify to the deployment trust anchor: ${certificate}"
  openssl verify -purpose "${required_purpose}" "${verify_arguments[@]}" \
    "${certificate}" >/dev/null 2>&1 \
    || fail "generated certificate is missing ${required_purpose}: ${certificate}"
  if openssl verify -purpose "${forbidden_purpose}" "${verify_arguments[@]}" \
      "${certificate}" >/dev/null 2>&1; then
    fail "generated certificate combines server and client authentication: ${certificate}"
  fi

  if [[ -n "${expected_host}" ]]; then
    if [[ "${expected_host}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      openssl x509 -in "${certificate}" -noout -checkip "${expected_host}" >/dev/null \
        || fail "generated certificate SAN does not contain IP ${expected_host}: ${certificate}"
    else
      openssl x509 -in "${certificate}" -noout -checkhost "${expected_host}" >/dev/null \
        || fail "generated certificate SAN does not contain DNS name ${expected_host}: ${certificate}"
    fi
  fi
}

# Enforces the deployment identity boundary: CA and Gateway use server-only certificates, while
# Console management and Gateway-to-CA authorization use separate client-only certificates.
validate_generated_identity_contract() {
  local roles_dir="$1"
  local trust_anchor="${roles_dir}/admin/deployment-ca/deployment-internal-ca-cert.pem"
  local ca_server="${roles_dir}/ca/xipki/keycerts/ca-server-cert.pem"
  local ca_management="${roles_dir}/ca/xipki/keycerts/ca-mgmt-client-cert.pem"
  local gateway_server="${roles_dir}/gateway/xipki/keycerts/gateway-server-cert.pem"
  local gateway_ra="${roles_dir}/gateway/xipki/keycerts/ra-sdk-client-cert.pem"
  local ca_server_anchor="${trust_anchor}"
  local gateway_server_anchor="${trust_anchor}"
  local ca_server_chain=""
  local gateway_server_chain=""
  local gateway_server_fingerprint gateway_ra_fingerprint

  if [[ -s "${roles_dir}/admin/deployment-ca/ca-server-trustanchors.pem" ]]; then
    ca_server_anchor="${roles_dir}/admin/deployment-ca/ca-server-trustanchors.pem"
    ca_server_chain="${roles_dir}/admin/deployment-ca/ca-server-chain.pem"
  fi
  if [[ -s "${roles_dir}/gateway/xipki/keycerts/gateway-server-trustanchors.pem" ]]; then
    gateway_server_anchor="${roles_dir}/gateway/xipki/keycerts/gateway-server-trustanchors.pem"
    gateway_server_chain="${roles_dir}/gateway/xipki/keycerts/gateway-server-chain.pem"
  fi

  validate_leaf_certificate "${ca_server}" "${ca_server_anchor}" \
    sslserver sslclient "${ca_host}" "${ca_server_chain}"
  validate_leaf_certificate "${gateway_server}" "${gateway_server_anchor}" \
    sslserver sslclient "${gateway_host}" "${gateway_server_chain}"
  validate_leaf_certificate "${ca_management}" "${trust_anchor}" \
    sslclient sslserver
  validate_leaf_certificate "${gateway_ra}" "${trust_anchor}" \
    sslclient sslserver

  gateway_server_fingerprint="$(openssl x509 -in "${gateway_server}" -noout -fingerprint -sha256)"
  gateway_ra_fingerprint="$(openssl x509 -in "${gateway_ra}" -noout -fingerprint -sha256)"
  [[ "${gateway_server_fingerprint}" != "${gateway_ra_fingerprint}" ]] \
    || fail 'Gateway server and RA client identities must be separate certificates'
}

# Generates stable role state in Bootstrap, then packages four independently deployable nodes.
prepare_distributed_deployment() {
  local pull_image=true
  local bootstrap_image="${XIPKI_BOOTSTRAP_IMAGE:-${image_prefix}/bootstrap:${version}}"
  local deployment_state="${state_root}/deployments/${deployment_name}"
  local bootstrap_state="${deployment_state}/bootstrap"
  local export_state="${deployment_state}/export"
  local output_parent="${script_dir}/dist"
  local output_dir="${output_parent}/${deployment_name}"
  local staging role current_uid current_gid
  local -a docker_args

  [[ "${deployment_mode}" == "distributed" ]] \
    || fail "prepare requires XIPKI_DEPLOYMENT_MODE=distributed; run ./container.sh config"
  [[ "${database_mode}" == "external" ]] \
    || fail "the first distributed milestone requires an external database"
  if [[ "${1:-}" == "--no-pull" ]]; then
    pull_image=false
    shift
  fi
  [[ $# -eq 0 ]] || fail "unknown prepare option: $1"

  require_compose
  require_command tar
  # Distributed database credentials belong to the target nodes. The control host only creates
  # deployment identities and Console first-login material.
  ensure_secrets
  install -d -m 0700 "${bootstrap_state}" "${export_state}" "${output_parent}"
  if [[ "${pull_image}" == "true" ]]; then
    docker pull "${bootstrap_image}"
  fi

  current_uid="$(id -u)"
  current_gid="$(id -g)"
  docker_args=(
    docker run --rm --user "${current_uid}:${current_gid}"
    -e XIPKI_BOOTSTRAP_MODE=prepare
    -e XIPKI_EXPORT_DIR=/export
    -e "XIPKI_ORGANIZATION=${XIPKI_ORGANIZATION:-XiPKI Evaluation}"
    -e "XIPKI_DEPLOYMENT_MODE=${deployment_mode}"
    -e "XIPKI_DEPLOYMENT_NAME=${deployment_name}"
    -e "XIPKI_DATABASE=${database}"
    -e "XIPKI_DATABASE_MODE=${database_mode}"
    -e "XIPKI_DB_HOST=${database_host}"
    -e "XIPKI_DB_PORT=${database_port}"
    -e "XIPKI_CA_HOST=${ca_host}"
    -e "XIPKI_CA_HTTPS_PORT=${XIPKI_CA_HTTPS_PORT:-8444}"
    -e "XIPKI_GATEWAY_HOST=${gateway_host}"
    -e "XIPKI_OCSP_HOST=${ocsp_host}"
    --mount "type=bind,source=${bootstrap_state},target=/var/lib/xipki-bootstrap"
    --mount "type=bind,source=${export_state},target=/export"
    "${bootstrap_image}"
  )
  "${docker_args[@]}"

  for role in ca console gateway ocsp; do
    [[ -r "${export_state}/roles/${role}/.initialized" ]] \
      || fail "Bootstrap did not export complete ${role} role state"
  done
  apply_server_certificate_overrides "${export_state}/roles"
  validate_generated_identity_contract "${export_state}/roles"

  staging="$(mktemp -d "${output_parent}/.${deployment_name}.XXXXXX")"
  for role in ca console gateway ocsp; do
    create_role_bundle "${role}" "${export_state}/roles" "${staging}"
  done
  write_bundle_checksums "${staging}"

  [[ "${output_dir}" == "${output_parent}/"* && "${output_dir}" != "${output_parent}" ]] \
    || fail "refusing to replace an unsafe distributed output path"
  rm -rf "${output_dir}"
  mv "${staging}" "${output_dir}"
  printf 'XiPKI distributed node bundles were written to %s\n' "${output_dir}"
}

build_setup_archive() {
  require_command mvn
  [[ -f "${project_dir}/pom.xml" && -f "${compose_build_file}" ]] \
    || fail "development commands require a XiPKI source checkout"
  (
    cd "${project_dir}"
    # xipki-setup copies reactor artifacts through Maven plugins, so Maven cannot
    # discover every required module via -am. Install the complete reactor just
    # like the project's supported install.sh entry point.
    mvn clean install -DskipTests
  )
}

ensure_setup_archive() {
  if [[ ! -f "${project_dir}/${setup_archive}" ]]; then
    echo "XiPKI setup archive is missing; building it from source."
    build_setup_archive
  fi

  [[ -f "${project_dir}/${setup_archive}" ]] \
    || fail "XiPKI setup archive was not created: ${setup_archive}"
}

run_smoke_test() {
  "${script_dir}/smoke-test.sh" "$@"
}

export_settings() {
  export XIPKI_COMPOSE_PROJECT="${project_name}"
  export XIPKI_IMAGE_PREFIX="${image_prefix}"
  export XIPKI_VERSION="${version}"
  export XIPKI_DEV_IMAGE_PREFIX="${dev_image_prefix}"
  export XIPKI_DEV_VERSION="${dev_version}"
  export XIPKI_SETUP_ARCHIVE="${setup_archive}"
  export XIPKI_CONSOLE_JAR="${console_jar}"
  export XIPKI_DATABASE="${database}"
  export XIPKI_DATABASE_MODE="${database_mode}"
  export XIPKI_DEPLOYMENT_MODE="${deployment_mode}"
  export XIPKI_DEPLOYMENT_NAME="${deployment_name}"
  export XIPKI_CA_HOST="${ca_host}"
  export XIPKI_CONSOLE_HOST="${console_host}"
  export XIPKI_GATEWAY_HOST="${gateway_host}"
  export XIPKI_OCSP_HOST="${ocsp_host}"
  export XIPKI_CA_HTTPS_PORT="${XIPKI_CA_HTTPS_PORT:-8444}"
  export XIPKI_DB_HOST="${database_host}"
  export XIPKI_DB_PORT="${database_port}"
  export XIPKI_CONSOLE_DB_URL="${console_database_url}"
}

start_release() {
  local pull_images=true
  if [[ "${1:-}" == "--no-pull" ]]; then
    pull_images=false
    shift
  fi
  [[ $# -eq 0 ]] || fail "unknown up option: $1"

  ensure_secrets
  if [[ "${pull_images}" == "true" ]]; then
    "${compose[@]}" pull
  fi
  # Never fall back to an implicit build in release mode. A missing image must
  # fail explicitly so an end user does not unexpectedly need source or Maven.
  "${compose[@]}" up -d --no-build --pull never
  run_smoke_test
}

build_development_images() {
  ensure_secrets
  build_setup_archive
  ensure_setup_archive
  if [[ "${database_mode}" == "external" ]]; then
    "${compose_dev[@]}" build bootstrap ca
  else
    "${compose_dev[@]}" build
  fi
}

# Requires an exact, project-specific acknowledgement, removes Compose state first, and only then
# erases locally generated credentials. Retaining .state when Compose fails keeps recovery possible.
purge_deployment() {
  local expected="DELETE ${project_name}"
  local confirmation
  local state_dir="${script_dir}/.state"

  printf 'This permanently deletes the %s deployment, all data volumes, keys, and credentials.\n' \
    "${project_name}" >&2
  printf 'Type %s to continue: ' "${expected}" >&2
  IFS= read -r confirmation || fail "purge confirmation is required"
  [[ "${confirmation}" == "${expected}" ]] || fail "purge confirmation did not match"

  "${compose[@]}" down --volumes --remove-orphans
  [[ "${script_dir}" != "/" && "${state_dir}" == "${script_dir}/.state" ]] \
    || fail "refusing to remove an unsafe state path"
  rm -rf -- "${state_dir}"
  printf 'Deployment %s was permanently erased.\n' "${project_name}"
}

main() {
  local command="${1:-}"
  shift || true

  case "${command}" in
    -h|--help|help)
      usage
      return
      ;;
    version)
      printf 'deployment-mode=%s\n' "${deployment_mode}"
      printf 'deployment-name=%s\n' "${deployment_name}"
      printf 'database=%s\n' "${database}"
      printf 'database-mode=%s\n' "${database_mode}"
      printf 'release=%s/{mariadb,postgres,bootstrap,xipki}:%s\n' \
        "${image_prefix}" "${version}"
      printf 'development=%s/{%s,bootstrap,xipki}:%s\n' \
        "${dev_image_prefix}" "${database}" "${dev_version}"
      return
      ;;
    config)
      case "${1:-}" in
        "")
          [[ $# -eq 0 ]] || fail "config does not accept additional arguments"
          configure_deployment
          ;;
        show)
          [[ $# -eq 1 ]] || fail "config show does not accept additional arguments"
          show_configuration
          ;;
        check)
          [[ $# -eq 1 ]] || fail "config check does not accept additional arguments"
          check_configuration
          ;;
        *) fail "unknown config action: $1 (expected show or check)" ;;
      esac
      return
      ;;
    certificates)
      case "${1:-}" in
        import)
          [[ $# -eq 4 ]] \
            || fail "usage: ./container.sh certificates import IDENTITY P12 TRUST_ANCHOR"
          import_server_identity "$2" "$3" "$4"
          ;;
        show)
          [[ $# -eq 1 ]] || fail "certificates show does not accept additional arguments"
          show_certificate_overrides
          ;;
        *) fail "unknown certificates action: ${1:-} (expected import or show)" ;;
      esac
      return
      ;;
    prepare)
      prepare_distributed_deployment "$@"
      return
      ;;
  esac

  if [[ "${deployment_mode}" == "distributed" ]]; then
    fail "distributed deployments start from generated node bundles; run prepare, transfer one bundle to each node, then run that bundle's ./node.sh setup"
  fi

  require_compose
  export_settings

  case "${command}" in
    up)
      start_release "$@"
      ;;
    pull)
      [[ $# -eq 0 ]] || fail "pull does not accept arguments"
      "${compose[@]}" pull
      ;;
    upgrade)
      [[ $# -eq 0 ]] || fail "upgrade does not accept arguments"
      start_release
      ;;
    dev-up)
      [[ $# -eq 0 ]] || fail "dev-up does not accept arguments"
      ensure_secrets
      build_setup_archive
      ensure_setup_archive
      if [[ "${database_mode}" == "external" ]]; then
        "${compose_dev[@]}" up -d --build --pull never bootstrap ca console gateway ocsp
      else
        "${compose_dev[@]}" up -d --build --pull never
      fi
      run_smoke_test
      ;;
    dev-build|build)
      [[ $# -eq 0 ]] || fail "${command} does not accept arguments"
      build_development_images
      ;;
    down)
      [[ $# -eq 0 ]] || fail "down does not accept arguments"
      "${compose[@]}" down
      ;;
    purge)
      [[ $# -eq 0 ]] || fail "purge does not accept arguments"
      purge_deployment
      ;;
    restart)
      [[ $# -eq 0 ]] || fail "restart does not accept arguments"
      if [[ "${database_mode}" == "managed" ]]; then
        "${compose[@]}" restart database ca console gateway ocsp
      else
        "${compose[@]}" restart ca console gateway ocsp
      fi
      run_smoke_test
      ;;
    credentials)
      [[ $# -eq 0 ]] || fail "credentials does not accept arguments"
      ensure_secrets
      printf 'Console URL: https://localhost:%s/\n' "${XIPKI_CONSOLE_HTTPS_PORT:-18081}"
      printf 'Username: admin\nPassword: '
      cat "${secret_dir}/console_admin_password"
      printf '\nClient certificate: %s\nClient certificate password: ' \
        "${console_client_dir}/admin.p12"
      cat "${secret_dir}/console_admin_client_password"
      printf '\n'
      ;;
    status)
      [[ $# -eq 0 ]] || fail "status does not accept arguments"
      "${compose[@]}" ps -a
      ;;
    logs)
      "${compose[@]}" logs -f "$@"
      ;;
    smoke)
      run_smoke_test "$@"
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
