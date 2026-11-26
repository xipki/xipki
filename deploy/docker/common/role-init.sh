#!/usr/bin/env bash

set -Eeuo pipefail
umask 0077

readonly role="${XIPKI_ROLE:-}"
readonly deployment_name="${XIPKI_DEPLOYMENT_NAME:-}"
readonly seed_dir="${XIPKI_ROLE_SEED:-/seed}"
readonly state_dir="${XIPKI_BASE:-/var/lib/xipki}"
readonly runtime_uid="${XIPKI_UID:-10001}"
readonly runtime_gid="${XIPKI_GID:-10001}"

fail() {
  printf 'xipki-role-init: %s\n' "$*" >&2
  exit 1
}

# Confirms that a complete role seed was prepared for the role pinned by this node bundle.
validate_role_directory() {
  local directory="$1"
  local expected_role="$2"
  local marker="${directory}/.initialized"
  local recorded_format recorded_role recorded_deployment
  [[ -r "${marker}" ]] || fail "role marker is missing: ${marker}"
  recorded_format="$(sed -n 's/^format=//p' "${marker}")"
  [[ "${recorded_format}" == "1" ]] \
    || fail "unsupported role marker format: ${recorded_format:-missing}"
  recorded_role="$(sed -n 's/^role=//p' "${marker}")"
  [[ "${recorded_role}" == "${expected_role}" ]] \
    || fail "role seed contains ${recorded_role:-no role}, expected ${expected_role}"
  recorded_deployment="$(sed -n 's/^deployment=//p' "${marker}")"
  [[ "${recorded_deployment}" == "${deployment_name}" ]] \
    || fail "role seed belongs to deployment ${recorded_deployment:-unknown}, expected ${deployment_name}"

  case "${expected_role}" in
    ca|gateway|ocsp)
      [[ -r "${directory}/conf/server.xml" && -d "${directory}/xipki" ]] \
        || fail "${expected_role} role state is incomplete"
      ;;
    console)
      [[ -r "${directory}/client/client.p12" \
        && -r "${directory}/client/trustanchors.pem" \
        && -r "${directory}/client/password" \
        && -d "${directory}/enrollment" ]] \
        || fail "console role state is incomplete"
      ;;
    *) fail "unsupported role: ${expected_role}" ;;
  esac
}

# Replaces one preparation placeholder without exposing its value in a process argument.
replace_database_placeholder() {
  local target_directory="$1"
  local placeholder="$2"
  local value="$3"
  local file content temporary replacements=0
  while IFS= read -r -d '' file; do
    content="$(<"${file}")"
    [[ "${content}" == *"${placeholder}"* ]] || continue
    temporary="${file}.materializing"
    printf '%s\n' "${content//${placeholder}/${value}}" > "${temporary}"
    chmod --reference="${file}" "${temporary}"
    mv "${temporary}" "${file}"
    replacements=$((replacements + 1))
  done < <(find "${target_directory}/xipki" -type f -name '*-db.properties' -print0)
  (( replacements > 0 )) \
    || fail "database placeholder was not found: ${placeholder}"
}

# Materializes the node-local database endpoint, names, account, and Secret while creating the
# private role volume. Console consumes the same values directly through its runtime environment.
materialize_database_configuration() {
  local target_directory="$1"
  local target_role="$2"
  local secret_file="/run/secrets/${target_role}_db_password"
  local uppercase_role password name variable value

  # Console receives its JDBC settings directly through the runtime environment. Return an
  # explicit success status because this function is called under `set -e`; a bare `return` after
  # a false comparison would inherit status 1 and silently terminate Console initialization.
  if [[ "${target_role}" == "console" ]]; then
    return 0
  fi
  [[ "${XIPKI_DB_HOST:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
    || fail "XIPKI_DB_HOST must be a DNS name or IPv4 address"
  [[ "${XIPKI_DB_PORT:-}" =~ ^[0-9]+$ \
    && "${XIPKI_DB_PORT}" -ge 1 && "${XIPKI_DB_PORT}" -le 65535 ]] \
    || fail "XIPKI_DB_PORT must be between 1 and 65535"
  [[ "${XIPKI_DB_USER:-}" =~ ^[A-Za-z][A-Za-z0-9_]{0,62}$ ]] \
    || fail "XIPKI_DB_USER is not a portable database identifier"
  [[ -r "${secret_file}" ]] || fail "database Secret is not readable: ${secret_file}"
  password="$(tr -d '\r\n' < "${secret_file}")"
  [[ -n "${password}" ]] || fail "database Secret must not be empty: ${secret_file}"

  # Bash 5 can optionally interpret '&' in parameter-substitution replacements. Disable that
  # behavior so arbitrary printable database passwords remain literal; older Bash ignores it.
  shopt -u patsub_replacement 2>/dev/null || true
  replace_database_placeholder "${target_directory}" __XIPKI_DB_HOST__ "${XIPKI_DB_HOST}"
  replace_database_placeholder "${target_directory}" __XIPKI_DB_PORT__ "${XIPKI_DB_PORT}"
  replace_database_placeholder "${target_directory}" __XIPKI_DB_USER__ "${XIPKI_DB_USER}"
  uppercase_role="$(printf '%s' "${target_role}" | tr '[:lower:]' '[:upper:]')"
  replace_database_placeholder \
    "${target_directory}" "__XIPKI_${uppercase_role}_DB_PASSWORD__" "${password}"

  case "${target_role}" in
    ca) names='CACONF CA OCSP KEYPOOL' ;;
    gateway) names='ACME' ;;
    ocsp) names='CA OCSP' ;;
  esac
  for name in ${names}; do
    variable="XIPKI_${name}_DB_NAME"
    value="${!variable:-}"
    [[ "${value}" =~ ^[A-Za-z][A-Za-z0-9_]{0,62}$ ]] \
      || fail "XIPKI_${name}_DB_NAME is not a portable database identifier"
    replace_database_placeholder "${target_directory}" "__XIPKI_${name}_DB_NAME__" "${value}"
  done
  if grep -R -q '__XIPKI_.*_DB_PASSWORD__' "${target_directory}/xipki"; then
    fail "unresolved database password placeholder remains for role ${target_role}"
  fi
  if grep -R -q '__XIPKI_.*DB_\|__XIPKI_DB_' "${target_directory}/xipki"; then
    fail "unresolved database configuration placeholder remains for role ${target_role}"
  fi
}

# Resolves one private-key password from a file-backed Secret into configuration only after the
# immutable seed has entered the role's private volume. Passwords never enter node.env or Compose
# environment values.
materialize_identity_password() {
  local configuration_file="$1"
  local placeholder="$2"
  local secret_name="$3"
  local secret_file="/run/secrets/${secret_name}"
  local password content temporary

  [[ -r "${secret_file}" ]] || fail "identity Secret is not readable: ${secret_file}"
  password="$(tr -d '\r\n' < "${secret_file}")"
  [[ -n "${password}" ]] || fail "identity Secret must not be empty: ${secret_file}"
  [[ "${password}" =~ ^[A-Za-z0-9._~!@#%+=:,/-]+$ ]] \
    || fail "identity Secret contains characters unsupported by XML/JSON materialization: ${secret_name}"
  [[ -r "${configuration_file}" ]] || fail "identity configuration is missing: ${configuration_file}"
  content="$(<"${configuration_file}")"
  [[ "${content}" == *"${placeholder}"* ]] \
    || fail "identity placeholder was not found in ${configuration_file}: ${placeholder}"
  shopt -u patsub_replacement 2>/dev/null || true
  temporary="${configuration_file}.materializing"
  printf '%s\n' "${content//${placeholder}/${password}}" > "${temporary}"
  chmod --reference="${configuration_file}" "${temporary}"
  mv "${temporary}" "${configuration_file}"
}

# Materializes only the private-key passwords owned by this role. Server and RA client identities
# remain separate so compromise, replacement, and CA authorization do not share one credential.
materialize_identity_configuration() {
  local target_directory="$1"
  local target_role="$2"

  case "${target_role}" in
    ca)
      materialize_identity_password \
        "${target_directory}/conf/server.xml" \
        __XIPKI_CA_TLS_KEYSTORE_PASSWORD__ ca_tls_keystore_password
      ;;
    gateway)
      materialize_identity_password \
        "${target_directory}/conf/server.xml" \
        __XIPKI_GATEWAY_TLS_KEYSTORE_PASSWORD__ gateway_tls_keystore_password
      if [[ -f "${target_directory}/xipki/etc/cmp-gateway.json" ]]; then
        materialize_identity_password \
          "${target_directory}/xipki/etc/cmp-gateway.json" \
          __XIPKI_GATEWAY_TLS_KEYSTORE_PASSWORD__ gateway_tls_keystore_password
      fi
      materialize_identity_password \
        "${target_directory}/xipki/etc/gateway.json" \
        __XIPKI_GATEWAY_RA_CLIENT_KEYSTORE_PASSWORD__ gateway_ra_client_keystore_password
      ;;
  esac
}

case "${role}" in
  ca|gateway|ocsp|console) ;;
  *) fail "XIPKI_ROLE must be ca, gateway, ocsp, or console" ;;
esac
[[ "${deployment_name}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] \
  || fail "XIPKI_DEPLOYMENT_NAME must be a lowercase DNS label of at most 63 characters"
[[ "$(id -u)" == "0" ]] || fail "role initialization must run as root"
[[ "${state_dir}" != "/" && -d "${state_dir}" ]] || fail "unsafe role state directory"
validate_role_directory "${seed_dir}" "${role}"

if [[ -f "${state_dir}/.initialized" ]]; then
  validate_role_directory "${state_dir}" "${role}"
  exit 0
fi

# Refuse to merge generated configuration into unknown state. The marker is copied last so a
# failed copy can be retried only after the incomplete volume has been inspected or replaced.
if find "${state_dir}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  fail "role state is non-empty but not initialized"
fi

(
  cd "${seed_dir}"
  tar -cf - --exclude=.initialized .
) | (
  cd "${state_dir}"
  tar -xf -
)
materialize_database_configuration "${state_dir}" "${role}"
materialize_identity_configuration "${state_dir}" "${role}"
chown -R "${runtime_uid}:${runtime_gid}" "${state_dir}"
install -o "${runtime_uid}" -g "${runtime_gid}" -m 0640 \
  "${seed_dir}/.initialized" "${state_dir}/.initialized.pending"
mv "${state_dir}/.initialized.pending" "${state_dir}/.initialized"
validate_role_directory "${state_dir}" "${role}"
printf 'XiPKI %s role state is initialized.\n' "${role}"
