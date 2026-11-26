#!/usr/bin/env bash

set -Eeuo pipefail
umask 0077

readonly setup_dir=/opt/xipki
readonly bootstrap_state=/var/lib/xipki-bootstrap
readonly artifacts_dir="${bootstrap_state}/artifacts"
readonly bootstrap_marker="${bootstrap_state}/.initialized"

fail() {
  printf 'xipki-bootstrap: %s\n' "$*" >&2
  exit 1
}

read_secret() {
  local name="$1"
  local path="/run/secrets/${name}"
  [[ -f "${path}" && -r "${path}" ]] || fail "required secret is not a readable file: ${name}"
  tr -d '\r\n' < "${path}"
}

random_secret() {
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

readonly bootstrap_mode="${XIPKI_BOOTSTRAP_MODE:-initialize}"
case "${bootstrap_mode}" in
  initialize|check|prepare) ;;
  *) fail "unsupported bootstrap mode: ${bootstrap_mode} (expected initialize, check, or prepare)" ;;
esac

export XIPKI_ORGANIZATION="${XIPKI_ORGANIZATION:-XiPKI Evaluation}"
export XIPKI_DATABASE="${XIPKI_DATABASE:-mariadb}"
export XIPKI_DATABASE_MODE="${XIPKI_DATABASE_MODE:-managed}"
export XIPKI_DEPLOYMENT_MODE="${XIPKI_DEPLOYMENT_MODE:-standalone}"
export XIPKI_DEPLOYMENT_NAME="${XIPKI_DEPLOYMENT_NAME:-xipki}"
export XIPKI_CA_HOST="${XIPKI_CA_HOST:-ca}"
export XIPKI_CA_HTTPS_PORT="${XIPKI_CA_HTTPS_PORT:-8444}"
export XIPKI_GATEWAY_HOST="${XIPKI_GATEWAY_HOST:-gateway}"
export XIPKI_OCSP_HOST="${XIPKI_OCSP_HOST:-ocsp}"

# Distributed preparation deliberately cannot access production database credentials. These
# unmistakable placeholders are materialized from node-local Secrets by xipki-role-init.
if [[ "${XIPKI_DEPLOYMENT_MODE}" == "distributed" && "${bootstrap_mode}" == "prepare" ]]; then
  export XIPKI_CA_DB_PASSWORD=__XIPKI_CA_DB_PASSWORD__
  export XIPKI_GATEWAY_DB_PASSWORD=__XIPKI_GATEWAY_DB_PASSWORD__
  export XIPKI_OCSP_DB_PASSWORD=__XIPKI_OCSP_DB_PASSWORD__
elif [[ "${bootstrap_mode}" == "check" && -n "${XIPKI_DB_CHECK_ROLE:-}" ]]; then
  # A distributed node mounts only its role-owned database Secret. The JDBC checker reads that
  # file directly; placeholder exports keep unrelated credentials out of the node contract.
  export XIPKI_CA_DB_PASSWORD=__XIPKI_UNUSED_CA_DB_PASSWORD__
  export XIPKI_GATEWAY_DB_PASSWORD=__XIPKI_UNUSED_GATEWAY_DB_PASSWORD__
  export XIPKI_OCSP_DB_PASSWORD=__XIPKI_UNUSED_OCSP_DB_PASSWORD__
else
  export XIPKI_CA_DB_PASSWORD="$(read_secret ca_db_password)"
  export XIPKI_GATEWAY_DB_PASSWORD="$(read_secret gateway_db_password)"
  export XIPKI_OCSP_DB_PASSWORD="$(read_secret ocsp_db_password)"
fi

case "${XIPKI_DATABASE}" in
  mariadb)
    readonly database_config_dir=mariadb
    ;;
  postgres)
    readonly database_config_dir=pgsql
    ;;
  *)
    fail "unsupported database: ${XIPKI_DATABASE} (expected mariadb or postgres)"
    ;;
esac

case "${XIPKI_DATABASE_MODE}" in
  managed|external) ;;
  *) fail "unsupported database mode: ${XIPKI_DATABASE_MODE} (expected managed or external)" ;;
esac

case "${XIPKI_DEPLOYMENT_MODE}" in
  standalone|distributed) ;;
  *) fail "unsupported deployment mode: ${XIPKI_DEPLOYMENT_MODE} (expected standalone or distributed)" ;;
esac

export XIPKI_DB_HOST="${XIPKI_DB_HOST:-database}"
if [[ -z "${XIPKI_DB_PORT:-}" ]]; then
  if [[ "${XIPKI_DATABASE}" == "mariadb" ]]; then
    export XIPKI_DB_PORT=3306
  else
    export XIPKI_DB_PORT=5432
  fi
fi
[[ "${XIPKI_DB_PORT}" =~ ^[0-9]+$ \
  && "${XIPKI_DB_PORT}" -ge 1 \
  && "${XIPKI_DB_PORT}" -le 65535 ]] \
  || fail "XIPKI_DB_PORT must be between 1 and 65535"
[[ "${XIPKI_CA_HTTPS_PORT}" =~ ^[0-9]+$ \
  && "${XIPKI_CA_HTTPS_PORT}" -ge 1 \
  && "${XIPKI_CA_HTTPS_PORT}" -le 65535 ]] \
  || fail "XIPKI_CA_HTTPS_PORT must be between 1 and 65535"

# Uses the same least-privilege identities as the runtime roles. This catches an unreachable,
# unauthorized, or uninitialized external database before publishing any generated role state.
check_database() {
  java -cp "/opt/xipki-bootstrap:/opt/xipki/xipki-mgmt-cli/lib/*" \
    org.xipki.container.ExternalDatabaseCheck
}

# Prevents a configuration edit from silently repointing persistent role state at another
# database or deployment topology. Pre-release marker formats are deliberately rejected.
validate_existing_database_state() {
  local stored_format stored_database stored_mode stored_host stored_port
  local stored_deployment_mode stored_deployment_name stored_ca_host stored_ca_port
  local stored_gateway_host stored_ocsp_host
  # A fresh preflight container has no persistent Bootstrap state. That is valid: there is
  # nothing to compare until initialization has written the deployment identity marker.
  [[ -f "${bootstrap_marker}" ]] || return 0

  stored_format="$(sed -n 's/^format=//p' "${bootstrap_marker}")"
  [[ "${stored_format}" == "4" ]] \
    || fail "existing Bootstrap state format is unsupported; reset the deployment state and initialize again"
  stored_database="$(sed -n 's/^database=//p' "${bootstrap_marker}")"
  [[ "${stored_database}" == "${XIPKI_DATABASE}" ]] \
    || fail "existing state uses ${stored_database}; choose it with XIPKI_DATABASE or start a new Compose project"
  stored_mode="$(sed -n 's/^mode=//p' "${bootstrap_marker}")"
  stored_host="$(sed -n 's/^host=//p' "${bootstrap_marker}")"
  stored_port="$(sed -n 's/^port=//p' "${bootstrap_marker}")"
  [[ "${stored_mode}" == "${XIPKI_DATABASE_MODE}" \
    && "${stored_host}" == "${XIPKI_DB_HOST}" \
    && "${stored_port}" == "${XIPKI_DB_PORT}" ]] \
    || fail "existing state uses database ${stored_mode} ${stored_host}:${stored_port}; start a new Compose project to change it"

  stored_deployment_mode="$(sed -n 's/^deployment-mode=//p' "${bootstrap_marker}")"
  stored_deployment_name="$(sed -n 's/^deployment-name=//p' "${bootstrap_marker}")"
  stored_ca_host="$(sed -n 's/^ca-host=//p' "${bootstrap_marker}")"
  stored_ca_port="$(sed -n 's/^ca-port=//p' "${bootstrap_marker}")"
  stored_gateway_host="$(sed -n 's/^gateway-host=//p' "${bootstrap_marker}")"
  stored_ocsp_host="$(sed -n 's/^ocsp-host=//p' "${bootstrap_marker}")"
  [[ "${stored_deployment_mode}" == "${XIPKI_DEPLOYMENT_MODE}" \
    && "${stored_deployment_name}" == "${XIPKI_DEPLOYMENT_NAME}" \
    && "${stored_ca_host}" == "${XIPKI_CA_HOST}" \
    && "${stored_ca_port}" == "${XIPKI_CA_HTTPS_PORT}" \
    && "${stored_gateway_host}" == "${XIPKI_GATEWAY_HOST}" \
    && "${stored_ocsp_host}" == "${XIPKI_OCSP_HOST}" ]] \
    || fail "existing state belongs to another deployment topology; start a new Compose project to change it"
}

if [[ "${bootstrap_mode}" == "initialize" || "${bootstrap_mode}" == "check" ]]; then
  check_database
fi
if [[ "${bootstrap_mode}" == "check" ]]; then
  validate_existing_database_state
  exit 0
fi

generate_service_secrets() {
  local name
  for name in \
    DEPLOYMENT_INTERNAL_CA_KEY_PASSWORD DUMMY_KEY_PASSWORD OCSP_KEY_PASSWORD \
    CA_KEY_PASSWORD CA_TRUSTSTORE_PASSWORD \
    GATEWAY_KEY_PASSWORD GATEWAY_TRUSTSTORE_PASSWORD GATEWAY_REQUESTOR_PASSWORD \
    RA_SDK_KEY_PASSWORD DH_POP_KEY_PASSWORD KEM_POP_KEY_PASSWORD SCEP_KEY_PASSWORD \
    CMP_CLIENT_CA_KEY_PASSWORD CMP_CLIENT_KEY_PASSWORD EST_CLIENT_CA_KEY_PASSWORD \
    EST_CLIENT_KEY_PASSWORD REST_CLIENT_CA_KEY_PASSWORD REST_CLIENT_KEY_PASSWORD \
    CA_MGMT_KEY_PASSWORD; do
    export "XIPKI_${name}=$(random_secret)"
  done
}

copy_ca_artifacts() {
  local work_dir="$1"
  local target="$2"
  install -d "${target}/conf" "${target}/xipki/keycerts"
  cp -a "${work_dir}/xipki-ca/tomcat/xipki/." "${target}/xipki/"
  cp "${work_dir}/xipki-ca/tomcat/conf/server.xml" "${target}/conf/server.xml"
  cp "${work_dir}/setup/keycerts/ca-server/"* \
    "${work_dir}/setup/keycerts/ca-mgmt-client/"*-cert.pem \
    "${work_dir}/setup/keycerts/certstore/ca-client-certstore.p12" \
    "${target}/xipki/keycerts/"
  cp "${target}/xipki/etc/ca/database/${database_config_dir}/"*-db.properties \
    "${target}/xipki/etc/ca/database/"
}

copy_admin_artifacts() {
  local work_dir="$1"
  local target="$2"
  install -d "${target}/xipki/keycerts" "${target}/deployment-ca" \
    "${target}/verification"
  cp -a "${work_dir}/xipki-mgmt-cli/xipki/etc" "${target}/xipki/"
  cp "${work_dir}/setup/keycerts/ca-mgmt-client/"* "${target}/xipki/keycerts/"
  cp "${work_dir}/setup/keycerts/CA-deployment-internal-ca/deployment-internal-ca-cert.pem" \
    "${target}/xipki/keycerts/ca-server-cert.pem"
  cp "${work_dir}/setup/keycerts/CA-deployment-internal-ca/"* "${target}/deployment-ca/"
  printf '%s' "${XIPKI_DEPLOYMENT_INTERNAL_CA_KEY_PASSWORD}" \
    > "${target}/deployment-ca/password"
  # The lifecycle verification identity is accepted only by Gateway's REST authenticator. It is
  # deliberately separate from the CA-management and browser-administrator identities.
  cp "${work_dir}/setup/keycerts/rest-client/rest-client.p12" \
    "${target}/verification/rest-client.p12"
  printf '%s' "${XIPKI_REST_CLIENT_KEY_PASSWORD}" \
    > "${target}/verification/rest-client.p12.password"
}

# Publishes only the management identity Console needs. Keeping this separate from
# admin-state prevents the web process from receiving CLI configuration it never uses.
copy_console_artifacts() {
  local work_dir="$1"
  local target="$2"
  install -d "${target}/client" "${target}/enrollment"
  cp "${work_dir}/setup/keycerts/ca-mgmt-client/ca-mgmt-client.p12" \
    "${target}/client/client.p12"
  cp "${work_dir}/setup/keycerts/CA-deployment-internal-ca/deployment-internal-ca-cert.pem" \
    "${target}/client/trustanchors.pem"
  cp "${work_dir}/setup/keycerts/ra-sdk-client/ra-sdk-client-cert.pem" \
    "${target}/client/gateway-ra-cert.pem"
  printf '%s' "${XIPKI_CA_MGMT_KEY_PASSWORD}" > "${target}/client/password"
}

copy_gateway_artifacts() {
  local work_dir="$1"
  local target="$2"
  install -d "${target}/conf" "${target}/xipki/keycerts"
  cp -a "${work_dir}/xipki-gateway/tomcat/xipki/." "${target}/xipki/"
  cp -a "${work_dir}/xipki-gateway/tomcat/conf/." "${target}/conf/"
  cp "${work_dir}/setup/keycerts/gateway-server/"* \
    "${work_dir}/setup/keycerts/ra-sdk-client/"* \
    "${work_dir}/setup/keycerts/cmp-client/"*-cert.pem \
    "${work_dir}/setup/keycerts/est-client/"*-cert.pem \
    "${work_dir}/setup/keycerts/rest-client/"*-cert.pem \
    "${work_dir}/setup/keycerts/certstore/gateway-client-ca-certstore.p12" \
    "${work_dir}/setup/keycerts/dh-pop/dh-pop.p12" \
    "${work_dir}/setup/keycerts/secretkeys/kem-pop.jceks" \
    "${target}/xipki/keycerts/"
  cp "${work_dir}/setup/keycerts/CA-deployment-internal-ca/deployment-internal-ca-cert.pem" \
    "${target}/xipki/keycerts/ca-server-cert.pem"
  cp "${target}/xipki/etc/acme/database/${database_config_dir}/acme-db.properties" \
    "${target}/xipki/etc/acme/database/"
}

copy_ocsp_artifacts() {
  local work_dir="$1"
  local target="$2"
  install -d "${target}/conf" "${target}/xipki/keycerts"
  cp -a "${work_dir}/xipki-ocsp/tomcat/xipki/." "${target}/xipki/"
  cp "${work_dir}/xipki-ocsp/tomcat/conf/server.xml" "${target}/conf/server.xml"
  cp "${work_dir}/setup/keycerts/ocsp1/"* "${target}/xipki/keycerts/"
  cp "${target}/xipki/etc/ocsp/database/${database_config_dir}/ca-db.properties" \
    "${target}/xipki/etc/ocsp/database/${database_config_dir}/ocsp-db.properties" \
    "${target}/xipki/etc/ocsp/database/"
}

prepare_artifacts() {
  local work_dir
  work_dir="$(mktemp -d "${bootstrap_state}/.prepare.XXXXXX")"
  trap 'rm -rf "${work_dir}"' RETURN

  cp -a "${setup_dir}/." "${work_dir}/"
  generate_service_secrets

  java -cp "${work_dir}/xipki-mgmt-cli/lib/*" \
    org.xipki.util.misc.BatchReplace "${work_dir}/setup/container-conf.json"
  java -cp "${work_dir}/xipki-mgmt-cli/lib/*" \
    org.xipki.pkix.util.GenerateCerts \
    "${work_dir}/setup/keycerts.json" "${work_dir}/setup/keycerts"

  local pending="${bootstrap_state}/.artifacts.pending"
  rm -rf "${pending}"
  install -d \
    "${pending}/admin" "${pending}/ca" "${pending}/console" \
    "${pending}/gateway" "${pending}/ocsp"
  copy_admin_artifacts "${work_dir}" "${pending}/admin"
  copy_ca_artifacts "${work_dir}" "${pending}/ca"
  copy_console_artifacts "${work_dir}" "${pending}/console"
  copy_gateway_artifacts "${work_dir}" "${pending}/gateway"
  copy_ocsp_artifacts "${work_dir}" "${pending}/ocsp"
  chmod -R go-rwx "${pending}"

  rm -rf "${artifacts_dir}"
  mv "${pending}" "${artifacts_dir}"
  printf 'format=4\ndatabase=%s\nmode=%s\nhost=%s\nport=%s\ndeployment-mode=%s\ndeployment-name=%s\nca-host=%s\nca-port=%s\ngateway-host=%s\nocsp-host=%s\n' \
    "${XIPKI_DATABASE}" "${XIPKI_DATABASE_MODE}" "${XIPKI_DB_HOST}" "${XIPKI_DB_PORT}" \
    "${XIPKI_DEPLOYMENT_MODE}" "${XIPKI_DEPLOYMENT_NAME}" "${XIPKI_CA_HOST}" \
    "${XIPKI_CA_HTTPS_PORT}" \
    "${XIPKI_GATEWAY_HOST}" "${XIPKI_OCSP_HOST}" \
    > "${bootstrap_marker}.tmp"
  mv "${bootstrap_marker}.tmp" "${bootstrap_marker}"
}

# Writes the runtime marker consumed by the unified image after a complete role directory exists.
write_role_marker() {
  local target_file="$1"
  local role="$2"
  printf 'format=1\nrole=%s\ndeployment=%s\n' "${role}" "${XIPKI_DEPLOYMENT_NAME}" \
    > "${target_file}"
}

# Atomically exports generated role directories for packaging without mounting runtime volumes.
export_roles() {
  local export_dir="${XIPKI_EXPORT_DIR:-}"
  local pending role
  [[ -n "${export_dir}" && "${export_dir}" != "/" ]] \
    || fail "XIPKI_EXPORT_DIR must name a non-root writable directory in prepare mode"
  install -d "${export_dir}"
  [[ -w "${export_dir}" ]] || fail "export directory is not writable: ${export_dir}"

  pending="${export_dir}/.roles.pending"
  rm -rf "${pending}"
  install -d "${pending}"
  for role in admin ca console gateway ocsp; do
    install -d "${pending}/${role}"
    cp -a "${artifacts_dir}/${role}/." "${pending}/${role}/"
    write_role_marker "${pending}/${role}/.initialized" "${role}"
  done
  cp "${bootstrap_marker}" "${pending}/deployment.properties"
  chmod -R go-rwx "${pending}"

  rm -rf "${export_dir}/roles"
  mv "${pending}" "${export_dir}/roles"
}

# Sanitizes generated distributed artifacts before every export. This preserves stable service
# identities while ensuring a control-host retry cannot package a node-local database password.
materialize_distributed_password_placeholders() {
  local role uppercase_role placeholder file replacements runtime_db_dir
  local domain uppercase_domain database_placeholder
  for role in ca gateway ocsp; do
    uppercase_role="$(printf '%s' "${role}" | tr '[:lower:]' '[:upper:]')"
    placeholder="__XIPKI_${uppercase_role}_DB_PASSWORD__"
    replacements=0
    while IFS= read -r -d '' file; do
      sed -E -i \
        "s|^([[:space:]]*dataSource\\.password[[:space:]]*=[[:space:]]*).*$|\\1${placeholder}|" \
        "${file}"
      if grep -q "${placeholder}" "${file}"; then
        replacements=$((replacements + 1))
      fi
    done < <(find "${artifacts_dir}/${role}/xipki" -type f -name '*-db.properties' -print0)
    (( replacements > 0 )) \
      || fail "no database properties were sanitized for distributed role ${role}"

    case "${role}" in
      ca) runtime_db_dir="${artifacts_dir}/ca/xipki/etc/ca/database" ;;
      gateway) runtime_db_dir="${artifacts_dir}/gateway/xipki/etc/acme/database" ;;
      ocsp) runtime_db_dir="${artifacts_dir}/ocsp/xipki/etc/ocsp/database" ;;
    esac
    replacements=0
    while IFS= read -r -d '' file; do
      domain="$(basename "${file}" -db.properties)"
      uppercase_domain="$(printf '%s' "${domain}" | tr '[:lower:]' '[:upper:]')"
      database_placeholder="__XIPKI_${uppercase_domain}_DB_NAME__"
      sed -E -i \
        -e "s|^([[:space:]]*dataSource\\.url[[:space:]]*=[[:space:]]*).*$|\\1jdbc:mariadb://__XIPKI_DB_HOST__:__XIPKI_DB_PORT__/${database_placeholder}|" \
        -e 's|^([[:space:]]*dataSource\.serverName[[:space:]]*=[[:space:]]*).*$|\1__XIPKI_DB_HOST__|' \
        -e 's|^([[:space:]]*dataSource\.portNumber[[:space:]]*=[[:space:]]*).*$|\1__XIPKI_DB_PORT__|' \
        -e 's|^([[:space:]]*dataSource\.user[[:space:]]*=[[:space:]]*).*$|\1__XIPKI_DB_USER__|' \
        -e "s|^([[:space:]]*dataSource\\.password[[:space:]]*=[[:space:]]*).*$|\\1${placeholder}|" \
        -e "s|^([[:space:]]*dataSource\\.databaseName[[:space:]]*=[[:space:]]*).*$|\\1${database_placeholder}|" \
        "${file}"
      replacements=$((replacements + 1))
    done < <(find "${runtime_db_dir}" -maxdepth 1 -type f -name '*-db.properties' -print0)
    (( replacements > 0 )) \
      || fail "no runtime database properties were templated for distributed role ${role}"
  done
}

publish_role() {
  local role="$1"
  local target="/state/${role}"
  local marker="${target}/.initialized"

  if [[ -f "${marker}" ]]; then
    if [[ "${role}" == "admin" ]]; then
      [[ -r "${target}/xipki/etc/ca-mgmt-client.json" ]] \
        || fail "${role} state is marked initialized but incomplete"
    elif [[ "${role}" == "console" ]]; then
      [[ -r "${target}/client/client.p12" \
        && -r "${target}/client/trustanchors.pem" \
        && -r "${target}/client/password" \
        && -d "${target}/enrollment" ]] \
        || fail "${role} state is marked initialized but incomplete"
    else
      [[ -r "${target}/conf/server.xml" && -d "${target}/xipki" ]] \
        || fail "${role} state is marked initialized but incomplete"
    fi
    return
  fi

  rm -rf "${target}/conf" "${target}/xipki"
  cp -a "${artifacts_dir}/${role}/." "${target}/"
  chmod -R go-rwx "${target}"
  write_role_marker "${marker}.tmp" "${role}"
  mv "${marker}.tmp" "${marker}"
}

if [[ -f "${bootstrap_marker}" ]]; then
  validate_existing_database_state
else
  # Persist the complete generated trust set before publishing any role. A
  # retry can then repair a partial role volume without rotating peer keys.
  prepare_artifacts
fi

[[ -d "${artifacts_dir}" ]] || fail "bootstrap state is marked initialized but artifacts are missing"
if [[ "${bootstrap_mode}" == "prepare" ]]; then
  materialize_distributed_password_placeholders
  export_roles
  printf 'XiPKI role configuration was prepared for export.\n'
  exit 0
fi
publish_role admin
publish_role ca
publish_role console
publish_role gateway
publish_role ocsp
printf 'XiPKI service configuration is initialized.\n'
