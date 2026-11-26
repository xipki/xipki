#!/usr/bin/env bash

set -Eeuo pipefail

readonly state_dir="${XIPKI_BASE:-/var/lib/xipki}"
readonly runtime_root="${XIPKI_RUNTIME_ROOT:-/opt/xipki-runtime}"
readonly role="${XIPKI_ROLE:-}"
readonly initialized_marker="${state_dir}/.initialized"

fail() {
  printf 'xipki-entrypoint: %s\n' "$*" >&2
  exit 1
}

case "${role}" in
  ca|gateway|ocsp|console) ;;
  *) fail "unsupported XIPKI_ROLE '${role}' (expected ca, gateway, ocsp, or console)" ;;
esac

if [[ "$(id -u)" == "0" ]]; then
  fail "refusing to run XiPKI as root"
fi

if [[ "${XIPKI_REQUIRE_INITIALIZED:-true}" == "true" && ! -f "${initialized_marker}" ]]; then
  # A missing marker means bootstrap did not finish. Starting with partial
  # configuration could create state that later initialization cannot repair.
  fail "${initialized_marker} is missing; run the bootstrap service first"
fi

umask 0027

# Start one servlet role from its isolated Tomcat base after validating bootstrap state and
# writable runtime directories. Keeping selection here prevents Compose from supplying commands.
start_tomcat_role() {
  local role_base="${runtime_root}/roles/${role}"
  local writable_dir

  [[ -r "${role_base}/conf/server.xml" ]] \
    || fail "bootstrap server configuration is missing for role ${role}"
  [[ -d "${role_base}/xipki" ]] || fail "bootstrap XiPKI state is missing for role ${role}"
  for writable_dir in "${role_base}/logs" "${role_base}/temp" "${role_base}/work"; do
    [[ -w "${writable_dir}" ]] || fail "required directory is not writable: ${writable_dir}"
  done

  export CATALINA_BASE="${role_base}"
  cd "${role_base}"
  exec "${CATALINA_HOME}/bin/catalina.sh" run
}

# Start the standalone Console only after its management identity and enrollment state are ready.
start_console() {
  local file

  for file in client/client.p12 client/trustanchors.pem client/password; do
    [[ -r "${state_dir}/${file}" ]] || fail "required Console artifact is missing: ${file}"
  done
  [[ -d "${state_dir}/enrollment" && -w "${state_dir}/enrollment" ]] \
    || fail "Console enrollment state directory is not writable"
  [[ -r "${runtime_root}/console/console.jar" ]] || fail "Console application is missing"

  cd "${runtime_root}/console"
  exec java -jar "${runtime_root}/console/console.jar"
}

# XIPKI_ROLE is the complete runtime interface. Role-specific commands, paths, and health defaults
# stay inside the image so Compose cannot accidentally deploy multiple applications in one process.
case "${role}" in
  ca|gateway|ocsp)
    start_tomcat_role
    ;;
  console)
    start_console
    ;;
  *)
    fail "unsupported XIPKI_ROLE '${role}' (expected ca, gateway, ocsp, or console)"
    ;;
esac
