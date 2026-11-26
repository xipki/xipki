#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_file="${script_dir}/compose.yaml"
database="${XIPKI_DATABASE:-mariadb}"
database_mode="${XIPKI_DATABASE_MODE:-managed}"
case "${database}" in
  mariadb|postgres) ;;
  *)
    echo "Unsupported XIPKI_DATABASE: ${database} (expected mariadb or postgres)" >&2
    exit 1
    ;;
esac
case "${database_mode}" in
  managed) database_compose_file="${script_dir}/compose.${database}.yaml" ;;
  external) database_compose_file="${script_dir}/compose.external-db.yaml" ;;
  *)
    echo "Unsupported XIPKI_DATABASE_MODE: ${database_mode} (expected managed or external)" >&2
    exit 1
    ;;
esac
project_name="${XIPKI_COMPOSE_PROJECT:-xipki}"
compose=(docker compose --project-name "${project_name}" -f "${compose_file}" -f "${database_compose_file}")
timeout_seconds="${XIPKI_SMOKE_TIMEOUT_SECONDS:-120}"
smoke_host="${XIPKI_SMOKE_HOST:-127.0.0.1}"

container_id() {
  "${compose[@]}" ps -a -q "$1"
}

container_state() {
  local id
  id="$(container_id "$1")"
  if [[ -z "${id}" ]]; then
    echo absent
    return
  fi
  docker inspect --format '{{.State.Status}}' "${id}"
}

container_health() {
  local id
  id="$(container_id "$1")"
  if [[ -z "${id}" ]]; then
    echo absent
    return
  fi
  docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${id}"
}

wait_for_bootstrap() {
  local deadline=$((SECONDS + timeout_seconds))
  local id state exit_code

  while ((SECONDS < deadline)); do
    id="$(container_id bootstrap)"
    if [[ -n "${id}" ]]; then
      state="$(docker inspect --format '{{.State.Status}}' "${id}")"
      if [[ "${state}" == "exited" ]]; then
        exit_code="$(docker inspect --format '{{.State.ExitCode}}' "${id}")"
        if [[ "${exit_code}" == "0" ]]; then
          return
        fi
        echo "Bootstrap failed with exit code ${exit_code}." >&2
        "${compose[@]}" logs --no-color bootstrap >&2
        exit 1
      fi
    fi
    sleep 2
  done

  echo "Timed out waiting for bootstrap after ${timeout_seconds}s." >&2
  exit 1
}

wait_for_healthy_service() {
  local service="$1"
  local deadline=$((SECONDS + timeout_seconds))
  local state health

  while ((SECONDS < deadline)); do
    state="$(container_state "${service}")"
    health="$(container_health "${service}")"
    if [[ "${health}" == "healthy" ]]; then
      return
    fi
    if [[ "${state}" == "exited" || "${state}" == "dead" ]]; then
      echo "${service} stopped before becoming healthy." >&2
      "${compose[@]}" logs --no-color "${service}" >&2
      exit 1
    fi
    sleep 2
  done

  echo "Timed out waiting for ${service} health after ${timeout_seconds}s." >&2
  "${compose[@]}" logs --no-color "${service}" >&2
  exit 1
}

check_endpoint() {
  local name="$1"
  local url="$2"
  shift 2

  # XiPKI protocol roots may legitimately return 404. curl's default exit code
  # still proves that the listener accepted the request and sent an HTTP response.
  if ! curl --silent --show-error --output /dev/null --max-time 5 "$@" "${url}"; then
    echo "Endpoint is not reachable: ${name} (${url})" >&2
    exit 1
  fi
}

ca_key_hash() {
  "${compose[@]}" exec -T ca sha256sum \
    /var/lib/xipki/xipki/keycerts/ca-server.p12 | awk '{print $1}'
}

# Enforce the packaging contract: the four independently configured services must execute the
# same immutable image, while XIPKI_ROLE remains the only selector for their runtime behavior.
assert_unified_runtime_contract() {
  local service role id image_id configured_role expected_image_id=""

  while read -r service role; do
    id="$(container_id "${service}")"
    image_id="$(docker inspect --format '{{.Image}}' "${id}")"
    configured_role="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${id}" \
      | awk -F= '$1 == "XIPKI_ROLE" {print substr($0, index($0, "=") + 1)}')"

    if [[ "${configured_role}" != "${role}" ]]; then
      echo "${service} has XIPKI_ROLE=${configured_role:-<unset>}; expected ${role}." >&2
      exit 1
    fi
    if [[ -z "${expected_image_id}" ]]; then
      expected_image_id="${image_id}"
    elif [[ "${image_id}" != "${expected_image_id}" ]]; then
      echo "${service} does not use the shared XiPKI runtime image." >&2
      exit 1
    fi
  done <<'EOF'
ca ca
console console
gateway gateway
ocsp ocsp
EOF
}

check_stack() {
  local service
  wait_for_bootstrap
  if [[ "${database_mode}" == "managed" ]]; then
    wait_for_healthy_service database
  fi
  for service in ca console gateway ocsp; do
    wait_for_healthy_service "${service}"
  done
  assert_unified_runtime_contract

  check_endpoint gateway-http \
    "http://${smoke_host}:${XIPKI_GATEWAY_HTTP_PORT:-18082}/"
  check_endpoint gateway-https \
    "https://${smoke_host}:${XIPKI_GATEWAY_HTTPS_PORT:-18445}/" --insecure
  check_endpoint ocsp-http \
    "http://${smoke_host}:${XIPKI_OCSP_HTTP_PORT:-18080}/"
  check_endpoint console \
    "https://${smoke_host}:${XIPKI_CONSOLE_HTTPS_PORT:-18081}/health/ready" --insecure
}

main() {
  local before_hash after_hash
  if ! command -v curl >/dev/null 2>&1; then
    echo "Required command not found: curl" >&2
    exit 1
  fi

  check_stack

  if [[ "${1:-}" == "--restart" ]]; then
    before_hash="$(ca_key_hash)"
    if [[ "${database_mode}" == "managed" ]]; then
      "${compose[@]}" restart database ca console gateway ocsp
    else
      "${compose[@]}" restart ca console gateway ocsp
    fi
    check_stack
    after_hash="$(ca_key_hash)"
    if [[ "${before_hash}" != "${after_hash}" ]]; then
      echo "CA bootstrap key changed after restart." >&2
      exit 1
    fi
  elif [[ $# -gt 0 ]]; then
    echo "Unknown option: $1" >&2
    exit 2
  fi

  "${compose[@]}" ps -a
  echo "XiPKI Compose smoke test passed."
}

main "$@"
