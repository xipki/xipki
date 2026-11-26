#!/usr/bin/env bash

set -Eeuo pipefail

readonly host="${XIPKI_HEALTH_HOST:-127.0.0.1}"
readonly mode="${XIPKI_HEALTH_MODE:-tcp}"
readonly path="${XIPKI_HEALTH_PATH:-/health/ready}"

case "${XIPKI_ROLE:-}" in
  ca) default_port=8444 ;;
  gateway) default_port=8082 ;;
  ocsp) default_port=8080 ;;
  console) default_port=8443 ;;
  *)
    printf 'xipki-healthcheck: unsupported XIPKI_ROLE %s\n' "${XIPKI_ROLE:-}" >&2
    exit 2
    ;;
esac
readonly port="${XIPKI_HEALTH_PORT:-${default_port}}"

open_socket() {
  exec 3<>"/dev/tcp/${host}/${port}"
}

open_socket 2>/dev/null || exit 1

if [[ "${mode}" == "tcp" ]]; then
  exit 0
fi

if [[ "${mode}" != "http" ]]; then
  printf 'xipki-healthcheck: unsupported mode %s\n' "${mode}" >&2
  exit 2
fi

printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "${path}" "${host}" >&3
IFS=' ' read -r -t 3 _ status _ <&3 || exit 1

[[ "${status}" =~ ^2[0-9][0-9]$ ]]
