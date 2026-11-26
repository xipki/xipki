#!/usr/bin/env bash

set -Eeuo pipefail
umask 0077

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_dir=""

fail() {
  printf 'xipki-gateway-verify: %s\n' "$*" >&2
  exit 1
}

# Removes the disposable certificate private key and all protocol scratch files on every exit.
cleanup() {
  [[ -z "${work_dir}" || ! -d "${work_dir}" ]] || rm -rf -- "${work_dir}"
}
trap cleanup EXIT

# Fails before network activity when the Gateway host lacks a required verification command.
require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

# Runs one authenticated Gateway REST request without exposing the PKCS#12 password in argv.
gateway_request() {
  local output="$1"
  local headers="$2"
  shift 2
  local password code
  password="$(tr -d '\r\n' < "${script_dir}/rest-client.p12.password")"
  [[ -n "${password}" ]] || fail "REST client password is empty"
  code="$({
      printf 'cert-type = "P12"\n'
      printf 'cert = "%s:%s"\n' "${script_dir}/rest-client.p12" "${password}"
      printf 'cacert = "%s"\n' "${script_dir}/gateway-server-trustanchors.pem"
    } | curl --config - --silent --show-error --max-time 20 \
      --dump-header "${headers}" --output "${output}" --write-out '%{http_code}' "$@")" \
    || fail "Gateway REST transport failed"
  if [[ ! "${code}" =~ ^2[0-9][0-9]$ ]]; then
    printf 'Gateway REST request failed with HTTP %s.\n' "${code}" >&2
    grep -i '^X-XIPKI-' "${headers}" >&2 || true
    [[ ! -s "${output}" ]] || sed 's/^/  /' "${output}" >&2
    return 1
  fi
}

# Polls OCSP because the responder may observe the shared CA database shortly after Gateway writes.
wait_for_ocsp_status() {
  local expected="$1"
  local deadline=$((SECONDS + 90))
  local output=""
  while (( SECONDS < deadline )); do
    output="$(openssl ocsp -no_nonce -noverify \
      -issuer "${work_dir}/cacert.pem" -cert "${work_dir}/certificate.pem" \
      -url "http://${XIPKI_OCSP_HOST}:${XIPKI_OCSP_HTTP_PORT}/ocsp/" 2>&1 || true)"
    if grep -Eq ": ${expected}([[:space:]]|$)" <<<"${output}"; then
      printf '[PASS] OCSP certificate status is %s\n' "${expected}"
      return
    fi
    sleep 3
  done
  printf '%s\n' "${output}" >&2
  fail "OCSP did not report ${expected} within 90 seconds"
}

# Exercises the end-user path: Gateway REST -> CA RA SDK -> shared database -> OCSP.
verify_certificate_lifecycle() {
  local gateway_base="https://${XIPKI_GATEWAY_HOST}:${XIPKI_GATEWAY_HTTPS_PORT}/rest/quickstart"
  # The Quick Start TLS profile requires an FQDN and derives the DNS SAN from the common name.
  local subject="/O=XiPKI Verification/CN=verify-$(date -u +%Y%m%d%H%M%S).example.org"
  local serial_raw serial ca_sha1

  curl --fail --silent --show-error --max-time 10 \
    --cacert "${script_dir}/gateway-server-trustanchors.pem" \
    --output "${work_dir}/cacert.der" "${gateway_base}/cacert" \
    || fail "Quick Start CA is unavailable through Gateway"
  openssl x509 -inform DER -in "${work_dir}/cacert.der" -out "${work_dir}/cacert.pem"

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "${work_dir}/private-key.pem" >/dev/null 2>&1
  openssl req -new -sha256 -key "${work_dir}/private-key.pem" -subj "${subject}" \
    -outform DER -out "${work_dir}/request.csr"
  gateway_request "${work_dir}/certificate.der" "${work_dir}/enroll.headers" \
    --header 'Content-Type: application/pkcs10' \
    --data-binary "@${work_dir}/request.csr" \
    "${gateway_base}/enroll-cert?profile=quickstart-tls-server"
  openssl x509 -inform DER -in "${work_dir}/certificate.der" \
    -out "${work_dir}/certificate.pem"
  openssl verify -CAfile "${work_dir}/cacert.pem" "${work_dir}/certificate.pem" >/dev/null \
    || fail "Gateway returned a certificate outside the Quick Start CA chain"
  printf '[PASS] Gateway enrolled and returned a valid certificate\n'

  serial_raw="$(openssl x509 -in "${work_dir}/certificate.pem" -noout -serial | cut -d= -f2)"
  serial_raw="${serial_raw#0X}"
  serial_raw="${serial_raw#0x}"
  serial="0X${serial_raw}"
  ca_sha1="$(openssl sha1 "${work_dir}/cacert.der" | awk '{print $NF}')"
  wait_for_ocsp_status good

  gateway_request "${work_dir}/revoke.body" "${work_dir}/revoke.headers" \
    --request POST \
    "${gateway_base}/revoke-cert?ca-sha1=${ca_sha1}&serial-number=${serial}&reason=cessationOfOperation"
  printf '[PASS] Gateway permanently revoked the certificate\n'
  wait_for_ocsp_status revoked
  printf 'XiPKI Gateway certificate lifecycle verification passed (serial=%s).\n' "${serial}"
}

# Keeps the verification interface intentionally small: one command proves the complete lifecycle.
main() {
  local material
  [[ $# -eq 0 ]] || fail "verify does not accept arguments"
  require_command curl
  require_command openssl
  for material in rest-client.p12 rest-client.p12.password gateway-server-trustanchors.pem; do
    [[ -s "${script_dir}/${material}" ]] || fail "verification material is missing: ${material}"
  done
  : "${XIPKI_GATEWAY_HOST:?missing XIPKI_GATEWAY_HOST}"
  : "${XIPKI_GATEWAY_HTTPS_PORT:?missing XIPKI_GATEWAY_HTTPS_PORT}"
  : "${XIPKI_OCSP_HOST:?missing XIPKI_OCSP_HOST}"
  : "${XIPKI_OCSP_HTTP_PORT:?missing XIPKI_OCSP_HTTP_PORT}"
  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/xipki-gateway-verify.XXXXXX")"
  verify_certificate_lifecycle
}

main "$@"
