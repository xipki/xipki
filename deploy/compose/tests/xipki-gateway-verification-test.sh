#!/usr/bin/env bash

set -Eeuo pipefail

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_dir="$(cd "${test_dir}/.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/xipki-gateway-verification-test.XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT

verification_dir="${work_dir}/verification"
fake_bin="${work_dir}/bin"
test_tmp="${work_dir}/tmp"
mkdir -p "${verification_dir}" "${fake_bin}" "${test_tmp}"
cp "${compose_dir}/distributed/gateway-verify.sh" "${verification_dir}/verify.sh"
chmod 0755 "${verification_dir}/verify.sh"
printf 'fixture-rest-client\n' > "${verification_dir}/rest-client.p12"
printf 'fixture-password' > "${verification_dir}/rest-client.p12.password"
printf 'fixture-gateway-anchor\n' > "${verification_dir}/gateway-server-trustanchors.pem"

# Simulates Gateway resources and changes the OCSP fixture only after permanent revocation.
cat > "${fake_bin}/curl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
output=""
headers=""
write_code=false
url=""
read_config=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --dump-header) headers="$2"; shift 2 ;;
    --write-out) write_code=true; shift 2 ;;
    --config) [[ "$2" == "-" ]] && read_config=true; shift 2 ;;
    --cacert|--max-time|--header|--data-binary|--request) shift 2 ;;
    --silent|--show-error|--fail) shift ;;
    http://*|https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
[[ "${read_config}" == "false" ]] || cat >/dev/null
[[ -z "${headers}" ]] || printf 'HTTP/1.1 200 OK\n' > "${headers}"
if [[ -n "${output}" && "${output}" != "/dev/null" ]]; then
  case "${url}" in
    */cacert) printf 'fixture-ca-certificate\n' > "${output}" ;;
    */enroll-cert?*) printf 'fixture-issued-certificate\n' > "${output}" ;;
    *) : > "${output}" ;;
  esac
fi
case "${url}" in
  *'/revoke-cert?'*'reason=cessationOfOperation'*)
    printf 'revoked' > "${XIPKI_TEST_OCSP_STATE}"
    ;;
esac
[[ "${write_code}" == "false" ]] || printf '200'
EOF
chmod 0755 "${fake_bin}/curl"

# Produces only the files and output shapes consumed by the verification script.
cat > "${fake_bin}/openssl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
command="$1"
shift
case "${command}" in
  genpkey)
    while [[ $# -gt 0 ]]; do
      [[ "$1" == "-out" ]] && { printf 'private-key\n' > "$2"; exit 0; }
      shift
    done
    ;;
  req)
    subject=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -subj) subject="$2"; shift 2 ;;
        -out)
          printf '%s\n' "${subject}" > "${XIPKI_TEST_CSR_SUBJECT}"
          printf 'csr\n' > "$2"
          exit 0
          ;;
        *) shift ;;
      esac
    done
    ;;
  x509)
    input=""
    output=""
    serial=false
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -in) input="$2"; shift 2 ;;
        -out) output="$2"; shift 2 ;;
        -serial) serial=true; shift ;;
        *) shift ;;
      esac
    done
    if [[ "${serial}" == "true" ]]; then
      echo 'serial=0123AB'
    elif [[ -n "${output}" ]]; then
      cp "${input}" "${output}"
    fi
    ;;
  verify) exit 0 ;;
  sha1) echo 'SHA1(fixture)= aabbccdd' ;;
  ocsp)
    state="$(<"${XIPKI_TEST_OCSP_STATE}")"
    printf 'certificate.pem: %s\n' "${state}"
    ;;
  *) echo "unsupported fake openssl command: ${command}" >&2; exit 1 ;;
esac
EOF
chmod 0755 "${fake_bin}/openssl"

ocsp_state="${work_dir}/ocsp.state"
csr_subject="${work_dir}/csr.subject"
printf 'good' > "${ocsp_state}"
output="$({
  PATH="${fake_bin}:${PATH}" \
  TMPDIR="${test_tmp}" \
  XIPKI_TEST_OCSP_STATE="${ocsp_state}" \
  XIPKI_TEST_CSR_SUBJECT="${csr_subject}" \
  XIPKI_GATEWAY_HOST=gateway.example.test \
  XIPKI_GATEWAY_HTTPS_PORT=18445 \
  XIPKI_OCSP_HOST=ocsp.example.test \
  XIPKI_OCSP_HTTP_PORT=18080 \
    "${verification_dir}/verify.sh"
})"

[[ "${output}" == *'[PASS] Gateway enrolled and returned a valid certificate'* \
  && "${output}" == *'[PASS] OCSP certificate status is good'* \
  && "${output}" == *'[PASS] Gateway permanently revoked the certificate'* \
  && "${output}" == *'[PASS] OCSP certificate status is revoked'* \
  && "${output}" == *'XiPKI Gateway certificate lifecycle verification passed'* ]] \
  || { echo 'Gateway lifecycle verification did not complete' >&2; exit 1; }
[[ "$(<"${ocsp_state}")" == revoked ]] \
  || { echo 'Gateway verification did not permanently revoke the certificate' >&2; exit 1; }
# The production Quick Start server profile rejects a single-label common name as badCertTemplate.
[[ "$(<"${csr_subject}")" =~ /CN=verify-[0-9]{14}\.example\.org$ ]] \
  || { echo 'Gateway verification CSR common name is not an FQDN' >&2; exit 1; }
[[ -z "$(find "${test_tmp}" -mindepth 1 -print -quit)" ]] \
  || { echo 'Gateway verification retained disposable private material' >&2; exit 1; }

echo 'XiPKI Gateway certificate verification test passed.'
