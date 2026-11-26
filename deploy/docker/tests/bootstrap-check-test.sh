#!/usr/bin/env bash

set -Eeuo pipefail

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${test_dir}/../../.." && pwd)"
bootstrap_script="${project_dir}/deploy/docker/bootstrap/bootstrap.sh"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/xipki-bootstrap-check.XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT

# Reads the reactor version so this test follows the same image tag as the release tooling.
project_version() {
  local line
  local version_pattern='<version>([^<]+)</version>'
  while IFS= read -r line; do
    if [[ "${line}" =~ ${version_pattern} ]]; then
      printf '%s\n' "${BASH_REMATCH[1]}"
      return
    fi
  done < "${project_dir}/pom.xml"
  echo 'bootstrap-check-test: could not read project version' >&2
  exit 1
}

version="$(project_version)"
image_prefix="${XIPKI_IMAGE_PREFIX:-docker.io/xipki}"
image="${XIPKI_BOOTSTRAP_TEST_IMAGE:-${image_prefix%/}/bootstrap:${version}}"

command -v docker >/dev/null 2>&1 || {
  echo 'bootstrap-check-test: docker is required' >&2
  exit 1
}
docker image inspect "${image}" >/dev/null 2>&1 || {
  printf 'bootstrap-check-test: test image is missing: %s\n' "${image}" >&2
  exit 1
}

# Replaces only the JDBC process so this test isolates the shell contract: a successful database
# check in a fresh preflight container must exit zero when no persistent Bootstrap marker exists.
mkdir -p "${work_dir}/bin"
cat > "${work_dir}/bin/java" <<'EOF'
#!/usr/bin/env bash
printf 'XiPKI database preflight passed for mariadb role ca at db.example.test:3306.\n'
EOF
chmod 0755 "${work_dir}/bin/java"
mkdir -p "${work_dir}/state"

# Runs the same check-mode contract against a caller-controlled persistent marker directory.
run_check() {
  docker run --rm \
    --user 0:0 \
    --mount "type=bind,src=${bootstrap_script},dst=/usr/local/bin/xipki-bootstrap,readonly" \
    --mount "type=bind,src=${work_dir}/bin,dst=/test-bin,readonly" \
    --mount "type=bind,src=${work_dir}/state,dst=/var/lib/xipki-bootstrap" \
    --entrypoint bash \
    --env PATH=/test-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --env XIPKI_BOOTSTRAP_MODE=check \
    --env XIPKI_DEPLOYMENT_MODE=distributed \
    --env XIPKI_DEPLOYMENT_NAME=production \
    --env XIPKI_CA_HOST=ca.example.test \
    --env XIPKI_CA_HTTPS_PORT=8444 \
    --env XIPKI_GATEWAY_HOST=gateway.example.test \
    --env XIPKI_OCSP_HOST=ocsp.example.test \
    --env XIPKI_DATABASE_MODE=external \
    --env XIPKI_DATABASE=mariadb \
    --env XIPKI_DB_CHECK_ROLE=ca \
    --env XIPKI_DB_HOST=db.example.test \
    --env XIPKI_DB_PORT=3306 \
    "${image}" /usr/local/bin/xipki-bootstrap
}

# Fresh state has no identity to compare, while a complete current marker must match exactly.
run_check
cat > "${work_dir}/state/.initialized" <<'EOF'
format=4
database=mariadb
mode=external
host=db.example.test
port=3306
deployment-mode=distributed
deployment-name=production
ca-host=ca.example.test
ca-port=8444
gateway-host=gateway.example.test
ocsp-host=ocsp.example.test
EOF
run_check

# An incomplete pre-release marker must fail instead of silently inheriting defaults.
sed -i.bak '/^format=/d' "${work_dir}/state/.initialized"
if output="$(run_check 2>&1)"; then
  echo 'bootstrap-check-test: unsupported marker unexpectedly passed' >&2
  exit 1
fi
[[ "${output}" == *'existing Bootstrap state format is unsupported'* ]] || {
  printf 'bootstrap-check-test: unexpected marker failure: %s\n' "${output}" >&2
  exit 1
}

echo 'XiPKI Bootstrap check-mode test passed.'
