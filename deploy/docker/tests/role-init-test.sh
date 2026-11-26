#!/usr/bin/env bash

set -Eeuo pipefail

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${test_dir}/../../.." && pwd)"
role_init_script="${project_dir}/deploy/docker/common/role-init.sh"

# Reads the reactor version so the test always targets the image built from this checkout.
project_version() {
  local line
  local version_pattern='<version>([^<]+)</version>'
  while IFS= read -r line; do
    if [[ "${line}" =~ ${version_pattern} ]]; then
      printf '%s\n' "${BASH_REMATCH[1]}"
      return
    fi
  done < "${project_dir}/pom.xml"
  echo 'role-init-test: could not read project version' >&2
  exit 1
}

version="$(project_version)"
image_prefix="${XIPKI_IMAGE_PREFIX:-docker.io/xipki}"
image="${XIPKI_ROLE_INIT_TEST_IMAGE:-${image_prefix%/}/xipki:${version}}"

command -v docker >/dev/null 2>&1 || {
  echo 'role-init-test: docker is required' >&2
  exit 1
}
docker image inspect "${image}" >/dev/null 2>&1 || {
  printf 'role-init-test: test image is missing: %s\n' "${image}" >&2
  exit 1
}

# A pre-release seed without the current format marker must fail instead of being interpreted.
if output="$(docker run --rm \
  --user 0:0 \
  --mount "type=bind,src=${role_init_script},dst=/usr/local/bin/xipki-role-init,readonly" \
  --entrypoint bash \
  --env XIPKI_ROLE=console \
  --env XIPKI_DEPLOYMENT_NAME=role-init-test \
  "${image}" -lc '
    set -Eeuo pipefail
    install -d /seed/client /seed/enrollment
    printf "role=console\ndeployment=role-init-test\n" > /seed/.initialized
    printf x > /seed/client/client.p12
    printf x > /seed/client/trustanchors.pem
    printf x > /seed/client/password
    /usr/local/bin/xipki-role-init
  ' 2>&1)"; then
  echo 'role-init-test: unsupported role marker unexpectedly passed' >&2
  exit 1
fi
[[ "${output}" == *'unsupported role marker format: missing'* ]] || {
  printf 'role-init-test: unexpected marker failure: %s\n' "${output}" >&2
  exit 1
}

# Exercises the real initialization entrypoint inside the release runtime. Console deliberately
# skips database materialization, and that successful no-op must not terminate the script under
# `set -e`. Running it twice also verifies that an initialized role volume remains idempotent.
docker run --rm \
  --user 0:0 \
  --mount "type=bind,src=${role_init_script},dst=/usr/local/bin/xipki-role-init,readonly" \
  --entrypoint bash \
  --env XIPKI_ROLE=console \
  --env XIPKI_DEPLOYMENT_NAME=role-init-test \
  "${image}" -lc '
    set -Eeuo pipefail
    install -d /seed/client /seed/enrollment
    printf "format=1\nrole=console\ndeployment=role-init-test\n" > /seed/.initialized
    printf x > /seed/client/client.p12
    printf x > /seed/client/trustanchors.pem
    printf x > /seed/client/password
    /usr/local/bin/xipki-role-init
    test -r /var/lib/xipki/.initialized
    /usr/local/bin/xipki-role-init
  '

# Verifies the supported OCSP database pair materializes completely after optional cache and CRL
# templates have been removed by distributed packaging. The password is an isolated test value.
docker run --rm \
  --user 0:0 \
  --mount "type=bind,src=${role_init_script},dst=/usr/local/bin/xipki-role-init,readonly" \
  --entrypoint bash \
  --env XIPKI_ROLE=ocsp \
  --env XIPKI_DEPLOYMENT_NAME=role-init-test \
  --env XIPKI_BASE=/tmp/role-state \
  --env XIPKI_DB_HOST=db.example.test \
  --env XIPKI_DB_PORT=3306 \
  --env XIPKI_DB_USER=xipki_ocsp \
  --env XIPKI_CA_DB_NAME=ca \
  --env XIPKI_OCSP_DB_NAME=ocsp \
  "${image}" -lc '
    set -Eeuo pipefail
    install -d /seed/conf /seed/xipki/etc/ocsp/database /tmp/role-state /run/secrets
    printf "format=1\nrole=ocsp\ndeployment=role-init-test\n" > /seed/.initialized
    printf "<Server/>\n" > /seed/conf/server.xml
    printf test-password > /run/secrets/ocsp_db_password
    for specification in ca:CA ocsp:OCSP; do
      filename="${specification%%:*}"
      placeholder="${specification##*:}"
      printf "dataSource.url=jdbc:mariadb://__XIPKI_DB_HOST__:__XIPKI_DB_PORT__/__XIPKI_%s_DB_NAME__\ndataSource.user=__XIPKI_DB_USER__\ndataSource.password=__XIPKI_OCSP_DB_PASSWORD__\n" \
        "${placeholder}" > "/seed/xipki/etc/ocsp/database/${filename}-db.properties"
    done
    /usr/local/bin/xipki-role-init
    ! grep -R -q "__XIPKI_" /tmp/role-state/xipki
  '

echo 'XiPKI role initialization test passed.'
