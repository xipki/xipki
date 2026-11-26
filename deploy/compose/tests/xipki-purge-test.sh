#!/usr/bin/env bash

set -euo pipefail

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_dir="$(cd "${test_dir}/.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/xipki-purge-test.XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT

fixture_dir="${work_dir}/compose"
fake_bin="${work_dir}/bin"
docker_log="${work_dir}/docker.log"
mkdir -p "${fixture_dir}/.state/secrets" "${fake_bin}"
cp "${compose_dir}/container.sh" \
  "${compose_dir}/compose.yaml" \
  "${compose_dir}/compose.mariadb.yaml" \
  "${compose_dir}/compose.postgres.yaml" \
  "${compose_dir}/compose.external-db.yaml" \
  "${fixture_dir}/"
cp "${test_dir}/fixtures/docker" "${fake_bin}/docker"
touch "${docker_log}"
printf 'keep-me\n' > "${fixture_dir}/.state/secrets/admin-password"

set +e
output="$(
  printf 'WRONG\n' \
    | PATH="${fake_bin}:${PATH}" \
      XIPKI_TEST_DOCKER_LOG="${docker_log}" \
      XIPKI_COMPOSE_PROJECT=demo \
      "${fixture_dir}/container.sh" purge 2>&1
)"
status=$?
set -e

[[ ${status} -ne 0 ]] || {
  echo "purge accepted an incorrect confirmation" >&2
  exit 1
}
[[ "${output}" == *"Type DELETE demo to continue"* ]] || {
  echo "purge did not explain the required confirmation" >&2
  exit 1
}
[[ -f "${fixture_dir}/.state/secrets/admin-password" ]] || {
  echo "purge removed state after an incorrect confirmation" >&2
  exit 1
}
[[ ! -s "${docker_log}" ]] || {
  echo "purge called Docker after an incorrect confirmation" >&2
  exit 1
}

output="$(
  printf 'DELETE demo\n' \
    | PATH="${fake_bin}:${PATH}" \
      XIPKI_TEST_DOCKER_LOG="${docker_log}" \
      XIPKI_COMPOSE_PROJECT=demo \
      "${fixture_dir}/container.sh" purge 2>&1
)"

[[ "$(<"${docker_log}")" == *"down --volumes --remove-orphans"* ]] || {
  echo "purge did not remove Compose data volumes and orphaned containers" >&2
  exit 1
}
[[ ! -e "${fixture_dir}/.state" ]] || {
  echo "purge did not remove local credentials and certificates" >&2
  exit 1
}
[[ "${output}" == *"Deployment demo was permanently erased"* ]] || {
  echo "purge did not report completion" >&2
  exit 1
}

echo "xipki purge tests passed"
