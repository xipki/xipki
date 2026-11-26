#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/../../.." && pwd)"
release_script="${project_dir}/deploy/release/images.sh"

# Reads the reactor version without starting Maven so the release archive contract remains fast
# and can run on a clean packaging host.
project_version() {
  local line
  local version_pattern='<version>([^<]+)</version>'
  while IFS= read -r line; do
    if [[ "${line}" =~ ${version_pattern} ]]; then
      printf '%s\n' "${BASH_REMATCH[1]}"
      return
    fi
  done < "${project_dir}/pom.xml"
  echo 'bundle-test: could not read project version' >&2
  exit 1
}

# Inspects the raw archive table because macOS bsdtar consumes AppleDouble entries
# as metadata and hides both them and their extended headers from ordinary listings.
assert_no_macos_metadata() {
  local archive="$1"
  python3 - "${archive}" <<'PY'
import sys
import tarfile

archive = sys.argv[1]
with tarfile.open(archive, "r:gz") as stream:
    members = stream.getmembers()

appledouble_entries = [
    member.name
    for member in members
    if member.name.rsplit("/", 1)[-1].startswith("._")
]
extended_headers = [
    f"{member.name}: {key}"
    for member in members
    for key in member.pax_headers
    if key.startswith("LIBARCHIVE.xattr.")
]

if appledouble_entries or extended_headers:
    print("bundle-test: release archive contains macOS metadata", file=sys.stderr)
    for entry in appledouble_entries + extended_headers:
        print(f"  {entry}", file=sys.stderr)
    raise SystemExit(1)
PY
}

version="$(project_version)"
bundle="${project_dir}/deploy/release/target/xipki-deploy-${version}.tar.gz"
prefix="xipki-deploy-${version}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/xipki-bundle.XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT

# Build once: all archive assertions below must describe the exact same release artifact.
"${release_script}" bundle >/dev/null
assert_no_macos_metadata "${bundle}"
tar -xzf "${bundle}" -C "${work_dir}"

grep -Fxq "XIPKI_VERSION=${version}" "${work_dir}/${prefix}/.env" \
  || { echo 'bundle-test: packaged image version does not match the Maven project' >&2; exit 1; }
grep -Fxq 'XIPKI_IMAGE_PREFIX=docker.io/xipki' "${work_dir}/${prefix}/.env" \
  || { echo 'bundle-test: packaged image namespace is not Docker Hub' >&2; exit 1; }
if "${release_script}" bundle "${version}" >/dev/null 2>&1; then
  echo 'bundle-test: release script still accepted a redundant version argument' >&2
  exit 1
fi

for path in \
  README.md \
  database/README.md \
  distributed/README.md \
  distributed/node-README.md \
  distributed/node.sh \
  distributed/gateway-verify.sh; do
  [[ -f "${work_dir}/${prefix}/${path}" ]] \
    || { echo "bundle-test: release archive is missing ${path}" >&2; exit 1; }
done

[[ -x "${work_dir}/${prefix}/container.sh" \
  && -x "${work_dir}/${prefix}/distributed/node.sh" \
  && -x "${work_dir}/${prefix}/distributed/gateway-verify.sh" ]] \
  || { echo 'bundle-test: a packaged launcher is not executable' >&2; exit 1; }

cmp "${project_dir}/deploy/release/deployment-README.md" \
  "${work_dir}/${prefix}/README.md" >/dev/null \
  || { echo 'bundle-test: packaged user guide is stale' >&2; exit 1; }
cmp "${project_dir}/deploy/compose/external-db/README.md" \
  "${work_dir}/${prefix}/database/README.md" >/dev/null \
  || { echo 'bundle-test: packaged database guide is stale' >&2; exit 1; }

# The deployment bundle intentionally excludes optional audit and OCSP-cache schemas. Comparing
# the complete extracted directory prevents newly copied SQL from silently becoming required.
actual="$({
  cd "${work_dir}/${prefix}/database"
  find . -type f -print | sed 's#^\./##' | sort
})"
expected="$(cat <<'EOF' | sort
README.md
mariadb/acme-init.mysql.sql
mariadb/ca-init.mysql.sql
mariadb/caconf-init.mysql.sql
mariadb/keypool-init.mysql.sql
mariadb/ocsp-init.mysql.sql
postgres/acme-init.postgresql.sql
postgres/ca-init.postgresql.sql
postgres/caconf-init.postgresql.sql
postgres/keypool-init.postgresql.sql
postgres/ocsp-init.postgresql.sql
EOF
)"

if [[ "${actual}" != "${expected}" ]]; then
  echo 'bundle-test: deployment archive contains an unexpected database file set' >&2
  diff <(printf '%s\n' "${expected}") <(printf '%s\n' "${actual}") >&2 || true
  exit 1
fi

echo 'XiPKI deployment bundle contract test passed.'
