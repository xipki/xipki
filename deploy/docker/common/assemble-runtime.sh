#!/usr/bin/env bash

set -Eeuo pipefail

readonly setup_dir="${1:?usage: assemble-runtime <xipki setup directory>}"
readonly jars_dir="${setup_dir}/setup/jars"
readonly cli_lib="${setup_dir}/xipki-mgmt-cli/lib"
readonly crypto_overlay="${setup_dir}/.container-war-crypto"

copy_matches() {
  local target="$1"
  shift
  local pattern match found=false

  for pattern in "$@"; do
    for match in ${pattern}; do
      [[ -e "${match}" ]] || continue
      cp "${match}" "${target}/"
      found=true
    done
  done

  [[ "${found}" == "true" ]] || {
    printf 'assemble-runtime: no files matched for %s\n' "$*" >&2
    exit 1
  }
}

# Adds only the pluggable crypto backend omitted from the application WAR. The latest upstream
# WARs already contain their normal runtime dependencies, so copying CLI libraries would create a
# second, potentially incompatible dependency set inside the web application.
add_crypto_backend() {
  local war="$1"
  [[ -f "${war}" ]] || {
    printf 'assemble-runtime: WAR not found: %s\n' "${war}" >&2
    exit 1
  }
  jar --update --file "${war}" -C "${crypto_overlay}" WEB-INF
}

rm -rf "${crypto_overlay}"
install -d "${crypto_overlay}/WEB-INF/lib"

# Bootstrap executes the certificate generator from the management CLI. Its
# pluggable crypto implementation and JDBC driver are packaged outside the CLI
# archive, so make them available before building the role WARs.
copy_matches "${cli_lib}" \
  "${jars_dir}/crypto/*.jar" \
  "${jars_dir}/jdbc/mariadb-java-client-*.jar" \
  "${jars_dir}/jdbc/postgresql-*.jar"

# MariaDB is the default database and PostgreSQL remains supported as an
# operator-selected alternative, so every application image carries both drivers.
for role in xipki-ca xipki-gateway xipki-ocsp; do
  install -d "${setup_dir}/${role}/tomcat/lib"
  copy_matches "${setup_dir}/${role}/tomcat/lib" \
    "${jars_dir}/jdbc/mariadb-java-client-*.jar" \
    "${jars_dir}/jdbc/postgresql-*.jar"
done

copy_matches "${crypto_overlay}/WEB-INF/lib" "${jars_dir}/crypto/*.jar"
add_crypto_backend "${setup_dir}/xipki-ca/tomcat/webapps/ca.war"
add_crypto_backend "${setup_dir}/xipki-gateway/tomcat/webapps/ROOT.war"
add_crypto_backend "${setup_dir}/xipki-ocsp/tomcat/webapps/ocsp.war"

rm -rf "${crypto_overlay}"
