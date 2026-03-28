#!/bin/sh

set -eu

DIR="$(cd -- "$(dirname "$0")" >/dev/null 2>&1; pwd -P)"
POM_FILE="${DIR}/pom.xml"

VERSION="$(sed -n 's@^[[:space:]]*<version>\(.*\)</version>[[:space:]]*$@\1@p' "${POM_FILE}" | head -n 1)"

if [ -z "${VERSION}" ]; then
  echo "Could not determine project version from ${POM_FILE}" >&2
  exit 1
fi

case "${VERSION}" in
  *-SNAPSHOT)
    echo "Refusing release deploy for snapshot version: ${VERSION}" >&2
    exit 1
    ;;
esac

echo "Deploying release version ${VERSION}"

cd "${DIR}"
exec mvn -Prelease deploy "$@"
