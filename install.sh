#!/bin/sh

set -e

DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
#DIR=`dirname $0`

echo "working dir: ${DIR}"

cd ${DIR}
mvn clean install -DskipTests

cd ${DIR}/assemblies
mvn clean install
