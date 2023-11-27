#!/bin/sh

DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# DIR=`dirname $0`

echo "working dir: ${DIR}"

cd ${DIR}
mvn clean deploy -DskipTests -Prelease

cd ${DIR}/servlets
mvn clean install

cd ${DIR}/assemblies
mvn clean install

cd ${DIR}/assemblies/xipki-setup
mvn clean deploy -Prelease
