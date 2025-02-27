#!/bin/sh

set -e

DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
#DIR=`dirname $0`

echo "working dir: ${DIR}"

BC_DIR=~/.m2/repository/org/bouncycastle
BC_VERSION=1.80

NAME=bcprov
cd ${DIR}/${NAME}
cp ${BC_DIR}/${NAME}-jdk18on/${BC_VERSION}/${NAME}-jdk18on-${BC_VERSION}.jar new.jar
zip -r -u new.jar META-INF
mvn install:install-file -DpomFile=pom.xml -Dfile=new.jar
rm new.jar

NAME=bcutil
cd ${DIR}/${NAME}
cp ${BC_DIR}/${NAME}-jdk18on/${BC_VERSION}/${NAME}-jdk18on-${BC_VERSION}.jar new.jar
zip -r -u new.jar META-INF
mvn install:install-file -DpomFile=pom.xml -Dfile=new.jar
rm new.jar

NAME=bcpkix
cd ${DIR}/${NAME}
cp ${BC_DIR}/${NAME}-jdk18on/${BC_VERSION}/${NAME}-jdk18on-${BC_VERSION}.jar new.jar
zip -r -u new.jar META-INF
mvn install:install-file -DpomFile=pom.xml -Dfile=new.jar
rm new.jar

cd ${DIR}
