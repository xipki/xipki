#!/bin/sh

TOMCAT_DIR=~/tools/tomcat

XIPKI_DIR=${TOMCAT_DIR}/xipki

DIR=`dirname $0`

echo "working dir: ${DIR}"

rm -rf ${TOMCAT_DIR}/webapps/* ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/mariadb-java-client-*.jar \
    ${TOMCAT_DIR}/lib/postgresql-*.jar \
    ${TOMCAT_DIR}/lib/h2-*.jar

cp -r xipki-ca/* ${TOMCAT_DIR}/

cp -r xipki-ocsp/* ${TOMCAT_DIR}/

cp -r ${DIR}/webapps/* ${TOMCAT_DIR}/webapps

cp -r ${DIR}/etc/* ${XIPKI_DIR}/etc

cp ${XIPKI_DIR}/etc/ca/database/mariadb/*.properties ${XIPKI_DIR}/etc/ca/database/

cp ${XIPKI_DIR}/etc/ocsp/database/mariadb/*.properties ${XIPKI_DIR}/etc/ocsp/database/

# Use H2 database for the cache
cp ${XIPKI_DIR}/etc/ocsp/database/h2/ocsp-cache-db.properties ${XIPKI_DIR}/etc/ocsp/database/

cp ${DIR}/server.xml ${TOMCAT_DIR}/conf
