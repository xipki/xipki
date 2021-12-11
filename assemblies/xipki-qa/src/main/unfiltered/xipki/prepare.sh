#!/bin/sh

TOMCAT_DIR=~/tools/tomcat
XIPKI_DIR=${TOMCAT_DIR}/xipki

DIR=`dirname $0`

echo "working dir: ${DIR}"

rm -rf ${TOMCAT_DIR}/webapps/* ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/lib/bc*.jar ${TOMCAT_DIR}/lib/mariadb*.jar ${TOMCAT_DIR}/lib/postgres*.jar

cp -r xipki-ca/* ${TOMCAT_DIR}/

cp -r xipki-ocsp/* ${TOMCAT_DIR}/

cp -r ${DIR}/webapps/* ${TOMCAT_DIR}/webapps

cp -r ${DIR}/etc/* ${XIPKI_DIR}/etc

cp ${XIPKI_DIR}/etc/ca/database/mariadb/*.properties ${XIPKI_DIR}/etc/ca/database/

cp ${XIPKI_DIR}/etc/ocsp/database/mariadb/*.properties ${XIPKI_DIR}/etc/ocsp/database/

cp ${DIR}/server.xml ${TOMCAT_DIR}/conf

