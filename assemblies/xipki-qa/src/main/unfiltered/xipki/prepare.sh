#!/bin/sh

TOMCAT_DIR=~/tools/tomcat
XIPKI_DIR=${TOMCAT_DIR}/xipki

DIR=`dirname $0`

echo "working dir: ${DIR}"

cp -r ${DIR}/webapps/* ${TOMCAT_DIR}/webapps

cp -r ${DIR}/etc/* ${XIPKI_DIR}/etc

cp ${XIPKI_DIR}/etc/ca/database/mariadb/*.properties ${XIPKI_DIR}/etc/ca/database/

cp ${XIPKI_DIR}/etc/ocsp/database/mariadb/*.properties ${XIPKI_DIR}/etc/ocsp/database/

cp ${DIR}/server.xml ${TOMCAT_DIR}/conf

