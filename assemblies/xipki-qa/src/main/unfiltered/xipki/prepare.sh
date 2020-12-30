#!/bin/sh

XIPKI_DIR=~/tools/tomcat/xipki
WEBAPPS_DIR=~/tools/tomcat/webapps

DIR=`dirname $0`

echo "working dir: ${DIR}"

cp -r ${DIR}/webapps/* ${WEBAPPS_DIR}

cp -r ${DIR}/etc/* ${XIPKI_DIR}/etc

cp ${XIPKI_DIR}/etc/ca/database/mariadb/*.properties ${XIPKI_DIR}/etc/ca/database/

cp ${XIPKI_DIR}/etc/ocsp/database/mariadb/*.properties ${XIPKI_DIR}/etc/ocsp/database/

