#!/bin/sh

TOMCAT_CA_DIR=~/tools/xipki/tomcat-ca

TOMCAT_OCSP_DIR=~/tools/xipki/tomcat-ocsp

TOMCAT_CMP_GATEWAY_DIR=~/tools/xipki/tomcat-cmp-gateway

TOMCAT_REST_GATEWAY_DIR=~/tools/xipki/tomcat-rest-gateway

TOMCAT_SCEP_GATEWAY_DIR=~/tools/xipki/tomcat-scep-gateway

DIR=`dirname $0`
echo "working dir: ${DIR}"

## CA

TOMCAT_DIR=${TOMCAT_CA_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

XIPKI_DIR=${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/webapps/* ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/mariadb-java-client-*.jar \
    ${TOMCAT_DIR}/lib/postgresql-*.jar \
    ${TOMCAT_DIR}/lib/h2-*.jar

cp -r xipki-ca/* ${TOMCAT_DIR}/

cp -r ${DIR}/webapps/* ${TOMCAT_DIR}/webapps

cp -r ${DIR}/tomcat/ca/* ${TOMCAT_DIR}/

cp ${XIPKI_DIR}/etc/ca/database/mariadb/*.properties ${XIPKI_DIR}/etc/ca/database/

cp -r ${DIR}/etc/ca/ ${XIPKI_DIR}/etc

## OCSP
TOMCAT_DIR=${TOMCAT_OCSP_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

XIPKI_DIR=${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/webapps/* ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/mariadb-java-client-*.jar \
    ${TOMCAT_DIR}/lib/postgresql-*.jar \
    ${TOMCAT_DIR}/lib/h2-*.jar

cp -r xipki-ocsp/* ${TOMCAT_DIR}/
cp -r ${DIR}/tomcat/ocsp/* ${TOMCAT_DIR}/

cp ${XIPKI_DIR}/etc/ocsp/database/mariadb/*.properties ${XIPKI_DIR}/etc/ocsp/database/

cp -r ${DIR}/etc/ocsp/ ${XIPKI_DIR}/etc

# Use H2 database for the cache
cp ${XIPKI_DIR}/etc/ocsp/database/h2/ocsp-cache-db.properties ${XIPKI_DIR}/etc/ocsp/database/

## CMP Gateway
TOMCAT_DIR=${TOMCAT_CMP_GATEWAY_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

rm -rf ${TOMCAT_DIR}/webapps/* ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki -rf ${TOMCAT_DIR}/lib/bc*.jar

cp -r xipki-cmp-gateway/* ${TOMCAT_DIR}/
cp -r ${DIR}/tomcat/cmp-gateway/* ${TOMCAT_DIR}/

## SCEP Gateway
TOMCAT_DIR=${TOMCAT_SCEP_GATEWAY_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

rm -rf ${TOMCAT_DIR}/webapps/* ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki ${TOMCAT_DIR}/lib/bc*.jar

cp -r xipki-scep-gateway/* ${TOMCAT_DIR}/
cp -r ${DIR}/tomcat/scep-gateway/* ${TOMCAT_DIR}/

## REST Gateway
TOMCAT_DIR=${TOMCAT_REST_GATEWAY_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

rm -rf ${TOMCAT_DIR}/webapps/* ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki ${TOMCAT_DIR}/lib/bc*.jar
cp -r xipki-rest-gateway/* ${TOMCAT_DIR}/
cp -r ${DIR}/tomcat/rest-gateway/* ${TOMCAT_DIR}/
