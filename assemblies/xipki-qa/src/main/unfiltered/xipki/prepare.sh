#!/bin/sh

T10FILE=~/tools/xipki/tomcat10

if [ -f "$T10FILE" ]; then
    echo "TOMCAT 10+"
else
    echo "TOMCAT 8/9"
fi

TOMCAT_CA_DIR=~/tools/xipki/ca-tomcat

TOMCAT_OCSP_DIR=~/tools/xipki/ocsp-tomcat

TOMCAT_GATEWAY_DIR=~/tools/xipki/gateway-tomcat

TOMCAT_HSMPROXY_DIR=~/tools/xipki/hsmproxy-tomcat

DIR=`dirname $0`
echo "working dir: ${DIR}"

cp xipki/security/pkcs11.json xipki-ca/xipki/security/
cp xipki/security/pkcs11.json xipki-ocsp/xipki/security/
cp xipki/security/pkcs11.json xipki-gateway/xipki/security/

## CA

TOMCAT_DIR=${TOMCAT_CA_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

XIPKI_DIR=${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/webapps ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki
mkdir ${TOMCAT_DIR}/webapps

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/mariadb-java-client-*.jar \
    ${TOMCAT_DIR}/lib/postgresql-*.jar \
    ${TOMCAT_DIR}/lib/h2-*.jar \
    ${TOMCAT_DIR}/lib/*pkcs11wrapper-*.jar \
    ${TOMCAT_DIR}/lib/password-*.jar \
    ${TOMCAT_DIR}/lib/xipki-tomcat-password-*.jar

cp -r xipki-ca/bin xipki-ca/lib xipki-ca/xipki ${TOMCAT_DIR}/

if [ -f "$T10FILE" ]; then
    cp -r xipki-ca/webapps-tomcat10on/* ${TOMCAT_DIR}/webapps
    cp -r ${DIR}/webapps-tomcat10on/* ${TOMCAT_DIR}/webapps
else
    cp -r xipki-ca/webapps/* ${TOMCAT_DIR}/webapps
    cp -r ${DIR}/webapps/* ${TOMCAT_DIR}/webapps
fi

cp -r ${DIR}/tomcat/ca/* ${TOMCAT_DIR}/

cp ${XIPKI_DIR}/etc/ca/database/mariadb/*.properties ${XIPKI_DIR}/etc/ca/database/

cp -r ${DIR}/etc/ca/ ${XIPKI_DIR}/etc

## OCSP
TOMCAT_DIR=${TOMCAT_OCSP_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

XIPKI_DIR=${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/webapps ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki
mkdir ${TOMCAT_DIR}/webapps

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/mariadb-java-client-*.jar \
    ${TOMCAT_DIR}/lib/postgresql-*.jar \
    ${TOMCAT_DIR}/lib/h2-*.jar \
    ${TOMCAT_DIR}/lib/*pkcs11wrapper-*.jar \
    ${TOMCAT_DIR}/lib/password-*.jar \
    ${TOMCAT_DIR}/lib/xipki-tomcat-password-*.jar

cp -r xipki-ocsp/bin xipki-ocsp/lib xipki-ocsp/xipki ${TOMCAT_DIR}/

if [ -f "$T10FILE" ]; then
    cp -r xipki-ocsp/webapps-tomcat10on/* ${TOMCAT_DIR}/webapps
else
    cp -r xipki-ocsp/webapps/* ${TOMCAT_DIR}/webapps
fi

cp -r ${DIR}/tomcat/ocsp/* ${TOMCAT_DIR}/

# For the QA, we need to restart the OCSP remotely, and this requires the HTTPS
mkdir -p ${TOMCAT_OCSP_DIR}/xipki/keycerts/tlskeys
cp -r ${DIR}/../xipki-ca/xipki/keycerts/tlskeys/* ${TOMCAT_OCSP_DIR}/xipki/keycerts/tlskeys

cp ${XIPKI_DIR}/etc/ocsp/database/mariadb/*.properties ${XIPKI_DIR}/etc/ocsp/database/

cp -r ${DIR}/etc/ocsp/ ${XIPKI_DIR}/etc

# Use H2 database for the cache
cp ${XIPKI_DIR}/etc/ocsp/database/h2/ocsp-cache-db.properties ${XIPKI_DIR}/etc/ocsp/database/

## Gateway
TOMCAT_DIR=${TOMCAT_GATEWAY_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

XIPKI_DIR=${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/webapps ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki
mkdir ${TOMCAT_DIR}/webapps

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/mariadb-java-client-*.jar \
    ${TOMCAT_DIR}/lib/postgresql-*.jar \
    ${TOMCAT_DIR}/lib/h2-*.jar \
    ${TOMCAT_DIR}/lib/*pkcs11wrapper-*.jar \
    ${TOMCAT_DIR}/lib/password-*.jar \
    ${TOMCAT_DIR}/lib/xipki-tomcat-password-*.jar

cp -r xipki-gateway/bin xipki-gateway/lib xipki-gateway/xipki ${TOMCAT_DIR}/

if [ -f "$T10FILE" ]; then
    cp -r xipki-gateway/webapps-tomcat10on/* ${TOMCAT_DIR}/webapps
    cp -r xipki-gateway/webapps-tomcat10on/.well-known.war ${TOMCAT_DIR}/webapps
else
    cp -r xipki-gateway/webapps/* ${TOMCAT_DIR}/webapps
    cp -r xipki-gateway/webapps/.well-known.war ${TOMCAT_DIR}/webapps
fi

rm ${TOMCAT_DIR}/webapps/acme.war

cp -r ${DIR}/tomcat/gateway/* ${TOMCAT_DIR}/
cp ${DIR}/etc/*-gateway.json ${XIPKI_DIR}/etc
cp ${DIR}/../qa/keys/dhpop.p12 ${XIPKI_DIR}/keycerts

## HSM Proxy

TOMCAT_DIR=${TOMCAT_HSMPROXY_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

XIPKI_DIR=${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/webapps ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki
mkdir ${TOMCAT_DIR}/webapps

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/*pkcs11wrapper-*.jar \
    ${TOMCAT_DIR}/lib/password-*.jar \
    ${TOMCAT_DIR}/lib/xipki-tomcat-password-*.jar

cp -r xipki-hsmproxy/bin xipki-hsmproxy/lib xipki-hsmproxy/xipki ${TOMCAT_DIR}/

if [ -f "$T10FILE" ]; then
    cp -r xipki-hsmproxy/webapps-tomcat10on/* ${TOMCAT_DIR}/webapps
else
    cp -r xipki-hsmproxy/webapps/* ${TOMCAT_DIR}/webapps
fi

cp -r ${DIR}/tomcat/hsmproxy/* ${TOMCAT_DIR}/