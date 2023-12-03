#!/bin/bash

set -e

WDIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
#WDIR=`dirname $0`
echo "working dir: ${WDIR}"

cd ~/tools/xipki/
echo "change to folder: `pwd`"

rm -rf ca-tomcat ocsp-tomcat gateway-tomcat hsmproxy-tomcat

TOMCAT_BINARY=`compgen -G "apache-tomcat-*.tar.gz"`
TOMCAT_DIR=`echo $TOMCAT_BINARY | cut -d "." -f -3`

rm -rf $TOMCAT_DIR
tar xf $TOMCAT_BINARY

rm -rf $TOMCAT_DIR/webapps/*

cp -r $TOMCAT_DIR ca-tomcat
cp -r $TOMCAT_DIR ocsp-tomcat
cp -r $TOMCAT_DIR gateway-tomcat
cp -r $TOMCAT_DIR hsmproxy-tomcat

cd $WDIR
echo "change to folder: `pwd`"

## detect the major version of tomcat
TOMCAT_VERSION=`~/tools/xipki/ca-tomcat/bin/version.sh | grep "Server number"`
echo "Tomcat ${TOMCAT_VERSION}"

TOMCAT_VERSION=`cut -d ":" -f2- <<< "${TOMCAT_VERSION}"`
TOMCAT_VERSION=`cut -d "." -f1  <<< "${TOMCAT_VERSION}"`
## Remove leading and trailing spaces and tabs
TOMCAT_VERSION=`awk '{$1=$1};1'  <<< "${TOMCAT_VERSION}"`

if [ "$TOMCAT_VERSION" -lt "8" ]; then
  echo "Unsupported tomcat major version ${TOMCAT_VERSION}"
  exit 1
elif [ "$TOMCAT_VERSION" -lt "10" ]; then
  _DIR=tomcat8on
else
  _DIR=tomcat10on
fi

# Copy the keys and certificates
KC_DIR=${WDIR}/setup/keycerts
KS_DIR=${WDIR}/setup/keycerts/certstore
RDIR=${WDIR}/..

# CA
TDIR=$RDIR/xipki-ca/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/*\
   $KC_DIR/ca-server/* \
   $KC_DIR/hsmproxy-server/hsmproxy-server-cert.pem \
   $KC_DIR/ca-mgmt-client/ca-mgmt-client-cert.pem \
   $KS_DIR/ca-client-certstore.p12 \
   $TDIR

# Gateway
TDIR=$RDIR/xipki-gateway/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/* \
   $KC_DIR/gateway-server/* \
   $KC_DIR/ra-sdk-client/* \
   $KC_DIR/hsmproxy-server/hsmproxy-server-cert.pem \
   $KC_DIR/ca-server/ca-server-cert.pem \
   $KS_DIR/gateway-client-ca-certstore.p12 \
   $TDIR

# HSM proxy
TDIR=$RDIR/xipki-hsmproxy/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-server/* \
   $KS_DIR/hsmproxy-client-certstore.p12 \
   $TDIR

# QA
TDIR=$RDIR/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/* \
   $KC_DIR/ca-mgmt-client/* \
   $KC_DIR/cmp-client/* \
   $KC_DIR/est-client/* \
   $KC_DIR/rest-client/* \
   $KC_DIR/ocsp-client/* \
   $KC_DIR/hsmproxy-server/hsmproxy-server-cert.pem \
   $KC_DIR/ca-server/* \
   $KC_DIR/gateway-server/*\
   $KC_DIR/ra-sdk-client/ra-sdk-client-cert.pem* \
   $TDIR

cp $RDIR/xipki/security/pkcs11.json $RDIR/xipki-ca/tomcat/xipki/security/
cp $RDIR/xipki/security/pkcs11.json $RDIR/xipki-ocsp/tomcat/xipki/security/
cp $RDIR/xipki/security/pkcs11.json $RDIR/xipki-gateway/tomcat/xipki/security/

TOMCAT_CA_DIR=~/tools/xipki/ca-tomcat
TOMCAT_OCSP_DIR=~/tools/xipki/ocsp-tomcat
TOMCAT_GATEWAY_DIR=~/tools/xipki/gateway-tomcat
TOMCAT_HSMPROXY_DIR=~/tools/xipki/hsmproxy-tomcat

## CA

TOMCAT_DIR=${TOMCAT_CA_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

rm -rf ${TOMCAT_DIR}/webapps ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/mariadb-java-client-*.jar \
    ${TOMCAT_DIR}/lib/postgresql-*.jar \
    ${TOMCAT_DIR}/lib/h2-*.jar \
    ${TOMCAT_DIR}/lib/*pkcs11wrapper-*.jar \
    ${TOMCAT_DIR}/lib/password-*.jar \
    ${TOMCAT_DIR}/lib/xipki-tomcat-password-*.jar

# copy files
cp -r ${WDIR}/../xipki-ca/tomcat/*  ${TOMCAT_DIR}/
cp -r ${WDIR}/../xipki-ca/${_DIR}/* ${TOMCAT_DIR}/
cp -r ${WDIR}/tomcat-files/xipki-ca/tomcat/*  ${TOMCAT_DIR}/
cp -r ${WDIR}/tomcat-files/xipki-ca/${_DIR}/* ${TOMCAT_DIR}/

cp ${TOMCAT_DIR}/xipki/etc/ca/database/mariadb/*.properties \
   ${TOMCAT_DIR}/xipki/etc/ca/database/

## OCSP
TOMCAT_DIR=${TOMCAT_OCSP_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

rm -rf ${TOMCAT_DIR}/webapps ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/mariadb-java-client-*.jar \
    ${TOMCAT_DIR}/lib/postgresql-*.jar \
    ${TOMCAT_DIR}/lib/h2-*.jar \
    ${TOMCAT_DIR}/lib/*pkcs11wrapper-*.jar \
    ${TOMCAT_DIR}/lib/password-*.jar \
    ${TOMCAT_DIR}/lib/xipki-tomcat-password-*.jar

# copy files
cp -r ${WDIR}/../xipki-ocsp/tomcat/*  ${TOMCAT_DIR}/
cp -r ${WDIR}/../xipki-ocsp/${_DIR}/* ${TOMCAT_DIR}/
cp -r ${WDIR}/tomcat-files/xipki-ocsp/tomcat/* ${TOMCAT_DIR}/

cp ${TOMCAT_DIR}/xipki/etc/ocsp/database/mariadb/*.properties \
   ${TOMCAT_DIR}/xipki/etc/ocsp/database/
# Use H2 database for the cache
cp ${TOMCAT_DIR}/xipki/etc/ocsp/database/h2/ocsp-cache-db.properties \
   ${TOMCAT_DIR}/xipki/etc/ocsp/database/

## Gateway
TOMCAT_DIR=${TOMCAT_GATEWAY_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

rm -rf ${TOMCAT_DIR}/webapps ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/mariadb-java-client-*.jar \
    ${TOMCAT_DIR}/lib/postgresql-*.jar \
    ${TOMCAT_DIR}/lib/h2-*.jar \
    ${TOMCAT_DIR}/lib/*pkcs11wrapper-*.jar \
    ${TOMCAT_DIR}/lib/password-*.jar \
    ${TOMCAT_DIR}/lib/xipki-tomcat-password-*.jar

# copy files
cp -r ${WDIR}/../xipki-gateway/tomcat/*  ${TOMCAT_DIR}/
cp -r ${WDIR}/../xipki-gateway/${_DIR}/* ${TOMCAT_DIR}/
cp -r ${WDIR}/tomcat-files/xipki-gateway/tomcat/* ${TOMCAT_DIR}/

cp ${WDIR}/../qa/keys/dhpop.p12 ${TOMCAT_DIR}/xipki/keycerts
rm ${TOMCAT_DIR}/webapps/acme.war

## HSM Proxy

TOMCAT_DIR=${TOMCAT_HSMPROXY_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

rm -rf ${TOMCAT_DIR}/webapps ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/*pkcs11wrapper-*.jar \
    ${TOMCAT_DIR}/lib/password-*.jar \
    ${TOMCAT_DIR}/lib/xipki-tomcat-password-*.jar

cp -r ${WDIR}/../xipki-gateway/tomcat/*  ${TOMCAT_DIR}/
cp -r ${WDIR}/../xipki-gateway/${_DIR}/* ${TOMCAT_DIR}/
