#!/bin/bash

set -e

helpFunction()
{
   echo ""
   echo "Usage: $0 -t <tomcat major version 10 or 11>"
   exit 1 # Exit script after printing help
}

while getopts "t:" opt
do
   case "$opt" in
      t ) TOMCAT_MAJOR_VERSION="$OPTARG" ;;
      ? ) helpFunction ;; # Print helpFunction in case parameter is non-existent
   esac
done

if [ -z "$TOMCAT_MAJOR_VERSION" ]
then
   echo "Please specify the -t parameter";
   helpFunction
fi

_DIR=tomcat
if [ "$TOMCAT_MAJOR_VERSION" -lt "10" ]; then
  echo "Unsupported tomcat major version ${TOMCAT_MAJOR_VERSION}"
  exit 1
fi

# Test base dir
TBDIR=~/test/xipki

mkdir -p $TBDIR

if ls $TBDIR/apache-tomcat-${TOMCAT_MAJOR_VERSION}*.tar.gz  &> /dev/null; then
  TOMCAT_VERSION=$(ls $TBDIR/apache-tomcat-${TOMCAT_MAJOR_VERSION}.*.tar.gz | tail -n 1 | cut -d "-" -f 3 | cut -d "." -f 1-3)
else
  TOMCAT_VERSION=`curl --silent http://dlcdn.apache.org/tomcat/tomcat-$TOMCAT_MAJOR_VERSION/ | grep v$TOMCAT_MAJOR_VERSION | tail -n 1 | awk '{split($5,c,">v") ; split(c[2],d,"/") ; print d[1]}'`
fi

echo "Tomcat ${TOMCAT_VERSION}"
TOMCAT_DIR=apache-tomcat-${TOMCAT_VERSION}
TOMCAT_BINARY=${TOMCAT_DIR}.tar.gz

WDIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
#WDIR=`dirname $0`
echo "working dir: ${WDIR}"

cd $TBDIR
echo "change to folder: `pwd`"

## download tar.gz file if not available
if [ -f ${TOMCAT_BINARY} ]; then
  echo "Use local ${TOMCAT_BINARY}"
else
  echo "Download ${TOMCAT_BINARY}"
  # For QA only, no-check-certificate is fine.
  wget --no-check-certificate https://dlcdn.apache.org/tomcat/tomcat-${TOMCAT_MAJOR_VERSION}/v${TOMCAT_VERSION}/bin/${TOMCAT_BINARY}
fi

rm -rf ca-tomcat ocsp-tomcat gateway-tomcat hsmproxy-tomcat

rm -rf $TOMCAT_DIR
tar xf $TOMCAT_BINARY

rm -rf $TOMCAT_DIR/webapps/*

cp -r $TOMCAT_DIR ca-tomcat
cp -r $TOMCAT_DIR ocsp-tomcat
cp -r $TOMCAT_DIR gateway-tomcat
cp -r $TOMCAT_DIR hsmproxy-tomcat
rm -rf $TOMCAT_DIR

cd $WDIR
echo "change to folder: `pwd`"

echo "configure XiPKI components"
if [ "x$JAVA_HOME" = "x" ]; then
	JAVA_EXEC=java
else
	JAVA_EXEC=$JAVA_HOME/bin/java
fi

LIB_DIR=$WDIR/system
XDIR=${WDIR}/xipki

CP="$CP:$LIB_DIR/org/xipki/util/${project.version}/*"
CP="$CP:$LIB_DIR/org/xipki/password/${project.version}/*"
CP="$CP:$LIB_DIR/com/fasterxml/jackson/core/jackson-databind/${jackson.version}/*"
CP="$CP:$LIB_DIR/com/fasterxml/jackson/core/jackson-annotations/${jackson.version}/*"
CP="$CP:$LIB_DIR/com/fasterxml/jackson/core/jackson-core/${jackson.version}/*"
CP="$CP:$XDIR/lib/*"

## Configure XiPKI

$JAVA_EXEC -cp "$CP" org.xipki.util.BatchReplace $XDIR/conf.json

# Copy the keys and certificates
KC_DIR=${XDIR}/setup/keycerts
KS_DIR=${XDIR}/setup/keycerts/certstore

# CA
TDIR=$WDIR/xipki-ca/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/*\
   $KC_DIR/ca-server/* \
   $KC_DIR/hsmproxy-server/hsmproxy-server-cert.pem \
   $KC_DIR/ca-mgmt-client/ca-mgmt-client-cert.pem \
   $KS_DIR/ca-client-certstore.p12 \
   $TDIR

# OCSP
TDIR=$WDIR/xipki-ocsp/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/*\
   $KC_DIR/hsmproxy-server/hsmproxy-server-cert.pem \
   $TDIR

# Gateway
TDIR=$WDIR/xipki-gateway/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/* \
   $KC_DIR/gateway-server/* \
   $KC_DIR/ra-sdk-client/* \
   $KC_DIR/hsmproxy-server/hsmproxy-server-cert.pem \
   $KC_DIR/ca-server/ca-server-cert.pem \
   $KS_DIR/gateway-client-ca-certstore.p12 \
   $TDIR

# HSM proxy
TDIR=$WDIR/xipki-hsmproxy/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-server/* \
   $KC_DIR/hsmproxy-client/*-cert.pem \
   $KS_DIR/hsmproxy-client-certstore.p12 \
   $TDIR

# QA
TDIR=$WDIR/xipki/keycerts

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

cp $WDIR/xipki/security/pkcs11.json $WDIR/xipki-ca/tomcat/xipki/security/
cp $WDIR/xipki/security/pkcs11.json $WDIR/xipki-ocsp/tomcat/xipki/security/
cp $WDIR/xipki/security/pkcs11.json $WDIR/xipki-gateway/tomcat/xipki/security/

TOMCAT_CA_DIR=$TBDIR/ca-tomcat
TOMCAT_OCSP_DIR=$TBDIR/ocsp-tomcat
TOMCAT_GATEWAY_DIR=$TBDIR/gateway-tomcat
TOMCAT_HSMPROXY_DIR=$TBDIR/hsmproxy-tomcat

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
cp -r ${WDIR}/xipki-ca/tomcat/*  ${TOMCAT_DIR}/
cp -r ${WDIR}/xipki-ca/${_DIR}/* ${TOMCAT_DIR}/
cp -r ${XDIR}/tomcat-files/xipki-ca/tomcat/*  ${TOMCAT_DIR}/
cp -r ${XDIR}/tomcat-files/xipki-ca/${_DIR}/* ${TOMCAT_DIR}/

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
cp -r ${WDIR}/xipki-ocsp/tomcat/*  ${TOMCAT_DIR}/
cp -r ${WDIR}/xipki-ocsp/${_DIR}/* ${TOMCAT_DIR}/
cp -r ${XDIR}/tomcat-files/xipki-ocsp/tomcat/* ${TOMCAT_DIR}/

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
cp -r ${WDIR}/xipki-gateway/tomcat/*  ${TOMCAT_DIR}/
cp -r ${WDIR}/xipki-gateway/${_DIR}/* ${TOMCAT_DIR}/
cp -r ${XDIR}/tomcat-files/xipki-gateway/tomcat/* ${TOMCAT_DIR}/

cp ${WDIR}/qa/keys/dhpop.p12 ${TOMCAT_DIR}/xipki/keycerts

## HSM Proxy

TOMCAT_DIR=${TOMCAT_HSMPROXY_DIR}
echo "tomcat dir: ${TOMCAT_DIR}"

rm -rf ${TOMCAT_DIR}/webapps ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/*pkcs11wrapper-*.jar \
    ${TOMCAT_DIR}/lib/password-*.jar \
    ${TOMCAT_DIR}/lib/xipki-tomcat-password-*.jar

cp -r ${WDIR}/xipki-hsmproxy/tomcat/*  ${TOMCAT_DIR}/
cp -r ${WDIR}/xipki-hsmproxy/${_DIR}/* ${TOMCAT_DIR}/
