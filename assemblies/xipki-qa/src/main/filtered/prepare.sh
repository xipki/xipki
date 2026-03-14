#!/bin/bash

# LTS or FIPS
BOUNCYCASTLE_MODE_CLIENT=LTS
# LTS or FIPS
BOUNCYCASTLE_MODE_SERVER=LTS

# where to install the tomcat
TBDIR=~/test/xipki

# Database type: h2, mariadb, pgsql
DATABASE_TYPE=h2

# 10 or 11
TOMCAT_MAJOR_VERSION=10

# Exit immediately if a command exits with a non-zero status.
set -e

if [ "$TOMCAT_MAJOR_VERSION" -lt "10" ]; then
  echo "Unsupported tomcat major version ${TOMCAT_MAJOR_VERSION}"
  exit 1
fi

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

echo "working dir: ${WDIR}"

if [ "x$JAVA_HOME" = "x" ]; then
	JAVA_EXEC=java
else
	JAVA_EXEC=$JAVA_HOME/bin/java
fi

if [ -d ${TBDIR}/jdk-tomcat ]; then
  TOMCAT_JAVA_HOME="--env JAVA_HOME=${TBDIR}/jdk-tomcat"
else
  TOMCAT_JAVA_HOME="";
fi

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

rm -rf ca-tomcat ocsp-tomcat gateway-tomcat dummy-tomcat

rm -rf $TOMCAT_DIR
tar xf $TOMCAT_BINARY

rm -rf $TOMCAT_DIR/webapps/*

cp -r $TOMCAT_DIR ca-tomcat
cp -r $TOMCAT_DIR ocsp-tomcat
cp -r $TOMCAT_DIR gateway-tomcat
mv    $TOMCAT_DIR dummy-tomcat

cd $WDIR
echo "change to folder: `pwd`"

mkdir -p xipki-ocsp/tomcat/lib
mkdir -p xipki-gateway/tomcat/lib
mkdir -p xipki-dummy/tomcat/lib

rm -f xipki-ca/tomcat/lib/bc*-lts*.jar
rm -f xipki-ca/tomcat/lib/bc*-fips-*.jar

rm -f xipki-ocsp/tomcat/lib/bc*-lts*.jar
rm -f xipki-ocsp/tomcat/lib/bc*-fips-*.jar

rm -f xipki-gateway/tomcat/lib/bc*-lts*.jar
rm -f xipki-gateway/tomcat/lib/bc*-fips-*.jar

echo "Copy JDBC jars to xipki-mgmt-cli"
cp xipki-ca/tomcat/lib/*.jar xipki-qa/lib/boot/

if [[ "${BOUNCYCASTLE_MODE_CLIENT}" == "LTS" ]]; then
  echo "Client: copy karaf configuration files based on BouncyCastle LTS jars"
  cp setup/bc-lts/org.apache.karaf.features.cfg xipki-qa/etc/
else
  echo "Client: Copy karaf configuration files based on BouncyCastle LTS jars"
  cp setup/bc-fips/org.apache.karaf.features.cfg xipki-qa/etc/
fi

if [[ "${BOUNCYCASTLE_MODE_SERVER}" == "LTS" ]]; then
  echo "Server: copy BouncyCastle LTS jars to xipki-ca"

  cp xipki-qa/system/org/bouncycastle/bcprov-lts8on/${bc-lts.version}/* \
     xipki-qa/system/org/bouncycastle/bcutil-lts8on/${bc-lts.version}/* \
     xipki-qa/system/org/bouncycastle/bcpkix-lts8on/${bc-lts.version}/* \
     xipki-qa/system/org/xipki/bcbridge-lts8on/${project.version}/*     \
     xipki-ca/tomcat/lib/
else
  echo "Server: copy BouncyCastle FIPS jars to xipki-ca"
  cp xipki-qa/system/org/bouncycastle/bc-fips/${bc-fips.version}/*         \
     xipki-qa/system/org/bouncycastle/bcpqc-fips/${bcpqc-fips.version}/*   \
     xipki-qa/system/org/bouncycastle/bcutil-fips/${bcutil-fips.version}/* \
     xipki-qa/system/org/bouncycastle/bcpkix-fips/${bcpkix-fips.version}/* \
     xipki-qa/system/org/xipki/bcbridge-fips/${project.version}/*          \
     xipki-ca/tomcat/lib/
fi

echo "Copy JDBC & BouncyCastle jars to xipki-ocsp and xipki-gateway"
cp xipki-ca/tomcat/lib/*  xipki-ocsp/tomcat/lib/
cp xipki-ca/tomcat/lib/*  xipki-gateway/tomcat/lib/
cp xipki-ca/tomcat/lib/*  xipki-dummy/tomcat/lib/

echo "Copy $WDIR/war-common/ to war files (ca.war, ocsp.war, gw.war)"

cp xipki-qa/system/com/zaxxer/HikariCP/${hikaricp.version}/*  \
   xipki-qa/system/org/xipki/codec/${project.version}/*       \
   xipki-qa/system/org/xipki/pkcs11/${project.version}/*      \
   xipki-qa/system/org/xipki/security/${project.version}/*    \
   xipki-qa/system/org/xipki/util/${project.version}/*        \
   xipki-qa/system/org/xipki/util-extra/${project.version}/*  \
   xipki-qa/system/org/xipki/xihsm/${project.version}/*       \
   $WDIR/war-common/WEB-INF/lib

CP="xipki-ca/tomcat/lib/*:war-common/WEB-INF/lib/*"

$JAVA_EXEC -cp "$CP" \
  -Ddatabase.type=${DATABASE_TYPE} -Dtest.basedir="${TBDIR}" \
  -Dtomcat.java.home="${TOMCAT_JAVA_HOME}" \
  org.xipki.util.extra.misc.BatchReplace setup/conf.json

## Generate keys
KC_DIR=setup/keycerts

$JAVA_EXEC -cp "$CP" org.xipki.security.util.GenerateCerts setup/keycerts.json $KC_DIR

cd $WDIR/war-common/
zip -r $WDIR/xipki-ca/tomcat/webapps/ca.war .
zip -r $WDIR/xipki-ocsp/tomcat/webapps/ocsp.war .
zip -r $WDIR/xipki-gateway/tomcat/webapps/gw.war .

# Copy the keys and certificates
KC_DIR=$WDIR/setup/keycerts
KS_DIR=$WDIR/setup/keycerts/certstore

# CA
TDIR=$WDIR/xipki-ca/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/ca-server/* \
   $KC_DIR/ca-mgmt-client/ca-mgmt-client-cert.pem \
   $KC_DIR/dummy-server/dummy-server-cert.pem \
   $KS_DIR/ca-client-certstore.p12 \
   $TDIR

# OCSP
TDIR=$WDIR/xipki-ocsp/tomcat/xipki/keycerts

mkdir -p $TDIR

# Gateway
TDIR=$WDIR/xipki-gateway/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/gateway-server/* \
   $KC_DIR/ra-sdk-client/* \
   $KC_DIR/ca-server/ca-server-cert.pem \
   $KS_DIR/gateway-client-ca-certstore.p12 \
   $KC_DIR/dh-pop/dh-pop.p12 \
   $KC_DIR/cmp-client/cmp-client-cert.pem \
   $KC_DIR/est-client/est-client-cert.pem \
   $KC_DIR/rest-client/rest-client-cert.pem \
   $KC_DIR/secretkeys/kem-pop.jceks \
   $TDIR

# Dummy: ctlog and crl download server
TDIR=$WDIR/xipki-dummy/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/dummy-server/* \
   $TDIR

# QA
TDIR=$WDIR/xipki-qa/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/ca-mgmt-client/* \
   $KC_DIR/cmp-client/* \
   $KC_DIR/est-client/* \
   $KC_DIR/rest-client/* \
   $KC_DIR/ocsp-client/* \
   $KC_DIR/ca-server/* \
   $KC_DIR/gateway-server/*\
   $KC_DIR/dh-pop/dh-pop-certs.pem\
   $KC_DIR/ra-sdk-client/ra-sdk-client.p12 \
   $KC_DIR/ra-sdk-client/ra-sdk-client-cert.pem \
   $KC_DIR/secretkeys/kem-pop.jceks \
   $TDIR

TOMCAT_DIR_CA=$TBDIR/ca-tomcat
TOMCAT_DIR_OCSP=$TBDIR/ocsp-tomcat
TOMCAT_DIR_GATEWAY=$TBDIR/gateway-tomcat
TOMCAT_DIR_DUMMY=$TBDIR/dummy-tomcat

## CA
TOMCAT_DIR=${TOMCAT_DIR_CA}
echo "tomcat dir: ${TOMCAT_DIR}"

rm -rf ${TOMCAT_DIR}/webapps ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/mariadb-java-client-*.jar \
    ${TOMCAT_DIR}/lib/postgresql-*.jar \
    ${TOMCAT_DIR}/lib/h2-*.jar

# copy files
cp -r ${WDIR}/xipki-ca/tomcat/*  ${TOMCAT_DIR}/

## OCSP
TOMCAT_DIR=${TOMCAT_DIR_OCSP}
echo "tomcat dir: ${TOMCAT_DIR}"

rm -rf ${TOMCAT_DIR}/webapps ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/mariadb-java-client-*.jar \
    ${TOMCAT_DIR}/lib/postgresql-*.jar \
    ${TOMCAT_DIR}/lib/h2-*.jar

# copy files
cp -r ${WDIR}/xipki-ocsp/tomcat/*  ${TOMCAT_DIR}/

## Gateway
TOMCAT_DIR=${TOMCAT_DIR_GATEWAY}
echo "tomcat dir: ${TOMCAT_DIR}"

rm -rf ${TOMCAT_DIR}/webapps ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/mariadb-java-client-*.jar \
    ${TOMCAT_DIR}/lib/postgresql-*.jar \
    ${TOMCAT_DIR}/lib/h2-*.jar

# copy files
cp -r ${WDIR}/xipki-gateway/tomcat/*  ${TOMCAT_DIR}/

## Dummy: ctlog and CRL download server
TOMCAT_DIR=${TOMCAT_DIR_DUMMY}
echo "tomcat dir: ${TOMCAT_DIR}"

rm -rf ${TOMCAT_DIR}/webapps ${TOMCAT_DIR}/logs/* ${TOMCAT_DIR}/xipki

rm -rf ${TOMCAT_DIR}/lib/bc*.jar \
    ${TOMCAT_DIR}/lib/mariadb-java-client-*.jar \
    ${TOMCAT_DIR}/lib/postgresql-*.jar \
    ${TOMCAT_DIR}/lib/h2-*.jar

# copy files
cp -r ${WDIR}/xipki-dummy/tomcat/*  ${TOMCAT_DIR}/

# Reset H2 database
rm -rf ~/.xipki/db/h2/

cp ${WDIR}/xipki-ca/tomcat/xipki/etc/ca/database/${DATABASE_TYPE}/* \
   ${TOMCAT_DIR_CA}/xipki/etc/ca/database/

mkdir -p ${TOMCAT_DIR_DUMMY}/xipki/etc/ca/database/
cp ${WDIR}/xipki-ca/tomcat/xipki/etc/ca/database/${DATABASE_TYPE}/ca-db.properties \
   ${TOMCAT_DIR_DUMMY}/xipki/etc/ca/database/

cp ${WDIR}/xipki-ocsp/tomcat/xipki/etc/ocsp/database/${DATABASE_TYPE}/* \
   ${TOMCAT_DIR_OCSP}/xipki/etc/ocsp/database/

# Use H2 database for the cache
cp ${TOMCAT_DIR_OCSP}/xipki/etc/ocsp/database/h2/ocsp-cache-db.properties \
   ${TOMCAT_DIR_OCSP}/xipki/etc/ocsp/database/

cp ${WDIR}/xipki-gateway/tomcat/xipki/etc/acme/database/${DATABASE_TYPE}/* \
   ${TOMCAT_DIR_GATEWAY}/xipki/etc/acme/database/
