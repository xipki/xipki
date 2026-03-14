#!/bin/sh

# Exit immediately if a command exits with a non-zero status.
set -e

WDIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

if [ "x$JAVA_HOME" = "x" ]; then
	JAVA_EXEC=java
else
	JAVA_EXEC=$JAVA_HOME/bin/java
fi

cd $WDIR
echo "change to folder: `pwd`"

echo "Copy karaf's folders bin, lib, and system"
rm -rf xipki-cli/bin
rm -rf xipki-cli/lib
rm -rf xipki-cli/system

cp -r xipki-mgmt-cli/bin xipki-mgmt-cli/lib xipki-mgmt-cli/system xipki-cli/

rm -rf xipki-cli/system/org/osgi/org.osgi.service.jdbc
rm -rf xipki-cli/system/org/xipki/ca-api
rm -rf xipki-cli/system/org/xipki/ca-mgmt
rm -rf xipki-cli/system/org/xipki/certprofile
rm -rf xipki-cli/system/org/xipki/shell/ca-mgmt-shell

echo "Copy karaf's folder etc"
rm -rf tmp
cp -r xipki-mgmt-cli/etc tmp
rm tmp/org.apache.karaf.features.cfg
rm tmp/branding*
rm tmp/org.xipki.ca.*
cp -r tmp/* xipki-cli/etc/
rm -rf tmp

echo "Prepare tomcat"
mkdir -p xipki-ocsp/tomcat/lib
mkdir -p xipki-gateway/tomcat/lib

echo "Copy JDBC jars to xipki-mgmt-cli"
cp xipki-ca/tomcat/lib/*.jar xipki-mgmt-cli/lib/boot/

BCBRIGDE_LTS_FILE=xipki-mgmt-cli/system/org/xipki/bcbridge-lts8on/${project.version}/bcbridge-lts8on-${project.version}.jar

if [ -f "${BCBRIGDE_LTS_FILE}" ]; then
  echo "Copy BouncyCastle LTS jars to xipki-ca"
  cp xipki-mgmt-cli/system/org/bouncycastle/bcprov-lts8on/${bc-lts.version}/* \
     xipki-mgmt-cli/system/org/bouncycastle/bcutil-lts8on/${bc-lts.version}/* \
     xipki-mgmt-cli/system/org/bouncycastle/bcpkix-lts8on/${bc-lts.version}/* \
     xipki-mgmt-cli/system/org/xipki/bcbridge-lts8on/${project.version}/*     \
     xipki-ca/tomcat/lib/
else
  echo "Copy BouncyCastle FIPS jars to xipki-ca"
  cp xipki-mgmt-cli/system/org/bouncycastle/bc-fips/${bc-fips.version}/*         \
     xipki-mgmt-cli/system/org/bouncycastle/bcpqc-fips/${bcpqc-fips.version}/*   \
     xipki-mgmt-cli/system/org/bouncycastle/bcutil-fips/${bcutil-fips.version}/* \
     xipki-mgmt-cli/system/org/bouncycastle/bcpkix-fips/${bcpkix-fips.version}/* \
     xipki-mgmt-cli/system/org/xipki/bcbridge-fips/${project.version}/*          \
     xipki-ca/tomcat/lib/
fi

echo "Copy JDBC & BouncyCastle jars"
cp xipki-ca/tomcat/lib/* xipki-ocsp/tomcat/lib/

cp xipki-ca/tomcat/lib/* xipki-gateway/tomcat/lib/
echo "End copy JDBC & BouncyCastle jars"

echo "Copy $WDIR/war-common/ to war files (ca.war, ocsp.war, gw.war)"

cp xipki-mgmt-cli/system/com/zaxxer/HikariCP/${hikaricp.version}/* \
  xipki-mgmt-cli/system/org/xipki/codec/${project.version}/*       \
  xipki-mgmt-cli/system/org/xipki/pkcs11/${project.version}/*      \
  xipki-mgmt-cli/system/org/xipki/security/${project.version}/*    \
  xipki-mgmt-cli/system/org/xipki/util/${project.version}/*        \
  xipki-mgmt-cli/system/org/xipki/util-extra/${project.version}/*  \
  xipki-mgmt-cli/system/org/xipki/xihsm/${project.version}/*       \
  $WDIR/war-common/WEB-INF/lib

cd $WDIR/war-common/
zip -r $WDIR/xipki-ca/tomcat/webapps/ca.war .
zip -r $WDIR/xipki-ocsp/tomcat/webapps/ocsp.war .
zip -r $WDIR/xipki-gateway/tomcat/webapps/gw.war .

cd $WDIR/

CP="xipki-ca/tomcat/lib/*:war-common/WEB-INF/lib/*"

## Configure XiPKI
$JAVA_EXEC -cp "$CP" org.xipki.util.extra.misc.BatchReplace setup/conf.json

## Generate keys
KC_DIR=setup/keycerts

$JAVA_EXEC -cp "$CP" org.xipki.security.util.GenerateCerts setup/keycerts.json $KC_DIR

## Copying generated keys to the XiPKI components
KS_DIR=$KC_DIR/certstore

# CA
echo "Copying generated keys to the XiPKI component xipki-ca"

TDIR=$WDIR/xipki-ca/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/ca-server/* \
   $KC_DIR/ca-mgmt-client/*-cert.pem \
   $KS_DIR/ca-client-certstore.p12 \
   $TDIR

# OCSP
echo "Copying generated keys to the XiPKI component xipki-ocsp"

TDIR=$WDIR/xipki-ocsp/tomcat/xipki/keycerts

mkdir -p $TDIR

# Gateway
echo "Copying generated keys to the XiPKI component xipki-gateway"

TDIR=$WDIR/xipki-gateway/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/gateway-server/* \
   $KC_DIR/ra-sdk-client/* \
   $KC_DIR/cmp-client/*-cert.pem \
   $KC_DIR/est-client/*-cert.pem \
   $KC_DIR/rest-client/*-cert.pem \
   $KC_DIR/ca-server/ca-server-cert.pem \
   $KS_DIR/gateway-client-ca-certstore.p12 \
   $KC_DIR/dh-pop/dh-pop.p12 \
   $KC_DIR/secretkeys/kem-pop.jceks \
   $TDIR

# xipki-cli
echo "Copying generated keys to the XiPKI component xipki-cli"
TDIR=$WDIR/xipki-cli/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/cmp-client/* \
   $KC_DIR/est-client/* \
   $KC_DIR/rest-client/* \
   $KC_DIR/gateway-server/gateway-server-cert.pem \
   $KC_DIR/dh-pop/dh-pop-certs.pem \
   $KC_DIR/secretkeys/kem-pop.jceks \
   $TDIR

# xipki-mgmt-cli
echo "Copying generated keys to the XiPKI component xipki-mgmt-cli"
TDIR=$WDIR/xipki-mgmt-cli/xipki/keycerts

mkdir -p $TDIR

## The same as those copied to xipki-cli
cp $KC_DIR/cmp-client/* \
   $KC_DIR/est-client/* \
   $KC_DIR/rest-client/* \
   $KC_DIR/gateway-server/gateway-server-cert.pem \
   $KC_DIR/dh-pop/dh-pop-certs.pem \
   $KC_DIR/secretkeys/kem-pop.jceks \
   $TDIR

cp $KC_DIR/ra-sdk-client/ra-sdk-client-cert.pem \
   $KC_DIR/ca-mgmt-client/*.p12 \
   $KC_DIR/ca-mgmt-client/*-cert.pem \
   $KC_DIR/ca-server/ca-server-cert.pem \
   $TDIR
