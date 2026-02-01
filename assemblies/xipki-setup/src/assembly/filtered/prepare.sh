#!/bin/sh

set -e

WDIR=$(dirname "$0")

if [ "x$JAVA_HOME" = "x" ]; then
	JAVA_EXEC=java
else
	JAVA_EXEC=$JAVA_HOME/bin/java
fi

LIB_DIR=$WDIR/xipki-cli/system

CP="$LIB_DIR/org/xipki/security/${project.version}/*"
CP="$CP:$LIB_DIR/org/xipki/util-extra/${project.version}/*"
CP="$CP:$LIB_DIR/org/xipki/codec/${project.version}/*"
CP="$CP:$LIB_DIR/org/xipki/util/${project.version}/*"
CP="$CP:$LIB_DIR/org/xipki/pkcs11/${project.version}/*"
CP="$CP:$LIB_DIR/org/bouncycastle/bcprov-jdk18on/${bc.version}/*"
CP="$CP:$LIB_DIR/org/bouncycastle/bcpkix-jdk18on/${bc.version}/*"
CP="$CP:$LIB_DIR/org/bouncycastle/bcutil-jdk18on/${bc.version}/*"
CP="$CP:$WDIR/setup/lib/*"

## Configure XiPKI
$JAVA_EXEC -cp "$CP" org.xipki.util.extra.misc.BatchReplace $WDIR/setup/conf.json

## Generate keys
KC_DIR=$WDIR/setup/keycerts

$JAVA_EXEC -cp "$CP" org.xipki.security.util.GenerateCerts $WDIR/setup/keycerts.json $KC_DIR

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

cp $KC_DIR/rest-client/* \
   $KC_DIR/ca-mgmt-client/*.p12 \
   $KC_DIR/ca-mgmt-client/*-cert.pem \
   $KC_DIR/ca-server/ca-server-cert.pem \
   $KC_DIR/gateway-server/gateway-server-cert.pem \
   $KC_DIR/ra-sdk-client/ra-sdk-client-cert.pem \
   $KC_DIR/dh-pop/dh-pop-certs.pem \
   $KC_DIR/secretkeys/kem-pop.jceks \
   $TDIR
