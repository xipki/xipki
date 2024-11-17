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
CP="$CP:$LIB_DIR/org/xipki/util/${project.version}/*"
CP="$CP:$LIB_DIR/org/xipki/password/${project.version}/*"
CP="$CP:$LIB_DIR/org/bouncycastle/bcprov-lts8on/${bc.version}/*"
CP="$CP:$LIB_DIR/org/bouncycastle/bcpkix-lts8on/${bc.version}/*"
CP="$CP:$LIB_DIR/org/bouncycastle/bcutil-lts8on/${bc.version}/*"
CP="$CP:$LIB_DIR/com/fasterxml/jackson/core/jackson-databind/${jackson.version}/*"
CP="$CP:$LIB_DIR/com/fasterxml/jackson/core/jackson-annotations/${jackson.version}/*"
CP="$CP:$LIB_DIR/com/fasterxml/jackson/core/jackson-core/${jackson.version}/*"
CP="$CP:$WDIR/setup/lib/*"

## Configure XiPKI
$JAVA_EXEC -cp "$CP" org.xipki.util.BatchReplace $WDIR/setup/conf.json

## Generate keys
KC_DIR=$WDIR/setup/keycerts

$JAVA_EXEC -cp "$CP" org.xipki.security.pkcs12.GenerateCerts $WDIR/setup/keycerts.json $KC_DIR

## Copying generated keys to the XiPKI components
KS_DIR=$KC_DIR/certstore

# CA
echo "Copying generated keys to the XiPKI component xipki-ca"

TDIR=$WDIR/xipki-ca/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/* \
   $KC_DIR/ca-server/* \
   $KC_DIR/hsmproxy-server/*-cert.pem \
   $KC_DIR/ca-mgmt-client/*-cert.pem \
   $KS_DIR/ca-client-certstore.p12 \
   $TDIR

# OCSP
echo "Copying generated keys to the XiPKI component xipki-ocsp"

TDIR=$WDIR/xipki-ocsp/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/* \
   $KC_DIR/hsmproxy-server/*-cert.pem \
   $TDIR

# Gateway
echo "Copying generated keys to the XiPKI component xipki-gateway"

TDIR=$WDIR/xipki-gateway/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/* \
   $KC_DIR/gateway-server/* \
   $KC_DIR/ra-sdk-client/* \
   $KC_DIR/cmp-client/*-cert.pem \
   $KC_DIR/est-client/*-cert.pem \
   $KC_DIR/rest-client/*-cert.pem \
   $KC_DIR/hsmproxy-server/hsmproxy-server-cert.pem \
   $KC_DIR/ca-server/ca-server-cert.pem \
   $KS_DIR/gateway-client-ca-certstore.p12 \
   $TDIR

# HSM proxy
echo "Copying generated keys to the XiPKI component xipki-hsmproxy"

TDIR=$WDIR/xipki-hsmproxy/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-server/* \
   $KC_DIR/hsmproxy-client/*-cert.pem \
   $KS_DIR/hsmproxy-client-certstore.p12 \
   $TDIR

# xipki-cli
echo "Copying generated keys to the XiPKI component xipki-cli"
TDIR=$WDIR/xipki-cli/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/* \
   $KC_DIR/cmp-client/* \
   $KC_DIR/est-client/* \
   $KC_DIR/rest-client/* \
   $KC_DIR/hsmproxy-server/hsmproxy-server-cert.pem \
   $KC_DIR/gateway-server/gateway-server-cert.pem \
   $TDIR

# xipki-mgmt-cli
echo "Copying generated keys to the XiPKI component xipki-mgmt-cli"
TDIR=$WDIR/xipki-mgmt-cli/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/* \
   $KC_DIR/rest-client/* \
   $KC_DIR/ca-mgmt-client/*.p12 \
   $KC_DIR/ca-mgmt-client/*-cert.pem \
   $KC_DIR/hsmproxy-server/hsmproxy-server-cert.pem \
   $KC_DIR/ca-server/ca-server-cert.pem \
   $KC_DIR/gateway-server/gateway-server-cert.pem \
   $KC_DIR/ra-sdk-client/ra-sdk-client-cert.pem* \
   $TDIR
