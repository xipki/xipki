#!/bin/sh

set -e

WDIR=$(dirname "$0")

if [ "x$JAVA_HOME" = "x" ]; then
	JAVA_EXEC=java
else
	JAVA_EXEC=$JAVA_HOME/bin/java
fi

LIB_DIR=$WDIR/../xipki-cli/system

CP="$LIB_DIR/org/xipki/commons/security/${xipki.commons.version}/*"
CP="$CP:$LIB_DIR/org/xipki/commons/util/${xipki.commons.version}/*"
CP="$CP:$LIB_DIR/org/xipki/commons/password/${xipki.commons.version}/*"
CP="$CP:$LIB_DIR/org/bouncycastle/bcprov-jdk18on/${bc.version}/*"
CP="$CP:$LIB_DIR/org/bouncycastle/bcpkix-jdk18on/${bc.version}/*"
CP="$CP:$LIB_DIR/org/bouncycastle/bcutil-jdk18on/${bc.version}/*"
CP="$CP:$LIB_DIR/com/fasterxml/jackson/core/jackson-databind/${jackson.version}/*"
CP="$CP:$LIB_DIR/com/fasterxml/jackson/core/jackson-annotations/${jackson.version}/*"
CP="$CP:$LIB_DIR/com/fasterxml/jackson/core/jackson-core/${jackson.version}/*"
CP="$CP:$WDIR/lib/*"

KC_DIR=$WDIR/keycerts
## Generate keys
$JAVA_EXEC -cp "$CP" org.xipki.security.pkcs12.GenerateCerts $WDIR/keycerts.json $KC_DIR

## Copying generated keys to the XiPKI components
RDIR=$WDIR/..
KS_DIR=$KC_DIR/certstore

# CA
echo "Copying generated keys to the XiPKI component xipki-ca"

TDIR=$RDIR/xipki-ca/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/*.p12 \
   $KC_DIR/hsmproxy-client/*-cert.pem \
   $KC_DIR/ca-server/*.p12 \
   $KC_DIR/ca-server/*-cert.pem \
   $KC_DIR/hsmproxy-server/*-cert.pem \
   $KC_DIR/ca-mgmt-client/*-cert.pem \
   $KS_DIR/ca-client-certstore.p12 \
   $TDIR

# OCSP
echo "Copying generated keys to the XiPKI component xipki-ocsp"

TDIR=$RDIR/xipki-ocsp/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/*.p12 \
   $KC_DIR/hsmproxy-client/*-cert.pem \
   $KC_DIR/hsmproxy-server/*-cert.pem \
   $TDIR

# Gateway
echo "Copying generated keys to the XiPKI component xipki-gateway"

TDIR=$RDIR/xipki-gateway/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/*.p12 \
   $KC_DIR/hsmproxy-client/*-cert.pem \
   $KC_DIR/gateway-server/*.p12 \
   $KC_DIR/gateway-server/*-cert.pem \
   $KC_DIR/ra-sdk-client/*.p12 \
   $KC_DIR/ra-sdk-client/*-cert.pem \
   $KC_DIR/cmp-client/*-cert.pem \
   $KC_DIR/est-client/*-cert.pem \
   $KC_DIR/rest-client/*-cert.pem \
   $KC_DIR/hsmproxy-server/hsmproxy-server-cert.pem \
   $KC_DIR/ca-server/ca-server-cert.pem \
   $KS_DIR/gateway-client-ca-certstore.p12 \
   $TDIR

# HSM proxy
echo "Copying generated keys to the XiPKI component xipki-hsmproxy"

TDIR=$RDIR/xipki-hsmproxy/tomcat/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-server/*.p12 \
   $KC_DIR/hsmproxy-server/*-cert.pem \
   $KC_DIR/hsmproxy-client/*-cert.pem \
   $KS_DIR/hsmproxy-client-certstore.p12 \
   $TDIR

# xipki-cli
echo "Copying generated keys to the XiPKI component xipki-cli"
TDIR=$RDIR/xipki-cli/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/*.p12 \
   $KC_DIR/hsmproxy-client/*-cert.pem \
   $KC_DIR/cmp-client/* \
   $KC_DIR/est-client/* \
   $KC_DIR/rest-client/* \
   $KC_DIR/hsmproxy-server/hsmproxy-server-cert.pem \
   $KC_DIR/gateway-server/gateway-server-cert.pem \
   $TDIR

# xipki-mgmt-cli
echo "Copying generated keys to the XiPKI component xipki-mgmt-cli"
TDIR=$RDIR/xipki-mgmt-cli/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/*.p12 \
   $KC_DIR/hsmproxy-client/*-cert.pem \
   $KC_DIR/ca-mgmt-client/*.p12 \
   $KC_DIR/ca-mgmt-client/*-cert.pem \
   $KC_DIR/hsmproxy-server/hsmproxy-server-cert.pem \
   $KC_DIR/ca-server/ca-server-cert.pem \
   $KC_DIR/gateway-server/gateway-server-cert.pem \
   $KC_DIR/ra-sdk-client/ra-sdk-client-cert.pem* \
   $TDIR
