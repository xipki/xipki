#!/bin/sh

DIRNAME=$(dirname "$0")

RDIR=$DIRNAME/..
KC_DIR=$DIRNAME/keycerts
KS_DIR=$DIRNAME/keycerts/certstore

# CA
TDIR=$RDIR/xipki-ca/xipki/keycerts

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
TDIR=$RDIR/xipki-ocsp/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/*.p12 \
   $KC_DIR/hsmproxy-client/*-cert.pem \
   $KC_DIR/hsmproxy-server/*-cert.pem \
   $TDIR

# Gateway
TDIR=$RDIR/xipki-gateway/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-client/*.p12 \
   $KC_DIR/hsmproxy-client/*-cert.pem \
   $KC_DIR/gateway-server/*.p12 \
   $KC_DIR/gateway-server/*-cert.pem \
   $KC_DIR/ra-sdk-client/*.p12 \
   $KC_DIR/ra-sdk-client/*-cert.pem \
   $KC_DIR/hsmproxy-server/hsmproxy-server-cert.pem \
   $KC_DIR/ca-server/ca-server-cert.pem \
   $KS_DIR/gateway-client-ca-certstore.p12 \
   $TDIR

# HSM proxy
TDIR=$RDIR/xipki-hsmproxy/xipki/keycerts

mkdir -p $TDIR

cp $KC_DIR/hsmproxy-server/*.p12 \
   $KC_DIR/hsmproxy-server/*-cert.pem \
   $KS_DIR/hsmproxy-client-certstore.p12 \
   $TDIR

# xipki-cli
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
