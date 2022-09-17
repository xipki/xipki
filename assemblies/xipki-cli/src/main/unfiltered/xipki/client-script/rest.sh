#!/bin/bash

ocsp=0

if [[ "$1" == "help" ]] ; then
  echo "Usage: "
  echo ""
  echo "/path/to/rest.sh [help|ocsp]"
  echo "    help:      Print this usage"
  echo "    ocsp:      Also test the OCSP status"
  exit
elif [[ "$1" == "ocsp" ]] ; then
  ocsp=1
fi

# Please adapt the URL
CA_URL="https://localhost:8445/rest/myca"
echo "CA URL: ${CA_URL}"

OCSP_URL="http://localhost:8080/ocsp/"

echo "OCSP URL: ${OCSP_URL}"

DIR=`dirname $0`

echo "working dir: ${DIR}"

# Use user and password to authorize
OPTS="--insecure --user user1:password1"

# Use TLS client certificate to authorize in Linux
#OPTS="--insecure --cert ${DIR}/../keycerts/tlskeys/client/tls-client-cert.pem --key ${DIR}/../keycerts/tlskeys/client/tls-client-key.pem"

# Use TLS client certificate to authorize in Mac
#OPTS="--insecure --cert-type PKCS#12 --cert ${DIR}/../keycerts/tlskeys/client/tls-client.p12:1234"

CUR_TIME=`date +%Y%m%d-%H%M%S`

OUT_DIR=${DIR}/../../output/rest-${CUR_TIME}

echo "output directory: ${OUT_DIR}"

mkdir -p ${OUT_DIR}

echo "get CA certificate"

curl --insecure --output ${OUT_DIR}/cacert.der "${CA_URL}/cacert"

curl --insecure --output ${OUT_DIR}/cacerts.pem "${CA_URL}/cacerts"

CA_SHA1FP=`openssl sha1 ${OUT_DIR}/cacert.der | cut -d '=' -f 2 | cut -d ' ' -f 2`

# The PEM file will be used by "openssl ocsp"
openssl x509 -inform der -in ${OUT_DIR}/cacert.der -out ${OUT_DIR}/cacert.pem

# enroll certificate smime
CN=smime-${CUR_TIME}

echo "generate RSA keypair"

openssl genrsa -out ${OUT_DIR}/${CN}-key.pem 2048

echo "generate CSR"

openssl req -new -sha256 -key ${OUT_DIR}/${CN}-key.pem -outform der \
    -out ${OUT_DIR}/${CN}.csr \
    -subj "/C=DE/O=myorg/CN=${CN}/emailAddress=info@example.com"

echo "enroll certificate"

curl ${OPTS} \
    --header "Content-Type: application/pkcs10" \
    --data-binary "@${OUT_DIR}/${CN}.csr" \
    --output ${OUT_DIR}/${CN}.der \
    "${CA_URL}/enroll-cert?profile=smime"

# enroll certificate tls (CA generate keypair)
CN=tls-genkey-${CUR_TIME}

echo "enroll certificate (CA generate keypair)"

curl ${OPTS} \
    --header "Content-Type: text/plain; encoding=utf-8" \
    --data-ascii "subject=C=DE,O=example,CN=${CN}.example.org" \
    --output ${OUT_DIR}/${CN}.pem \
    "${CA_URL}/enroll-serverkeygen?profile=tls"

# enroll certificate tls
CN=tls-${CUR_TIME}

echo "generate RSA keypair"

openssl genrsa -out ${OUT_DIR}/${CN}-key.pem 2048

echo "generate CSR"

openssl req -new -sha256 -key ${OUT_DIR}/${CN}-key.pem -outform der \
    -out ${OUT_DIR}/${CN}.csr \
    -subj "/C=DE/O=myorg/CN=${CN}.example.org"

echo "enroll certificate"

curl ${OPTS} \
    --header "Content-Type: application/pkcs10" \
    --data-binary "@${OUT_DIR}/${CN}.csr" \
    --output ${OUT_DIR}/${CN}.der \
    "${CA_URL}/enroll-cert?profile=tls"

# get the serial number
SERIAL=0X`openssl x509 -inform der -serial -noout -in ${OUT_DIR}/${CN}.der | cut -d '=' -f 2`

# The PEM file will be used by "openssl ocsp"
openssl x509 -inform der -in ${OUT_DIR}/${CN}.der -out ${OUT_DIR}/${CN}.pem

if [[ $ocsp -eq 1 ]]; then
	echo "Current OCSP status"

	openssl ocsp -nonce  -CAfile ${OUT_DIR}/cacert.pem -url ${OCSP_URL} -issuer ${OUT_DIR}/cacert.pem -cert ${OUT_DIR}/${CN}.pem
fi

echo "suspend certificate"

curl ${OPTS} "${CA_URL}/revoke-cert?ca-sha1=${CA_SHA1FP}&serial-number=${SERIAL}&reason=certificateHold"

if [[ $ocsp -eq 1 ]]; then
	echo "Current OCSP status"
	echo "Current OCSP status"

	openssl ocsp -nonce  -CAfile ${OUT_DIR}/cacert.pem -url ${OCSP_URL} -issuer ${OUT_DIR}/cacert.pem -cert ${OUT_DIR}/${CN}.pem
fi

echo "unsuspend certificate"

curl ${OPTS} "${CA_URL}/unsuspend-cert?ca-sha1=${CA_SHA1FP}&serial-number=${SERIAL}"

if [[ $ocsp -eq 1 ]]; then
	echo "Current OCSP status"

	openssl ocsp -nonce  -CAfile ${OUT_DIR}/cacert.pem -url ${OCSP_URL} -issuer ${OUT_DIR}/cacert.pem -cert ${OUT_DIR}/${CN}.pem
fi

echo "revoke certificate"

curl ${OPTS} "${CA_URL}/revoke-cert?ca-sha1=${CA_SHA1FP}&serial-number=${SERIAL}&reason=keyCompromise"

if [[ $ocsp -eq 1 ]]; then
	echo "Current OCSP status"

	openssl ocsp -nonce  -CAfile ${OUT_DIR}/cacert.pem -url ${OCSP_URL} -issuer ${OUT_DIR}/cacert.pem -cert ${OUT_DIR}/${CN}.pem
fi

# echo "get current CRL"

# curl ${OPTS} --output ${OUT_DIR}/crl.crl "${CA_URL}/crl"

