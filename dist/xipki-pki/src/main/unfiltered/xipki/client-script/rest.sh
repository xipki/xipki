#!/bin/sh

# Please adapt the URL
CA_URL="https://localhost:8443/rest/myca"
echo "CA URL: ${CA_URL}"

OCSP_URL="http://localhost:8080/ocsp/responder1"

echo "OCSP URL: ${OCSP_URL}"

DIR=`dirname $0`

echo "working dir: ${DIR}"

# Use user and password to authorize
OPTS="--insecure --user user1:password1"

# Use TLS client certificate to authorize in Linux
#OPTS="--insecure --cert ${DIR}/tlskeys/tls-client.pem --key ${DIR}/tlskeys/tls-client-key.pem"

# Use TLS client certificate to authorize in Mac
#OPTS="--insecure --cert-type PKCS#12 --cert ${DIR}/tlskeys/tls-client.p12:1234"

CUR_TIME=`date +%Y%m%d-%H%M%S`

OUT_DIR=${DIR}/../../output/rest-${CUR_TIME}

echo "output directory: ${OUT_DIR}"

mkdir -p ${OUT_DIR}

CN=tls-${CUR_TIME} 

echo "generate RSA keypair"

openssl genrsa -out ${OUT_DIR}/${CN}-key.pem 2048

echo "generate CSR"

openssl req -new -sha256 -key ${OUT_DIR}/${CN}-key.pem -outform der \
    -out ${OUT_DIR}/${CN}.csr \
    -subj "/CN=${CN}.xipki.org/O=xipki/C=DE"

echo "get CA certificate"

curl ${OPTS} \
    --output ${OUT_DIR}/cacert.der \
    "${CA_URL}/cacert"

CA_SHA1FP=`openssl sha1 ${OUT_DIR}/cacert.der | cut -d '=' -f 2 | cut -d ' ' -f 2`

# The PEM file will be used by "openssl ocsp"
openssl x509 -inform der -in ${OUT_DIR}/cacert.der -out ${OUT_DIR}/cacert.pem

echo "enroll certificate"

curl ${OPTS} \
    --header "Content-Type: application/pkcs10" \
    --data-binary "@${OUT_DIR}/${CN}.csr" \
    --output ${OUT_DIR}/${CN}.der \
    "${CA_URL}/enroll-cert?profile=TLS"

# get the serial number
SERIAL=0X`openssl x509 -inform der -serial -noout -in ${OUT_DIR}/${CN}.der | cut -d '=' -f 2`

# The PEM file will be used by "openssl ocsp"
openssl x509 -inform der -in ${OUT_DIR}/${CN}.der -out ${OUT_DIR}/${CN}.pem

echo "Current OCSP status"

openssl ocsp -nonce  -CAfile ${OUT_DIR}/cacert.pem -url ${OCSP_URL} \
  -issuer ${OUT_DIR}/cacert.pem -cert ${OUT_DIR}/${CN}.pem

echo "suspend certificate"

curl ${OPTS} \
    "${CA_URL}/revoke-cert?ca-sha1=${CA_SHA1FP}&serial-number=${SERIAL}&reason=certificateHold"

echo "Current OCSP status"

openssl ocsp -nonce  -CAfile ${OUT_DIR}/cacert.pem -url ${OCSP_URL} \
  -issuer ${OUT_DIR}/cacert.pem -cert ${OUT_DIR}/${CN}.pem

echo "unsuspend certificate"

curl ${OPTS} \
    "${CA_URL}/revoke-cert?ca-sha1=${CA_SHA1FP}&serial-number=${SERIAL}&reason=removeFromCRL"

echo "Current OCSP status"

openssl ocsp -nonce  -CAfile ${OUT_DIR}/cacert.pem -url ${OCSP_URL} \
  -issuer ${OUT_DIR}/cacert.pem -cert ${OUT_DIR}/${CN}.pem

echo "revoke certificate"

curl ${OPTS} \
    "${CA_URL}/revoke-cert?ca-sha1=${CA_SHA1FP}&serial-number=${SERIAL}&reason=keyCompromise"

echo "Current OCSP status"

openssl ocsp -nonce  -CAfile ${OUT_DIR}/cacert.pem -url ${OCSP_URL} \
  -issuer ${OUT_DIR}/cacert.pem -cert ${OUT_DIR}/${CN}.pem

echo "generate new CRL"

curl ${OPTS} \
    --output ${OUT_DIR}/new-crl.crl \
    "${CA_URL}/new-crl"

echo "get current CRL"

curl ${OPTS} \
    --output ${OUT_DIR}/crl.crl \
    "${CA_URL}/crl"

echo "get CRL for given CRL number"

CRLNUMBER=`openssl crl -inform der -in ${OUT_DIR}/crl.crl -crlnumber -noout | cut -d '=' -f 2`

curl ${OPTS} \
    --output ${OUT_DIR}/crl-${CRLNUMBER}.crl \
    "${CA_URL}/crl?crl-number=${CRLNUMBER}"
