#!/bin/sh

# Please adapt the URL
BASE_URL="https://localhost:8443/rest/SubCAwithCRL"
CACERT="output/SubCAwithCRL1.der"

echo "base url: ${BASE_URL}"

DIRNAME=`dirname $0`

echo "working dir: ${DIRNAME}"

CA_SHA1FP=`openssl sha1 ${DIR}/../../${CACERT} | cut -d '=' -f 2 | cut -d ' ' -f`

SSL="-k --cert ${DIRNAME}/../security/tlskeys/tls-client.pem --key ${DIRNAME}/../security/tlskeys/tls-client-privateKey.pem"

filename=tls-`date +%s` 

echo "generate RSA keypair"

openssl genrsa -out ${filename}-key.pem 2048

echo "generate CSR"

openssl req -new -sha256 -key ${filename}-key.pem -outform der \
    -out ${filename}.csr \
    -subj "/CN=${filename}.xipki.org/O=xipki/C=DE"

echo "get CA certificate"

curl ${SSL} \
    --output cacert.der \
    "${BASE_URL}/cacert"

echo "enroll certificate"

curl ${SSL} \
    --header "Content-Type: application/pkcs10" \
    --data-binary "@${filename}.csr" \
    --output ${filename}.der -v \
    "${BASE_URL}/enroll-cert?profile=TLSA"

# get the serial number
SERIAL=0X`openssl x509 -inform der -serial -noout -in ${filename}.der | cut -d '=' -f 2`

echo "suspend certificate"

curl ${SSL} \
    "${BASE_URL}/revoke-cert?ca-sha1={CA_SHA1FP}&serial-number=${SERIAL}&reason=certificateHold"

echo "unsuspend certificate"

curl ${SSL} \
    "${BASE_URL}/revoke-cert?ca-sha1={CA_SHA1FP}&serial-number=${SERIAL}&reason=removeFromCRL"

echo "revoke certificate"

curl ${SSL} \
    "${BASE_URL}/revoke-cert?ca-sha1={CA_SHA1FP}&serial-number=${SERIAL}&reason=keyCompromise"

echo "generate new CRL"

curl ${SSL} \
    --output new-crl.crl \
    "${BASE_URL}/new-crl"

echo "get current CRL"

curl ${SSL} \
    --output crl.crl \
    "${BASE_URL}/crl"

echo "get CRL for given CRL number"

CRLNUMBER=`openssl crl -inform der -in crl.crl -crlnumber -noout | cut -d '=' -f 2`

curl ${SSL} \
    --output crl-${CRLNUMBER}.crl \
    "${BASE_URL}/crl?crl-number=${CRLNUMBER}"
