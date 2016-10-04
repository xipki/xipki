#!/bin/sh

# Please adapt the URL
BASE_URL="https://localhost:8443/rest/SubCAwithCRL"

echo "${BASE_URL}"

DIR=`dirname $0`

echo ${DIR}

TLS_CLIENT_CERT="${DIR}/../security/tlskeys/tls-client-keystore.p12:1234"

filename=tls-`date +%s` 

echo "generate RSA keypair"

openssl genrsa -out ${filename}-key.pem 2048

echo "generate CSR"

openssl req -new -key ${filename}-key.pem -outform der \
    -out ${filename}.csr \
    -subj "/CN=${filename}.xipki.org/O=xipki/C=DE"

echo "get CA certificate"

curl -k --cert ${TLS_CLIENT_CERT} \
    --output cacert.der \
    "${BASE_URL}/cacert"

echo "enroll certificate"

curl -k --cert ${TLS_CLIENT_CERT} \
    --header "Content-Type: application/pkcs10" \
    --data-binary "@${filename}.csr" \
    --output ${filename}.der -v \
    "${BASE_URL}/enroll-cert?profile=TLSA"

# get the serial number
SERIAL=0X`openssl x509 -inform der -serial -noout -in ${filename}.der | cut -d '=' -f 2`

echo "suspend certificate"

curl -k --cert ${TLS_CLIENT_CERT} \
    "${BASE_URL}/revoke-cert?serial-number=${SERIAL}&reason=certificateHold"

echo "ussuspend certificate"

curl -k --cert ${TLS_CLIENT_CERT} \
    "${BASE_URL}/revoke-cert?serial-number=${SERIAL}&reason=removeFromCRL"

echo "ussuspend certificate"

curl -k --cert ${TLS_CLIENT_CERT} \
    "${BASE_URL}/revoke-cert?serial-number=${SERIAL}&reason=keyCompromise"

echo "generate new CRL"

curl -k --cert ${TLS_CLIENT_CERT} \
    --output new-crl.der \
    "${BASE_URL}/new-crl"

echo "get current CRL"

curl -k --cert ${TLS_CLIENT_CERT} \
    --output crl.der \
    "${BASE_URL}/crl"

echo "get CRL for given CRL number"

curl -k --cert ${TLS_CLIENT_CERT} \
    --output crl-1.der \
    "${BASE_URL}/crl?crl-number=1"
