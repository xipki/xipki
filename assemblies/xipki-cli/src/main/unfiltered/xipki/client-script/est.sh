#!/bin/bash

# Please adapt the URL
CA_URL=https://localhost:8445/.well-known/est/myca/tls
echo "CA URL: ${CA_URL}"

CT_PKCS10="Content-Type: application/pkcs10"

DIR=`dirname $0`

echo "working dir: ${DIR}"

# Use user and password to authorize
OPTS="--insecure --user user1:password1"

# Use TLS client certificate to authorize in Linux
#OPTS="--insecure --cert ${DIR}/../keycerts/tlskeys/client/tls-client-cert.pem --key ${DIR}/../keycerts/tlskeys/client/tls-client-key.pem"

# Use TLS client certificate to authorize in Mac
#OPTS="--insecure --cert-type PKCS#12 --cert ${DIR}/../keycerts/tlskeys/client/tls-client.p12:1234"

CUR_TIME=`date +%Y%m%d-%H%M%S`

OUT_DIR=${DIR}/../../output/est-${CUR_TIME}

echo "output directory: ${OUT_DIR}"

mkdir -p ${OUT_DIR}

echo "#################################################################"
echo "#             Manage certificate via EST interface              #"
echo "#################################################################"

#####
CMD=csrattrs
echo "-----${CMD}-----"
FILE="${OUT_DIR}/${CMD}"

curl --insecure --output "${FILE}.csrattrs.b64" "${CA_URL}/${CMD}"

openssl enc -d -base64 -in ${FILE}.csrattrs.b64 -out ${FILE}.csrattrs

#####
CMD=cacerts
echo "-----${CMD}-----"
FILE="${OUT_DIR}/${CMD}"

curl --insecure --output "${FILE}.p7m" "${CA_URL}/${CMD}"

#####
CMD=simpleenroll
echo "-----${CMD}-----"
FILE="${OUT_DIR}/${CMD}"
CN="enroll-${CUR_TIME}"

echo "generate RSA keypair"

openssl genrsa -out ${FILE}-key.pem 2048

echo "generate CSR"

openssl req -new -sha256 -key ${FILE}-key.pem -outform der -out ${FILE}.csr \
    -subj "/C=DE/O=myorg/CN=${CN}.example.com"

echo "enroll certificate"

openssl enc -base64 -in ${FILE}.csr -out ${FILE}.csr.b64

curl ${OPTS} \
    --header "Content-Type: application/pkcs10" \
    --header "Content-Transfer-Encoding: base64" \
    --data-binary "@${FILE}.csr.b64" \
    --output ${FILE}.p7m \
    "${CA_URL}/${CMD}"

#####
CMD=simplereenroll
echo "-----${CMD}-----"
FILE="${OUT_DIR}/${CMD}"

echo "generate RSA keypair"

openssl genrsa -out ${FILE}-key.pem 2048

echo "generate CSR"

cp ${DIR}/template.openssl-san.cnf ${OUT_DIR}/openssl-san.cnf
echo "DNS.1=${CN}.example.com" >> ${OUT_DIR}/openssl-san.cnf

# must use the same subject as in the certificate to be updated
openssl req -new -sha256 -key ${FILE}-key.pem -outform der -out ${FILE}.csr \
    -subj "/C=DE/O=myorg/CN=${CN}.example.com" -config ${OUT_DIR}/openssl-san.cnf

echo "enroll certificate"

openssl enc -base64 -in ${FILE}.csr -out ${FILE}.csr.b64

curl ${OPTS} \
    --header "Content-Type: application/pkcs10" \
    --header "Content-Transfer-Encoding: base64" \
    --data-binary "@${FILE}.csr.b64" \
    --output ${FILE}.p7m \
    "${CA_URL}/${CMD}"

#####
CMD=serverkeygen
echo "-----${CMD}-----"
FILE="${OUT_DIR}/${CMD}"
CN="${CMD}-${CUR_TIME}"

echo "generate dummy RSA keypair (will not be used by CA)"

openssl genrsa -out ${FILE}-dummy.pem 2048

echo "generate dummy CSR"

# The public key and signature will be ignored by the server
openssl req -new -sha256 -key ${FILE}-dummy.pem -outform der -out ${FILE}.csr \
    -subj "/C=DE/O=myorg/CN=${CN}.example.com"

echo "enroll certificate"

openssl enc -base64 -in ${FILE}.csr -out ${FILE}.csr.b64

curl ${OPTS} \
    --header "Content-Type: application/pkcs10" \
    --header "Content-Transfer-Encoding: base64" \
    --data-binary "@${FILE}.csr.b64" \
    --output ${FILE}.p7m \
    "${CA_URL}/${CMD}"

echo "#################################################################"
echo "#      Manage certificate via EST interface (XiPKI extension)   #"
echo "#################################################################"

#####
CMD=ucacerts
echo "-----${CMD}-----"
FILE="${OUT_DIR}/${CMD}"

curl --insecure --output ${FILE}.pem "${CA_URL}/${CMD}"

#####
CMD=ucacert
echo "-----${CMD}-----"
FILE="${OUT_DIR}/${CMD}"

curl --insecure --output ${FILE}.crt.b64 "${CA_URL}/${CMD}"

openssl enc -d -base64 -in ${FILE}.crt.b64 -out ${FILE}.crt

#####
CMD=ucrl
echo "-----${CMD}-----"
FILE="${OUT_DIR}/${CMD}"

curl --insecure --output ${FILE}.crl.b64 "${CA_URL}/${CMD}"

openssl enc -d -base64 -in ${FILE}.crl.b64 -out ${FILE}.crl

#####
CMD=usimpleenroll
echo "-----${CMD}-----"
FILE="${OUT_DIR}/${CMD}"
CN="enroll-${CUR_TIME}"

echo "generate RSA keypair"

openssl genrsa -out ${FILE}-key.pem 2048

echo "generate CSR"

openssl req -new -sha256 -key ${FILE}-key.pem -outform der -out ${FILE}.csr \
    -subj "/C=DE/O=myorg/CN=${CN}.example.com"

echo "enroll certificate"

openssl enc -base64 -in ${FILE}.csr -out ${FILE}.csr.b64

curl ${OPTS} \
    --header "Content-Type: application/pkcs10" \
    --header "Content-Transfer-Encoding: base64" \
    --data-binary "@${FILE}.csr.b64" \
    --output ${FILE}.crt.b64 \
    "${CA_URL}/${CMD}"

openssl enc -d -base64 -in ${FILE}.crt.b64 -out ${FILE}.crt

#####
CMD=usimplereenroll
echo "-----${CMD}-----"
FILE="${OUT_DIR}/${CMD}"

echo "generate RSA keypair"

openssl genrsa -out ${FILE}-key.pem 2048

echo "generate CSR"

cp ${DIR}/template.openssl-san.cnf ${OUT_DIR}/openssl-san.cnf
echo "DNS.1=${CN}.example.com" >> ${OUT_DIR}/openssl-san.cnf

# must use the same subject as in the certificate to be updated
openssl req -new -sha256 -key ${FILE}-key.pem -outform der -out ${FILE}.csr \
    -subj "/C=DE/O=myorg/CN=${CN}.example.com" -config ${OUT_DIR}/openssl-san.cnf

echo "enroll certificate"

openssl enc -base64 -in ${FILE}.csr -out ${FILE}.csr.b64

curl ${OPTS} \
    --header "Content-Type: application/pkcs10" \
    --header "Content-Transfer-Encoding: base64" \
    --data-binary "@${FILE}.csr.b64" \
    --output ${FILE}.crt.b64 \
    "${CA_URL}/${CMD}"

openssl enc -d -base64 -in ${FILE}.crt.b64 -out ${FILE}.crt

#####
CMD=userverkeygen
echo "-----${CMD}-----"
FILE="${OUT_DIR}/${CMD}"
CN="${CMD}-${CUR_TIME}"

echo "generate dummy RSA keypair (will not be used by CA)"

openssl genrsa -out ${FILE}-dummy.pem 2048

echo "generate dummy CSR"

# The public key and signature will be ignored by the server
openssl req -new -sha256 -key ${FILE}-dummy.pem -outform der -out ${FILE}.csr \
    -subj "/C=DE/O=myorg/CN=${CN}.example.com"

echo "enroll certificate"

openssl enc -base64 -in ${FILE}.csr -out ${FILE}.csr.b64

curl ${OPTS} \
    --header "Content-Type: application/pkcs10" \
    --header "Content-Transfer-Encoding: base64" \
    --data-binary "@${FILE}.csr.b64" \
    --output ${FILE}.pem \
    "${CA_URL}/${CMD}"

echo "extract private key"
openssl pkey -in ${FILE}.pem -out ${FILE}-key.pem

echo "extract certificate"
openssl x509 -in ${FILE}.pem -out ${FILE}-cert.pem

