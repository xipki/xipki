#!/bin/sh

filename="tls-"`date +%s` 

openssl genrsa -out $filename.pem 2048

openssl req -new -key ${filename}.pem -outform der -out ${filename}.req -subj "/CN=${filename}.xipki.org/2.5.4.97=VATDE-123456789/O=xipki/C=DE"

#curl --cert ../security/tls-keys/tls-client.pem --key ../security/tls-keys/tls-client-privateKey.pem -k $host:$port/rest/SUBCAWITHCRL/enroll ...
