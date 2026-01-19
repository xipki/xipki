#!/bin/bash

set -e

WDIR=$(dirname "$0")

${WDIR}/../../../../xipki-ca/install.sh -t ~/test/xipki/ca-tomcat

${WDIR}/../../../../xipki-ocsp/install.sh -t ~/test/xipki/ocsp-tomcat

${WDIR}/../../../../xipki-gateway/install.sh -t ~/test/xipki/gateway-tomcat

cp ${WDIR}/../../../../xipki-cli/xipki/keycerts/kem-pop.jceks \
   ${WDIR}/../../../../xipki-cli/xipki/keycerts/dh-pop-certs.pem \
   ${WDIR}/../../..//xipki/keycerts/

cp ${WDIR}/../../../../xipki-cli/xipki/etc/csr.json \
   ${WDIR}/../../..//xipki/etc/
