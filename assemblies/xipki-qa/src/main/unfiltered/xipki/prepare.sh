#!/bin/sh

DIR=`dirname $0`

echo "working dir: ${DIR}"

cp -r ${DIR}/ca ${DIR}/ocsp /opt/xipki

cp /opt/xipki/ca/etc/database/mariadb/*.properties /opt/xipki/ca/etc/database/

cp /opt/xipki/ocsp/etc/database/mariadb/*.properties /opt/xipki/ocsp/etc/database/