#!/bin/bash

# Database type: h2, mariadb, pgsql
DATABASE_TYPE=h2
DEMO_DIR=~/demo_xipki
TOMCAT_MAJOR_VERSION=10

# Exit immediately if a command exits with a non-zero status.
set -e

WDIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

LIB_DIR=$WDIR/xipki-mgmt-cli/system

CP="$LIB_DIR/org/xipki/util-extra/${project.version}/*"
CP="$CP:$LIB_DIR/org/xipki/codec/${project.version}/*"
CP="$CP:$LIB_DIR/org/xipki/util/${project.version}/*"
CP="$CP:$WDIR/war-common/WEB-INF/lib/*"

if [ "x$JAVA_HOME" = "x" ]; then
	JAVA_EXEC=java
else
	JAVA_EXEC=$JAVA_HOME/bin/java
fi

$JAVA_EXEC -cp "$CP" -Ddemo.dir=${DEMO_DIR} \
  org.xipki.util.extra.misc.BatchReplace setup/demo-conf.json

sh $WDIR/prepare.sh

# Test base dir
mkdir -p $DEMO_DIR

if ls $DEMO_DIR/apache-tomcat-${TOMCAT_MAJOR_VERSION}*.tar.gz  &> /dev/null; then
  TOMCAT_VERSION=$(ls $DEMO_DIR/apache-tomcat-${TOMCAT_MAJOR_VERSION}.*.tar.gz | tail -n 1 | cut -d "-" -f 3 | cut -d "." -f 1-3)
else
  TOMCAT_VERSION=`curl --silent http://dlcdn.apache.org/tomcat/tomcat-$TOMCAT_MAJOR_VERSION/ | grep v$TOMCAT_MAJOR_VERSION | tail -n 1 | awk '{split($5,c,">v") ; split(c[2],d,"/") ; print d[1]}'`
fi

echo "Tomcat ${TOMCAT_VERSION}"
TOMCAT_DIR=apache-tomcat-${TOMCAT_VERSION}
TOMCAT_BINARY=${TOMCAT_DIR}.tar.gz

WDIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
#WDIR=`dirname $0`
echo "working dir: ${WDIR}"

cd $DEMO_DIR
echo "change to folder: `pwd`"

## download tar.gz file if not available
if [ -f ${TOMCAT_BINARY} ]; then
  echo "Use local ${TOMCAT_BINARY}"
else
  echo "Download ${TOMCAT_BINARY}"
  # For QA only, no-check-certificate is fine.
  wget --no-check-certificate https://dlcdn.apache.org/tomcat/tomcat-${TOMCAT_MAJOR_VERSION}/v${TOMCAT_VERSION}/bin/${TOMCAT_BINARY}
fi

rm -rf ca-tomcat ocsp-tomcat gateway-tomcat

rm -rf $TOMCAT_DIR
tar xf $TOMCAT_BINARY

rm -rf $TOMCAT_DIR/webapps/*

cp -r $TOMCAT_DIR ca-tomcat
cp -r $TOMCAT_DIR ocsp-tomcat
mv    $TOMCAT_DIR gateway-tomcat

cd $WDIR
echo "change to folder: `pwd`"

${WDIR}/xipki-ca/install.sh      -t ${DEMO_DIR}/ca-tomcat

${WDIR}/xipki-ocsp/install.sh    -t ${DEMO_DIR}/ocsp-tomcat

${WDIR}/xipki-gateway/install.sh -t ${DEMO_DIR}/gateway-tomcat

# overwrite the database files
DBCONF_DIR=${WDIR}/xipki-ca/tomcat/xipki/etc/ca/database/${DATABASE_TYPE}
DBCONF_CA=${DBCONF_DIR}/ca-db.properties
DBCONF_CACONF=${DBCONF_DIR}/caconf-db.properties
DBCONF_OCSP=${DBCONF_DIR}/ocsp-db.properties

if [ "$DATABASE_TYPE" = "h2" ]; then
  rm -rf ~/.xipki/db/h2/
fi

cp $DBCONF_CA $DBCONF_CACONF $DBCONF_OCSP \
   ${DEMO_DIR}/ca-tomcat/xipki/etc/ca/database/

cp $DBCONF_CA $DBCONF_OCSP \
   ${DEMO_DIR}/ocsp-tomcat/xipki/etc/ocsp/database/

cd ${WDIR}/xipki-mgmt-cli

echo "change to folder: `pwd`"

bin/karaf
