#!/bin/bash

set -e

helpFunction()
{
   echo ""
   echo "Usage: $0 [OPTION]... -t <dir of destination tomcat>"
   echo "OPTIONS"
   echo -e "\t-a protocol ACME"
   echo -e "\t-c: protocol CMP"
   echo -e "\t-e: protocol EST"
   echo -e "\t-r: protocol REST"
   echo -e "\t-s: protocol SCEP"
   echo -e "\tno option: all protocols"
   exit 1 # Exit script after printing help
}

#while getopts "a:b:" opt
while getopts "t:acers" opt
do
   case "$opt" in
      t ) tomcatDir="$OPTARG" ;;
      a ) ACME=1 ;;
      c ) CMP=1 ;;
      e ) EST=1 ;;
      r ) REST=1 ;;
      s ) SCEp=1 ;;
      ? ) helpFunction ;; # Print helpFunction in case parameter is non-existent
   esac
done

# Print helpFunction in case parameters are empty
#if [ -z "$parameterA" ] || [ -z "$parameterB" ]
if [ -z "$tomcatDir" ]
then
   echo "Some or all of the parameters are empty";
   helpFunction
fi

if [ "$ACME" == "1" ] || [ "$CMP" == "1" ] || [ "$EST" == "1" ] || [ "$REST" == "1" ] || [ "$SCEP" == "1" ]
then
  DUMMY=0
else
  ACME=1
  CMP=1
  EST=1
  REST=1
  SCEP=1
fi

## workding dir
#WDIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
WDIR=`dirname $0`

## check the pre-conditions
if [ ! -d ${WDIR}/tomcat/xipki/keycerts ]; then
   echo "Generate the key and certificate via ${WDIR}/../setup/generate-keycerts.sh first."
   exit 1
fi

echo "Tomcat: $tomcatDir"

## make sure the tomcat is only for HSM proxy
if [ -f ${tomcatDir}/webapps/ca.war ]; then
   echo "CA is running in $tomcatDir, please use other tomcat instance."
   exit 1
fi

if [ -f ${tomcatDir}/webapps/hsmproxy.war ]; then
   echo "HSM proxy is running in $tomcatDir, please use other tomcat instance."
   exit 1
fi

if [ -f ${tomcatDir}/webapps/ocsp.war ]; then
   echo "OCSP responder is running in $tomcatDir, please use other tomcat instance."
   exit 1
fi

## detect the major version of tomcat
TOMCAT_VERSION=`${tomcatDir}/bin/version.sh | grep "Server number"`
echo "Tomcat ${TOMCAT_VERSION}"

TOMCAT_VERSION=`cut -d ":" -f2- <<< "${TOMCAT_VERSION}"`
TOMCAT_VERSION=`cut -d "." -f1  <<< "${TOMCAT_VERSION}"`
## Remove leading and trailing spaces and tabs
TOMCAT_VERSION=`awk '{$1=$1};1'  <<< "${TOMCAT_VERSION}"`

if [ "$TOMCAT_VERSION" -lt "8" ]; then
  echo "Unsupported tomcat major version ${TOMCAT_VERSION}"
  exit 1
fi

## Backup the current files
BDIR=$tomcatDir/backup-`date '+%Y%m%dT%H%M%S'`
mkdir ${BDIR}
mkdir ${BDIR}/bin
mkdir ${BDIR}/lib
mkdir ${BDIR}/conf
mkdir ${BDIR}/webapps
echo "back up dir: $BDIR"

SRC="${tomcatDir}/xipki"
[ -d $SRC ] && cp -r $SRC ${BDIR}

SRC="${tomcatDir}/conf/catalina.properties"
[ -f $SRC ] && mv $SRC ${BDIR}/conf

SRC="${tomcatDir}/conf/server.xml"
[ -f $SRC ] && mv $SRC ${BDIR}/conf

# mv if file exists
# [ -f old ] && mv old nu

SRC="${tomcatDir}/bin/setenv.*"
for X in $SRC; do [[ -e $X ]] && mv "$X" ${BDIR}/bin; done

SRC="${tomcatDir}/lib/password-*.jar"
for X in $SRC; do [[ -e $X ]] && mv "$X" ${BDIR}/lib; done

SRC="${tomcatDir}/lib/xipki-tomcat-password-*.jar"
for X in $SRC; do [[ -e $X ]] && mv "$X" ${BDIR}/lib; done

SRC="${tomcatDir}/lib/*pkcs11wrapper-*.jar"
for X in $SRC; do [[ -e $X ]] && mv "$X" ${BDIR}/lib; done

SRC="${tomcatDir}/lib/bc*-jdk*.jar"
for X in $SRC; do [[ -e $X ]] && mv "$X" ${BDIR}/lib; done

SRC="${tomcatDir}/lib/h2-*.jar"
for X in $SRC; do [[ -e $X ]] && mv "$X" ${BDIR}/lib; done

SRC="${tomcatDir}/lib/mariadb-java-*.jar"
for X in $SRC; do [[ -e $X ]] && mv "$X" ${BDIR}/lib; done

SRC="${tomcatDir}/lib/mariadb-java-*.jar"
for X in $SRC; do [[ -e $X ]] && mv "$X" ${BDIR}/lib; done

if [ "$TOMCAT_VERSION" -lt "10" ]; then
  _DIR=tomcat8on
else
  _DIR=tomcat10on
fi

cp -r ${WDIR}/tomcat/* ${tomcatDir}
cp -r ${WDIR}/${_DIR}/conf ${tomcatDir}/

if [ "$ACME" == "1" ]; then
  echo "Copying acme.war"
  WAR="${tomcatDir}/webapps/acme"

  [ -f ${WAR}.war ] && mv ${WAR}.war ${BDIR}/webapps
  rm -rf "${WAR}"

  cp ${WDIR}/${_DIR}/webapps/acme.war ${tomcatDir}/webapps
fi

if [ "$CMP" == "1" ]; then
  echo "Copying cmp.war"
  WAR="${tomcatDir}/webapps/cmp"

  [ -f ${WAR}.war ] && mv ${WAR}.war ${BDIR}/webapps
  rm -rf "${WAR}"

  cp ${WDIR}/${_DIR}/webapps/cmp.war ${tomcatDir}/webapps
fi

if [ "$EST" == "1" ]; then
  echo "Copying est.war"
  WAR="${tomcatDir}/webapps/est"

  [ -f ${WAR}.war ] && mv ${WAR}.war ${BDIR}/webapps
  rm -rf "${WAR}"

  cp ${WDIR}/${_DIR}/webapps/est.war ${tomcatDir}/webapps
fi

if [ "$REST" == "1" ]; then
  echo "Copying rest.war"
  WAR="${tomcatDir}/webapps/rest"

  [ -f ${WAR}.war ] && mv ${WAR}.war ${BDIR}/webapps
  rm -rf "${WAR}"

  cp ${WDIR}/${_DIR}/webapps/rest.war ${tomcatDir}/webapps
fi

if [ "$SCEP" == "1" ]; then
  echo "Copying scep.war"
  WAR="${tomcatDir}/webapps/scep"

  [ -f ${WAR}.war ] && mv ${WAR}.war ${BDIR}/webapps
  rm -rf "${WAR}"

  cp ${WDIR}/${_DIR}/webapps/scep.war ${tomcatDir}/webapps
fi
