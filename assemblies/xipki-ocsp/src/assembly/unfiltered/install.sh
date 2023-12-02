#!/bin/bash

set -e

helpFunction()
{
   echo ""
   echo "Usage: $0 -t <dir of destination tomcat>"
#   echo "Usage: $0 -a parameterA -b parameterB"
#   echo -e "\t-a Description of what is parameterA"
#   echo -e "\t-b Description of what is parameterB"
   exit 1 # Exit script after printing help
}

#while getopts "a:b:" opt
while getopts "t:" opt
do
   case "$opt" in
      t ) tomcatDir="$OPTARG" ;;
#      a ) parameterA="$OPTARG" ;;
#      b ) parameterB="$OPTARG" ;;
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

echo $tomcatDir
## workding dir
WDIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
#WDIR=`dirname $0`

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

SRC="${tomcatDir}/lib/passwords-*.jar"
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

WAR="${tomcatDir}/webapps/ocsp"
[ -f ${WAR}.war ] && mv ${WAR}.war ${BDIR}/webapps
rm -rf "${WAR}"

if [ "$TOMCAT_VERSION" -lt "10" ]; then
  _DIR=tomcat8on
else
  _DIR=tomcat10on
fi

cp -r ${WDIR}/tomcat/* ${tomcatDir}
cp -r ${WDIR}/${_DIR}/* ${tomcatDir}
