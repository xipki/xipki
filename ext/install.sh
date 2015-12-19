#!/bin/sh

# pkcs11-wrapper
mvn install:install-file -Dfile=pkcs11-wrapper-1.3.jar -DgroupId=at.tugraz.iaik \
  -DartifactId=pkcs11-wrapper -Dversion=1.3 -Dpackaging=jar

mvn install:install-file -Dfile=pkcs11-wrapper-native-1.3.zip -DgroupId=at.tugraz.iaik \
  -DartifactId=pkcs11-wrapper-native -Dversion=1.3 -Dpackaging=zip

## Install bundles
GROUP=org.xipki.bundles

ARTIFACT=at.tugraz.iaik.pkcs11-wrapper
VERSION=1.3
mvn install:install-file -Dfile=bundles/${ARTIFACT}-${VERSION}.jar -DgroupId=${GROUP} \
  -DartifactId=${ARTIFACT} -Dversion=${VERSION} -Dpackaging=jar

ARTIFACT=com.caucho.hessian
VERSION=4.0.38
mvn install:install-file -Dfile=bundles/${ARTIFACT}-${VERSION}.jar -DgroupId=${GROUP} \
  -DartifactId=${ARTIFACT} -Dversion=${VERSION} -Dpackaging=jar

ARTIFACT=com.cloudbees.syslog-java-client
VERSION=1.0.7
mvn install:install-file -Dfile=bundles/${ARTIFACT}-${VERSION}.jar -DgroupId=${GROUP} \
  -DartifactId=${ARTIFACT} -Dversion=${VERSION} -Dpackaging=jar

mvn install:install-file -Dfile=pkcs11-wrapper-native-1.3.zip -DgroupId=at.tugraz.iaik \
  -DartifactId=pkcs11-wrapper-native -Dversion=1.3 -Dpackaging=zip
