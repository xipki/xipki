#!/bin/sh

VERSION=1.3

mvn install:install-file -Dfile=pkcs11-wrapper-${VERSION}.jar -DgroupId=at.tugraz.iaik \
  -DartifactId=pkcs11-wrapper -Dversion=${VERSION} -Dpackaging=jar

mvn install:install-file -Dfile=pkcs11-wrapper-native-${VERSION}.zip -DgroupId=at.tugraz.iaik \
  -DartifactId=pkcs11-wrapper-native -Dversion=${VERSION} -Dpackaging=zip
