#!/bin/sh

VERSION=1.3.0

mvn install:install-file -Dfile=iaikPkcs11Wrapper-${VERSION}.jar -DgroupId=at.tugraz.iaik \
  -DartifactId=iaikPkcs11Wrapper -Dversion=${VERSION} -Dpackaging=jar

mvn install:install-file -Dfile=iaikPkcs11Wrapper-native-${VERSION}.zip -DgroupId=at.tugraz.iaik \
  -DartifactId=iaikPkcs11Wrapper-native -Dversion=${VERSION} -Dpackaging=zip
