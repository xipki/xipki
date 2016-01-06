#!/bin/sh

# pkcs11-wrapper
mvn install:install-file -Dfile=pkcs11-wrapper-1.3.jar -DgroupId=at.tugraz.iaik \
  -DartifactId=pkcs11-wrapper -Dversion=1.3 -Dpackaging=jar

mvn install:install-file -Dfile=pkcs11-wrapper-native-1.3.zip -DgroupId=at.tugraz.iaik \
  -DartifactId=pkcs11-wrapper-native -Dversion=1.3 -Dpackaging=zip

