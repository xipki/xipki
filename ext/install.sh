#!/bin/sh

mvn install:install-file -Dfile=iaikPkcs11Wrapper-1.2.18.jar -DgroupId=at.tugraz.iaik \
  -DartifactId=iaikPkcs11Wrapper -Dversion=1.2.18 -Dpackaging=jar

mvn install:install-file -Dfile=iaikPkcs11Wrapper-native-1.2.18.zip -DgroupId=at.tugraz.iaik \
  -DartifactId=iaikPkcs11Wrapper-native -Dversion=1.2.18 -Dpackaging=zip
