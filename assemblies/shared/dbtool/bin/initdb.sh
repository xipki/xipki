#!/bin/sh

MYPWD=`pwd`

DIRNAME=$(dirname "$0")

if [ ! -d "$DIRNAME/../tmplib" ]; then
	mkdir "$DIRNAME/../tmplib"
	cd "$DIRNAME/../tmplib"

	if [ -f "../../webapps/ca.war" ]; then
		WARFILE=../../webapps/ca.war
	else
		WARFILE=../../webapps/ocsp.war
	fi

	jar xf $WARFILE WEB-INF/lib
	cd $MYPWD
fi

if [ "x$JAVA_HOME" = "x" ]; then
     JAVA_EXEC=java
else
     JAVA_EXEC=$JAVA_HOME/bin/java
fi

CLASSPATH="$DIRNAME/../lib/*:$DIRNAME/../../lib/*:$DIRNAME/../tmplib/WEB-INF/lib/*"

$JAVA_EXEC -cp "$CLASSPATH" org.xipki.dbtool.InitDbMain "$@"