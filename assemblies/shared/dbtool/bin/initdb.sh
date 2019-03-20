#!/bin/sh

DIRNAME=$(dirname "$0")
TMPLIB="$DIRNAME/../tmplib"

if [ ! -d "$TMPLIB" ]; then
	WEBAPPS="$DIRNAME/../../webapps"
	if [ -f "$WEBAPPS/ca.war" ]; then
		WARFILE=$WEBAPPS/ca.war
	else
		WARFILE=$WEBAPPS/ocsp.war
	fi

	unzip -q -d "$TMPLIB" $WARFILE
fi

if [ "x$JAVA_HOME" = "x" ]; then
	JAVA_EXEC=java
else
	JAVA_EXEC=$JAVA_HOME/bin/java
fi

CLASSPATH="$DIRNAME/../lib/*:$DIRNAME/../../lib/*:$TMPLIB/WEB-INF/lib/*"

$JAVA_EXEC -cp "$CLASSPATH" org.xipki.dbtool.InitDbMain "$@"
