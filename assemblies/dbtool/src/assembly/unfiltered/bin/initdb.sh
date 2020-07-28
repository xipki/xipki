#!/bin/sh

DIRNAME=$(dirname "$0")

if [ "x$JAVA_HOME" = "x" ]; then
	JAVA_EXEC=java
else
	JAVA_EXEC=$JAVA_HOME/bin/java
fi

CLASSPATH="$DIRNAME/../lib:$DIRNAME/../lib/*:$DIRNAME/../lib/jdbc/*"

$JAVA_EXEC -cp "$CLASSPATH" org.xipki.dbtool.InitDbMain "$@"
