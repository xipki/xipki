#!/bin/sh

DIRNAME=$(dirname "$0")

if [ "x$JAVA_HOME" = "x" ]; then
     JAVA_EXEC=java
else
     JAVA_EXEC=$JAVA_HOME/bin/java
fi

$JAVA_EXEC -cp "$DIRNAME/..:$DIRNAME/../lib/*:$DIRNAME/../../lib/*" org.xipki.dbtool.InitDbMain "$@"
