#!/bin/sh

set -e

helpFunction()
{
   echo ""
   echo "Usage: $0 -t <dest dir>"
   exit 1 # Exit script after printing help
}

if [ -z "$1" ]
then
   echo "<dest dir> is not specified";
   helpFunction
fi

WDIR=$(dirname "$0")

if [ "x$JAVA_HOME" = "x" ]; then
	JAVA_EXEC=java
else
	JAVA_EXEC=$JAVA_HOME/bin/java
fi

CLASSPATH="$WDIR/../lib:$WDIR/../lib/*"

$JAVA_EXEC -cp "$CLASSPATH" org.xipki.apppackage.RestorePackage $WDIR/../files "$1"

