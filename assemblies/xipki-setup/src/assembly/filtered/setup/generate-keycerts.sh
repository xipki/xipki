#!/bin/sh

DIRNAME=$(dirname "$0")

if [ "x$JAVA_HOME" = "x" ]; then
	JAVA_EXEC=java
else
	JAVA_EXEC=$JAVA_HOME/bin/java
fi

LIB_DIR=$DIRNAME/../xipki-cli/system

CP="$LIB_DIR/org/xipki/commons/security/${xipki.commons.version}/security-${xipki.commons.version}.jar"
CP="$CP:$LIB_DIR/org/xipki/commons/util/${xipki.commons.version}/util-${xipki.commons.version}.jar"
CP="$CP:$LIB_DIR/org/xipki/commons/password/${xipki.commons.version}/password-${xipki.commons.version}.jar"
CP="$CP:$LIB_DIR/org/bouncycastle/bcprov-jdk18on/${bc.version}/bcprov-jdk18on-${bc.version}.jar"
CP="$CP:$LIB_DIR/org/bouncycastle/bcpkix-jdk18on/${bc.version}/bcpkix-jdk18on-${bc.version}.jar"
CP="$CP:$LIB_DIR/org/bouncycastle/bcutil-jdk18on/${bc.version}/bcutil-jdk18on-${bc.version}.jar"
CP="$CP:$LIB_DIR/com/fasterxml/jackson/core/jackson-databind/${jackson.version}/jackson-databind-${jackson.version}.jar"
CP="$CP:$LIB_DIR/com/fasterxml/jackson/core/jackson-annotations/${jackson.version}/jackson-annotations-${jackson.version}.jar"
CP="$CP:$LIB_DIR//com/fasterxml/jackson/core/jackson-core/${jackson.version}/jackson-core-${jackson.version}.jar"
CP="$CP:$DIRNAME/lib/slf4j-api.jar"

# Generate keys
$JAVA_EXEC -cp "$CP" org.xipki.security.pkcs12.GenerateCerts $DIRNAME/keycerts.json $DIRNAME/keycerts
