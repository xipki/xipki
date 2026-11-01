# Try to guess where xipki conf is

if [ -d ${CATALINA_HOME}/xipki ] ; then
	# try first the CATALINA_HOME - original
	XI_TOMCAT_BASE=${CATALINA_HOME}
elif [ -d ${CATALINA_BASE}/xipki ] ; then
	# try the CATALINA_BASE (usual setup on debian/ubuntu)
	XI_TOMCAT_BASE=${CATALINA_BASE}
else
	# Finally fall back to CATALINA_HOME (source install)
	XI_TOMCAT_BASE=${CATALINA_HOME}
fi

export JAVA_OPTS="${JAVA_OPTS} -DXIPKI_BASE=${XI_TOMCAT_BASE}/xipki"

# ML-DSA with context string (composite ML-DSA) with the crypto-be-jdk backend
# uses the internals of the JDK.
export JAVA_OPTS="${JAVA_OPTS} --add-exports java.base/sun.security.provider=ALL-UNNAMED"

# Native access via the foreign function & memory API (restricted methods).
# Without --enable-native-access the JDK prints a warning. The option is only known since Java 17.
if [ -n "${JRE_HOME}" ] ; then
	XI_JAVA_EXEC=${JRE_HOME}/bin/java
elif [ -n "${JAVA_HOME}" ] ; then
	XI_JAVA_EXEC=${JAVA_HOME}/bin/java
else
	XI_JAVA_EXEC=java
fi

XI_JAVA_MAJOR=$("${XI_JAVA_EXEC}" -version 2>&1 | sed -n 's/.* version "\([0-9]*\)\.\{0,1\}\([0-9]*\).*/\1 \2/p' | head -n 1)
case "${XI_JAVA_MAJOR}" in
	"1 "*) XI_JAVA_MAJOR=${XI_JAVA_MAJOR#1 } ;;
	*) XI_JAVA_MAJOR=${XI_JAVA_MAJOR%% *} ;;
esac

if [ -n "${XI_JAVA_MAJOR}" ] && [ "${XI_JAVA_MAJOR}" -ge 17 ] 2>/dev/null ; then
	export JAVA_OPTS="${JAVA_OPTS} --enable-native-access=ALL-UNNAMED"
fi
