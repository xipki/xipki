# Try to guess where xipki conf is
if [ -d ${CATALINA_HOME}/xipki ] ; then
	# try first the CATALINA_HOME - original
	export JAVA_OPTS="${JAVA_OPTS} -DXIPKI_BASE=${CATALINA_HOME}/xipki"
elif [ -d ${CATALINA_BASE}/xipki ] ; then
	# try the CATALINA_BASE (usual setup on debian/ubuntu)
	export JAVA_OPTS="${JAVA_OPTS} -DXIPKI_BASE=${CATALINA_BASE}/xipki"
else
	# Finally fall back to CATALINA_HOME (source install)
	export JAVA_OPTS="${JAVA_OPTS} -DXIPKI_BASE=${CATALINA_HOME}/xipki"
fi

export JDK_JAVA_OPTIONS="${JDK_JAVA_OPTIONS} --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED"
