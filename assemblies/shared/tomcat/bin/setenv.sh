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

