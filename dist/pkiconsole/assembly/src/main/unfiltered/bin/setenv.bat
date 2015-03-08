@echo off
rem
rem
rem    Licensed to the Apache Software Foundation (ASF) under one or more
rem    contributor license agreements.  See the NOTICE file distributed with
rem    this work for additional information regarding copyright ownership.
rem    The ASF licenses this file to You under the Apache License, Version 2.0
rem    (the "License"); you may not use this file except in compliance with
rem    the License.  You may obtain a copy of the License at
rem
rem       http://www.apache.org/licenses/LICENSE-2.0
rem
rem    Unless required by applicable law or agreed to in writing, software
rem    distributed under the License is distributed on an "AS IS" BASIS,
rem    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
rem    See the License for the specific language governing permissions and
rem    limitations under the License.
rem

rem
rem handle specific scripts; the SCRIPT_NAME is exactly the name of the Karaf
rem script; for example karaf.bat, start.bat, stop.bat, admin.bat, client.bat, ...
rem
rem if "%KARAF_SCRIPT%" == "SCRIPT_NAME" (
rem   Actions go here...
rem )

rem
rem general settings which should be applied for all scripts go here; please keep
rem in mind that it is possible that scripts might be executed more than once, e.g.
rem in example of the start script where the start script is executed first and the
rem karaf script afterwards.
rem

rem
rem The following section shows the possible configuration options for the default 
rem karaf scripts
rem
rem Window name of the windows console
rem SET KARAF_TITLE
rem Minimum memory for the JVM
rem SET JAVA_MIN_MEM
rem Maximum memory for the JVM
rem SET JAVA_MAX_MEM
rem Minimum perm memory for the JVM
rem SET JAVA_PERM_MEM
rem Maximum memory for the JVM
rem SET JAVA_MAX_PERM_MEM
rem Karaf home folder
rem SET KARAF_HOME
rem Karaf data folder
rem SET KARAF_DATA
rem Karaf base folder
rem SET KARAF_BASE
rem Additional available Karaf options
rem SET KARAF_OPTS

if "%PROCESSOR_ARCHITECTURE%"=="x86" goto 32BIT
SET NATIVE_LIB=xipki\native-lib\windows\win_x64
goto OS_END
:32BIT
SET NATIVE_LIB=native-lib\windows\win_x86
:OS_END

SET PATH = %PATH% %NATIVE_LIB%

rem SET KARAF_OPTS=%KARAF_OPTS% -DNSSLIB=point\to\firefox
SET KARAF_OPTS=KARAF_OPTS% -Djava.library.path=%NATIVE_LIB%
rem SET KARAF_OPTS=%KARAF_OPTS% -Dorg.xipki.signservice.timeout=10000
SET KARAF_OPTS=%KARAF_OPTS% -Dorg.xipki.console.passwordui=console
rem SET KARAF_OPTS=%KARAF_OPTS% -Dorg.xipki.console.passwordui=gui
SET KARAF_OPTS=%KARAF_OPTS% -Dhttps.protocols=TLSv1.2,TLSv1.1,TLSv1
SET KARAF_OPTS=%KARAF_OPTS% -Djavax.net.ssl.trustStore=etc\tlskeys\tls-client-truststore.jks
SET KARAF_OPTS=%KARAF_OPTS% -Djavax.net.ssl.trustStorePassword=1234
SET KARAF_OPTS=%KARAF_OPTS% -Djavax.net.ssl.keyStore=etc\tlskeys\tls-client-keystore.jks
SET KARAF_OPTS=%KARAF_OPTS% -Djavax.net.ssl.keyStorePassword=1234
SET KARAF_OPTS=%KARAF_OPTS% -Dsun.net.http.errorstream.enableBuffering=true
SET KARAF_OPTS=%KARAF_OPTS% -Dsun.net.client.defaultConnectTimeout=60000
SET KARAF_OPTS=%KARAF_OPTS% -Dsun.net.client.defaultReadTimeout=60000
rem SET KARAF_OPTS="%KARAF_OPTS% -Djavax.net.debug=all

rem PORTS configuration
SET KARAF_OPTS=%KARAF_OPTS% -Dmy.https.port=9443
SET KARAF_OPTS=%KARAF_OPTS% -Dmy.http.port=9090
SET KARAF_OPTS=%KARAF_OPTS% -Dmy.rmiServerPort=44445
SET KARAF_OPTS=%KARAF_OPTS% -Dmy.rmiRegistryPort=2099
SET KARAF_OPTS=%KARAF_OPTS% -Dmy.ssh.port=9101
SET KARAF_OPTS=%KARAF_OPTS% -Dorg.xipki.console.ignore.regex=\..*
