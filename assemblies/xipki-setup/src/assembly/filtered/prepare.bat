@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "JARS_JDBC_DIR=%SCRIPT_DIR%\setup\jars\jdbc"
set "JARS_BC_DIR=%SCRIPT_DIR%\setup\jars\bouncycastle"
set "JARS_XIPKI_DIR=%SCRIPT_DIR%\setup\jars\xipki"
set "JAVA_EXEC=%JAVA_HOME%\bin\java.exe"
if not exist "%JAVA_EXEC%" set "JAVA_EXEC=java"
set "CLASSPATH=%SCRIPT_DIR%\xipki-mgmt-cli\lib\*"

if not exist "%JARS_JDBC_DIR%\*.jar" call :error no jar file found in "%JARS_JDBC_DIR%"
if not exist "%JARS_BC_DIR%\*.jar" call :error no jar file found in "%JARS_BC_DIR%"

set "BCBRIDGE_GLOB="
if exist "%JARS_BC_DIR%\bcutil-lts8on-*.jar" set "BCBRIDGE_GLOB=%JARS_XIPKI_DIR%\bcbridge-lts*.jar"
if not defined BCBRIDGE_GLOB if exist "%JARS_BC_DIR%\bcutil-fips-*.jar" set "BCBRIDGE_GLOB=%JARS_XIPKI_DIR%\bcbridge-fips*.jar"
if not defined BCBRIDGE_GLOB if exist "%JARS_BC_DIR%\bcutil-jdk8on-*.jar" set "BCBRIDGE_GLOB=%JARS_XIPKI_DIR%\bcbridge-lts*.jar"
if not defined BCBRIDGE_GLOB call :error none of bcutil-{lts8on^|fips^|jdk8on}-*.jar found in "%JARS_BC_DIR%"

cd /d "%SCRIPT_DIR%"
echo change to folder: %CD%

echo Copy xipki-mgmt-cli's folders lib to xipki-cli
xcopy /E /I /Y "%SCRIPT_DIR%\xipki-mgmt-cli\lib\*" "%SCRIPT_DIR%\xipki-cli\lib\" >nul
del /q "%SCRIPT_DIR%\xipki-cli\lib\ca-api*.jar" "%SCRIPT_DIR%\xipki-cli\lib\ca-mgmt*.jar" ^
  "%SCRIPT_DIR%\xipki-cli\lib\certprofile*.jar" "%SCRIPT_DIR%\xipki-cli\lib\ca-mgmt-shell*.jar" ^
  "%SCRIPT_DIR%\xipki-cli\lib\xipki-mgmt-cli*.jar" "%SCRIPT_DIR%\xipki-cli\lib\demo-shell*.jar" 2>nul

echo Prepare tomcat
mkdir "%SCRIPT_DIR%\xipki-ca\tomcat\lib" "%SCRIPT_DIR%\xipki-ocsp\tomcat\lib" "%SCRIPT_DIR%\xipki-gateway\tomcat\lib" >nul 2>&1

echo Copy bcbridge jar
for %%F in ("%BCBRIDGE_GLOB%") do (
  if exist "%%~fF" (
    copy /Y "%%~fF" "%SCRIPT_DIR%\xipki-mgmt-cli\lib\" >nul
    copy /Y "%%~fF" "%SCRIPT_DIR%\xipki-cli\lib\" >nul
    copy /Y "%%~fF" "%SCRIPT_DIR%\xipki-ca\tomcat\lib\" >nul
    copy /Y "%%~fF" "%SCRIPT_DIR%\xipki-ocsp\tomcat\lib\" >nul
    copy /Y "%%~fF" "%SCRIPT_DIR%\xipki-gateway\tomcat\lib\" >nul
  )
)

echo Copy bouncycastle jars
copy /Y "%JARS_BC_DIR%\*.jar" "%SCRIPT_DIR%\xipki-mgmt-cli\lib\" >nul
copy /Y "%JARS_BC_DIR%\*.jar" "%SCRIPT_DIR%\xipki-cli\lib\" >nul
copy /Y "%JARS_BC_DIR%\*.jar" "%SCRIPT_DIR%\xipki-ca\tomcat\lib\" >nul
copy /Y "%JARS_BC_DIR%\*.jar" "%SCRIPT_DIR%\xipki-ocsp\tomcat\lib\" >nul
copy /Y "%JARS_BC_DIR%\*.jar" "%SCRIPT_DIR%\xipki-gateway\tomcat\lib\" >nul

echo Copy JDBC driver jars
copy /Y "%JARS_JDBC_DIR%\*.jar" "%SCRIPT_DIR%\xipki-mgmt-cli\lib\" >nul
copy /Y "%JARS_JDBC_DIR%\*.jar" "%SCRIPT_DIR%\xipki-ca\tomcat\lib\" >nul
copy /Y "%JARS_JDBC_DIR%\*.jar" "%SCRIPT_DIR%\xipki-ocsp\tomcat\lib\" >nul
copy /Y "%JARS_JDBC_DIR%\*.jar" "%SCRIPT_DIR%\xipki-gateway\tomcat\lib\" >nul

echo Copy %SCRIPT_DIR%\war-common\ to war files (ca.war, ocsp.war, gw.war)
if exist "%SCRIPT_DIR%\war-common" rd /s /q "%SCRIPT_DIR%\war-common"
mkdir "%SCRIPT_DIR%\war-common\WEB-INF\lib" >nul 2>&1
copy /Y "%SCRIPT_DIR%\xipki-mgmt-cli\lib\HikariCP-${hikaricp.version}.jar" "%SCRIPT_DIR%\war-common\WEB-INF\lib\" >nul
copy /Y "%SCRIPT_DIR%\xipki-mgmt-cli\lib\codec-${project.version}.jar" "%SCRIPT_DIR%\war-common\WEB-INF\lib\" >nul
copy /Y "%SCRIPT_DIR%\xipki-mgmt-cli\lib\pkcs11-${project.version}.jar" "%SCRIPT_DIR%\war-common\WEB-INF\lib\" >nul
copy /Y "%SCRIPT_DIR%\xipki-mgmt-cli\lib\security-${project.version}.jar" "%SCRIPT_DIR%\war-common\WEB-INF\lib\" >nul
copy /Y "%SCRIPT_DIR%\xipki-mgmt-cli\lib\util-${project.version}.jar" "%SCRIPT_DIR%\war-common\WEB-INF\lib\" >nul
copy /Y "%SCRIPT_DIR%\xipki-mgmt-cli\lib\util-extra-${project.version}.jar" "%SCRIPT_DIR%\war-common\WEB-INF\lib\" >nul
copy /Y "%SCRIPT_DIR%\xipki-mgmt-cli\lib\xihsm-${project.version}.jar" "%SCRIPT_DIR%\war-common\WEB-INF\lib\" >nul
copy /Y "%SCRIPT_DIR%\xipki-mgmt-cli\lib\slf4j-api-*.jar" "%SCRIPT_DIR%\war-common\WEB-INF\lib\" >nul
copy /Y "%SCRIPT_DIR%\xipki-mgmt-cli\lib\slf4j-jdk14-*.jar" "%SCRIPT_DIR%\war-common\WEB-INF\lib\" >nul

pushd "%SCRIPT_DIR%\war-common"
powershell -NoProfile -Command "Compress-Archive -Path * -DestinationPath '%SCRIPT_DIR%\xipki-ocsp\tomcat\webapps\ocsp.war' -Force"
powershell -NoProfile -Command "Compress-Archive -Path * -DestinationPath '%SCRIPT_DIR%\xipki-gateway\tomcat\webapps\gw.war' -Force"
copy /Y "%SCRIPT_DIR%\xipki-mgmt-cli\lib\ca-api-*.jar" "%SCRIPT_DIR%\war-common\WEB-INF\lib\" >nul
copy /Y "%SCRIPT_DIR%\xipki-mgmt-cli\lib\certprofile-*.jar" "%SCRIPT_DIR%\war-common\WEB-INF\lib\" >nul
powershell -NoProfile -Command "Compress-Archive -Path * -DestinationPath '%SCRIPT_DIR%\xipki-ca\tomcat\webapps\ca.war' -Force"
popd
rd /s /q "%SCRIPT_DIR%\war-common"

"%JAVA_EXEC%" -cp "%CLASSPATH%" org.xipki.util.extra.misc.BatchReplace "%SCRIPT_DIR%\setup\conf.json"
if errorlevel 1 exit /b 1

set "KC_DIR=%SCRIPT_DIR%\setup\keycerts"
"%JAVA_EXEC%" -cp "%CLASSPATH%" org.xipki.security.util.GenerateCerts "%SCRIPT_DIR%\setup\keycerts.json" "%KC_DIR%"
if errorlevel 1 exit /b 1

set "KS_DIR=%KC_DIR%\certstore"

echo Copying generated keys to the XiPKI component xipki-ca
mkdir "%SCRIPT_DIR%\xipki-ca\tomcat\xipki\keycerts" >nul 2>&1
copy /Y "%KC_DIR%\ca-server\*" "%SCRIPT_DIR%\xipki-ca\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ca-mgmt-client\*-cert.pem" "%SCRIPT_DIR%\xipki-ca\tomcat\xipki\keycerts\" >nul
copy /Y "%KS_DIR%\ca-client-certstore.p12" "%SCRIPT_DIR%\xipki-ca\tomcat\xipki\keycerts\" >nul

echo Copying generated keys to the XiPKI component xipki-gateway
mkdir "%SCRIPT_DIR%\xipki-gateway\tomcat\xipki\keycerts" >nul 2>&1
copy /Y "%KC_DIR%\gateway-server\*" "%SCRIPT_DIR%\xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ra-sdk-client\*" "%SCRIPT_DIR%\xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\cmp-client\*-cert.pem" "%SCRIPT_DIR%\xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\est-client\*-cert.pem" "%SCRIPT_DIR%\xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\rest-client\*-cert.pem" "%SCRIPT_DIR%\xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ca-server\ca-server-cert.pem" "%SCRIPT_DIR%\xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KS_DIR%\gateway-client-ca-certstore.p12" "%SCRIPT_DIR%\xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\dh-pop\dh-pop.p12" "%SCRIPT_DIR%\xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\secretkeys\kem-pop.jceks" "%SCRIPT_DIR%\xipki-gateway\tomcat\xipki\keycerts\" >nul

echo Copying generated keys to the XiPKI component xipki-cli
mkdir "%SCRIPT_DIR%\xipki-cli\xipki\keycerts" >nul 2>&1
copy /Y "%KC_DIR%\cmp-client\*" "%SCRIPT_DIR%\xipki-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\est-client\*" "%SCRIPT_DIR%\xipki-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\rest-client\*" "%SCRIPT_DIR%\xipki-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\gateway-server\gateway-server-cert.pem" "%SCRIPT_DIR%\xipki-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\dh-pop\dh-pop-certs.pem" "%SCRIPT_DIR%\xipki-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\secretkeys\kem-pop.jceks" "%SCRIPT_DIR%\xipki-cli\xipki\keycerts\" >nul

echo Copying generated keys to the XiPKI component xipki-mgmt-cli
mkdir "%SCRIPT_DIR%\xipki-mgmt-cli\xipki\keycerts" >nul 2>&1
copy /Y "%KC_DIR%\cmp-client\*" "%SCRIPT_DIR%\xipki-mgmt-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\est-client\*" "%SCRIPT_DIR%\xipki-mgmt-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\rest-client\*" "%SCRIPT_DIR%\xipki-mgmt-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\gateway-server\gateway-server-cert.pem" "%SCRIPT_DIR%\xipki-mgmt-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\dh-pop\dh-pop-certs.pem" "%SCRIPT_DIR%\xipki-mgmt-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\secretkeys\kem-pop.jceks" "%SCRIPT_DIR%\xipki-mgmt-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ra-sdk-client\ra-sdk-client-cert.pem" "%SCRIPT_DIR%\xipki-mgmt-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ca-mgmt-client\*.p12" "%SCRIPT_DIR%\xipki-mgmt-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ca-mgmt-client\*-cert.pem" "%SCRIPT_DIR%\xipki-mgmt-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ca-server\ca-server-cert.pem" "%SCRIPT_DIR%\xipki-mgmt-cli\xipki\keycerts\" >nul
exit /b 0

:error
echo ERROR: %* 1>&2
exit /b 1
