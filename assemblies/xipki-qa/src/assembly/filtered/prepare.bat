@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "BOUNCYCASTLE_MODE_CLIENT=LTS"
set "BOUNCYCASTLE_MODE_SERVER=LTS"
set "TBDIR=%USERPROFILE%\test\xipki"
set "DATABASE_TYPE=h2"
set "TOMCAT_MAJOR_VERSION=10"
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "JAVA_EXEC=%JAVA_HOME%\bin\java.exe"
if not exist "%JAVA_EXEC%" set "JAVA_EXEC=java"

if %TOMCAT_MAJOR_VERSION% LSS 10 (
  echo Unsupported tomcat major version %TOMCAT_MAJOR_VERSION%
  exit /b 1
)

if not exist "%TBDIR%" mkdir "%TBDIR%"
call :find_tomcat_version "%TBDIR%" %TOMCAT_MAJOR_VERSION%
if errorlevel 1 exit /b 1
echo Tomcat !TOMCAT_VERSION!

set "TOMCAT_DIR_NAME=apache-tomcat-!TOMCAT_VERSION!"
set "TOMCAT_BINARY=!TOMCAT_DIR_NAME!.tar.gz"

echo working dir: %SCRIPT_DIR%
if exist "%TBDIR%\jdk-tomcat" (
  set "TOMCAT_JAVA_HOME=--env JAVA_HOME=%TBDIR%\jdk-tomcat"
) else (
  set "TOMCAT_JAVA_HOME="
)

cd /d "%TBDIR%"
echo change to folder: %CD%

if exist "!TOMCAT_BINARY!" (
  echo Use local !TOMCAT_BINARY!
) else (
  echo Download !TOMCAT_BINARY!
  curl.exe -L -o "!TOMCAT_BINARY!" "https://dlcdn.apache.org/tomcat/tomcat-%TOMCAT_MAJOR_VERSION%/v!TOMCAT_VERSION!/bin/!TOMCAT_BINARY!"
  if errorlevel 1 exit /b 1
)

call :shutdown_tomcat ca-tomcat
call :shutdown_tomcat ocsp-tomcat
call :shutdown_tomcat gateway-tomcat
call :shutdown_tomcat dummy-tomcat

for %%D in (ca-tomcat ocsp-tomcat gateway-tomcat dummy-tomcat "!TOMCAT_DIR_NAME!") do if exist "%%~D" rd /s /q "%%~D"
tar -xf "!TOMCAT_BINARY!"
if errorlevel 1 exit /b 1
if exist "!TOMCAT_DIR_NAME!\webapps" rd /s /q "!TOMCAT_DIR_NAME!\webapps"
mkdir "!TOMCAT_DIR_NAME!\webapps" >nul 2>&1
xcopy /E /I /Y "!TOMCAT_DIR_NAME!" "ca-tomcat" >nul
xcopy /E /I /Y "!TOMCAT_DIR_NAME!" "ocsp-tomcat" >nul
xcopy /E /I /Y "!TOMCAT_DIR_NAME!" "gateway-tomcat" >nul
move /Y "!TOMCAT_DIR_NAME!" "dummy-tomcat" >nul

cd /d "%SCRIPT_DIR%"
echo change to folder: %CD%

del /q "xipki-qa-cli\lib\bc*-lts*.jar" "xipki-qa-cli\lib\bc*-fips-*.jar" 2>nul
mkdir "xipki-ca\tomcat\lib" "xipki-ocsp\tomcat\lib" "xipki-gateway\tomcat\lib" "xipki-dummy\tomcat\lib" >nul 2>&1
del /q "xipki-ca\tomcat\lib\bc*-lts*.jar" "xipki-ca\tomcat\lib\bc*-fips-*.jar" 2>nul
del /q "xipki-ocsp\tomcat\lib\bc*-lts*.jar" "xipki-ocsp\tomcat\lib\bc*-fips-*.jar" 2>nul
del /q "xipki-gateway\tomcat\lib\bc*-lts*.jar" "xipki-gateway\tomcat\lib\bc*-fips-*.jar" 2>nul
del /q "xipki-dummy\tomcat\lib\bc*-lts*.jar" "xipki-dummy\tomcat\lib\bc*-fips-*.jar" 2>nul

echo Copy JDBC jars
set "JARS_DIR=setup\jars"
copy /Y "%JARS_DIR%\jdbc\*.jar" "xipki-qa-cli\lib\" >nul
copy /Y "%JARS_DIR%\jdbc\*.jar" "xipki-ca\tomcat\lib\" >nul
copy /Y "%JARS_DIR%\jdbc\*.jar" "xipki-ocsp\tomcat\lib\" >nul
copy /Y "%JARS_DIR%\jdbc\*.jar" "xipki-gateway\tomcat\lib\" >nul
copy /Y "%JARS_DIR%\jdbc\*.jar" "xipki-dummy\tomcat\lib\" >nul

if /I "%BOUNCYCASTLE_MODE_CLIENT%"=="LTS" (
  echo Client: copy BouncyCastle LTS jars
  copy /Y "%JARS_DIR%\bclts\*" "xipki-qa-cli\lib\" >nul
  copy /Y "%JARS_DIR%\xipki\bcbridge-lts*" "xipki-qa-cli\lib\" >nul
) else (
  echo Client: copy BouncyCastle FIPS jars to xipki-qa-cli
  copy /Y "%JARS_DIR%\bcfips\*" "xipki-qa-cli\lib\" >nul
  copy /Y "%JARS_DIR%\xipki\bcbridge-fips*" "xipki-qa-cli\lib\" >nul
)

if /I "%BOUNCYCASTLE_MODE_SERVER%"=="LTS" (
  echo Server: copy BouncyCastle LTS jars to xipki-ca
  copy /Y "%JARS_DIR%\bclts\*" "xipki-ca\tomcat\lib\" >nul
  copy /Y "%JARS_DIR%\xipki\bcbridge-lts*" "xipki-ca\tomcat\lib\" >nul
) else (
  echo Server: copy BouncyCastle FIPS jars to xipki-ca
  copy /Y "%JARS_DIR%\bcfips\*" "xipki-ca\tomcat\lib\" >nul
  copy /Y "%JARS_DIR%\xipki\bcbridge-fips*" "xipki-ca\tomcat\lib\" >nul
)

echo Copy JDBC ^& BouncyCastle jars to xipki-ocsp, xipki-gateway, and xipki-dummy
xcopy /E /I /Y "xipki-ca\tomcat\lib\*" "xipki-ocsp\tomcat\lib\" >nul
xcopy /E /I /Y "xipki-ca\tomcat\lib\*" "xipki-gateway\tomcat\lib\" >nul
xcopy /E /I /Y "xipki-ca\tomcat\lib\*" "xipki-dummy\tomcat\lib\" >nul

if exist "war-common" rd /s /q "war-common"
mkdir "war-common\WEB-INF\lib" >nul 2>&1
copy /Y "xipki-qa-cli\lib\HikariCP-${hikaricp.version}.jar" "war-common\WEB-INF\lib\" >nul
copy /Y "xipki-qa-cli\lib\codec-${project.version}.jar" "war-common\WEB-INF\lib\" >nul
copy /Y "xipki-qa-cli\lib\pkcs11-${project.version}.jar" "war-common\WEB-INF\lib\" >nul
copy /Y "xipki-qa-cli\lib\security-${project.version}.jar" "war-common\WEB-INF\lib\" >nul
copy /Y "xipki-qa-cli\lib\util-${project.version}.jar" "war-common\WEB-INF\lib\" >nul
copy /Y "xipki-qa-cli\lib\util-extra-${project.version}.jar" "war-common\WEB-INF\lib\" >nul
copy /Y "xipki-qa-cli\lib\xihsm-${project.version}.jar" "war-common\WEB-INF\lib\" >nul
copy /Y "xipki-qa-cli\lib\slf4j-api-*.jar" "war-common\WEB-INF\lib\" >nul
copy /Y "xipki-qa-cli\lib\slf4j-jdk14-*.jar" "war-common\WEB-INF\lib\" >nul

set "CLASSPATH=xipki-qa-cli\lib\*"
"%JAVA_EXEC%" -cp "%CLASSPATH%" -Ddatabase.type="%DATABASE_TYPE%" -Dtest.basedir="%TBDIR%" -Dtomcat.java.home="%TOMCAT_JAVA_HOME%" org.xipki.util.extra.misc.BatchReplace "setup\conf.json"
if errorlevel 1 exit /b 1
"%JAVA_EXEC%" -cp "%CLASSPATH%" org.xipki.security.util.GenerateCerts "setup\keycerts.json" "setup\keycerts"
if errorlevel 1 exit /b 1

pushd "war-common"
powershell -NoProfile -Command "Compress-Archive -Path * -DestinationPath '%SCRIPT_DIR%\xipki-ocsp\tomcat\webapps\ocsp.war' -Force"
powershell -NoProfile -Command "Compress-Archive -Path * -DestinationPath '%SCRIPT_DIR%\xipki-gateway\tomcat\webapps\gw.war' -Force"
powershell -NoProfile -Command "Compress-Archive -Path * -DestinationPath '%SCRIPT_DIR%\xipki-dummy\tomcat\webapps\dummy.war' -Force"
copy /Y "%SCRIPT_DIR%\xipki-qa-cli\lib\ca-api-*.jar" "%SCRIPT_DIR%\war-common\WEB-INF\lib\" >nul
copy /Y "%SCRIPT_DIR%\xipki-qa-cli\lib\certprofile-*.jar" "%SCRIPT_DIR%\war-common\WEB-INF\lib\" >nul
powershell -NoProfile -Command "Compress-Archive -Path * -DestinationPath '%SCRIPT_DIR%\xipki-ca\tomcat\webapps\ca.war' -Force"
popd
rd /s /q "war-common"

set "KC_DIR=%SCRIPT_DIR%\setup\keycerts"
set "KS_DIR=%KC_DIR%\certstore"

mkdir "xipki-ca\tomcat\xipki\keycerts" >nul 2>&1
copy /Y "%KC_DIR%\ca-server\*" "xipki-ca\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ca-mgmt-client\ca-mgmt-client-cert.pem" "xipki-ca\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\dummy-server\dummy-server-cert.pem" "xipki-ca\tomcat\xipki\keycerts\" >nul
copy /Y "%KS_DIR%\ca-client-certstore.p12" "xipki-ca\tomcat\xipki\keycerts\" >nul

mkdir "xipki-ocsp\tomcat\xipki\keycerts" >nul 2>&1

mkdir "xipki-gateway\tomcat\xipki\keycerts" >nul 2>&1
copy /Y "%KC_DIR%\gateway-server\*" "xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ra-sdk-client\*" "xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ca-server\ca-server-cert.pem" "xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KS_DIR%\gateway-client-ca-certstore.p12" "xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\dh-pop\dh-pop.p12" "xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\cmp-client\cmp-client-cert.pem" "xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\est-client\est-client-cert.pem" "xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\rest-client\rest-client-cert.pem" "xipki-gateway\tomcat\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\secretkeys\kem-pop.jceks" "xipki-gateway\tomcat\xipki\keycerts\" >nul

mkdir "xipki-dummy\tomcat\xipki\keycerts" >nul 2>&1
copy /Y "%KC_DIR%\dummy-server\*" "xipki-dummy\tomcat\xipki\keycerts\" >nul

mkdir "xipki-qa-cli\xipki\keycerts" >nul 2>&1
copy /Y "%KC_DIR%\ca-mgmt-client\*" "xipki-qa-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\cmp-client\*" "xipki-qa-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\est-client\*" "xipki-qa-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\rest-client\*" "xipki-qa-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ocsp-client\*" "xipki-qa-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ca-server\*" "xipki-qa-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\gateway-server\*" "xipki-qa-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\dh-pop\dh-pop-certs.pem" "xipki-qa-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ra-sdk-client\ra-sdk-client.p12" "xipki-qa-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\ra-sdk-client\ra-sdk-client-cert.pem" "xipki-qa-cli\xipki\keycerts\" >nul
copy /Y "%KC_DIR%\secretkeys\kem-pop.jceks" "xipki-qa-cli\xipki\keycerts\" >nul

set "PKI_UI_DIR=%TBDIR%\pki-ui"
mkdir "%PKI_UI_DIR%\keycerts" >nul 2>&1
copy /Y "%KC_DIR%\ca-server\ca-server-cert.pem" "%PKI_UI_DIR%\keycerts\" >nul
copy /Y "%KC_DIR%\ca-mgmt-client\ca-mgmt-client.p12" "%PKI_UI_DIR%\keycerts\" >nul

for %%T in ("%TBDIR%\ca-tomcat" "%TBDIR%\ocsp-tomcat" "%TBDIR%\gateway-tomcat" "%TBDIR%\dummy-tomcat") do (
  echo tomcat dir: %%~fT
  if exist "%%~fT\webapps" rd /s /q "%%~fT\webapps"
  if exist "%%~fT\xipki" rd /s /q "%%~fT\xipki"
  if exist "%%~fT\logs" del /q "%%~fT\logs\*" 2>nul
  del /q "%%~fT\lib\bc*.jar" "%%~fT\lib\mariadb-java-client-*.jar" "%%~fT\lib\postgresql-*.jar" "%%~fT\lib\h2-*.jar" 2>nul
)

xcopy /E /I /Y "xipki-ca\tomcat\*" "%TBDIR%\ca-tomcat\" >nul
xcopy /E /I /Y "xipki-ocsp\tomcat\*" "%TBDIR%\ocsp-tomcat\" >nul
xcopy /E /I /Y "xipki-gateway\tomcat\*" "%TBDIR%\gateway-tomcat\" >nul
xcopy /E /I /Y "xipki-dummy\tomcat\*" "%TBDIR%\dummy-tomcat\" >nul

if exist "%USERPROFILE%\.xipki\db\h2" rd /s /q "%USERPROFILE%\.xipki\db\h2"

copy /Y "%SCRIPT_DIR%\xipki-ca\tomcat\xipki\etc\ca\database\%DATABASE_TYPE%\*" "%TBDIR%\ca-tomcat\xipki\etc\ca\database\" >nul
mkdir "%TBDIR%\dummy-tomcat\xipki\etc\ca\database" >nul 2>&1
copy /Y "%SCRIPT_DIR%\xipki-ca\tomcat\xipki\etc\ca\database\%DATABASE_TYPE%\ca-db.properties" "%TBDIR%\dummy-tomcat\xipki\etc\ca\database\" >nul
copy /Y "%SCRIPT_DIR%\xipki-ocsp\tomcat\xipki\etc\ocsp\database\%DATABASE_TYPE%\*" "%TBDIR%\ocsp-tomcat\xipki\etc\ocsp\database\" >nul
copy /Y "%TBDIR%\ocsp-tomcat\xipki\etc\ocsp\database\h2\ocsp-cache-db.properties" "%TBDIR%\ocsp-tomcat\xipki\etc\ocsp\database\" >nul
copy /Y "%SCRIPT_DIR%\xipki-gateway\tomcat\xipki\etc\acme\database\%DATABASE_TYPE%\*" "%TBDIR%\gateway-tomcat\xipki\etc\acme\database\" >nul

cd /d "%SCRIPT_DIR%\xipki-qa-cli"
echo change to folder: %CD%
call bin\xipki.bat
exit /b %ERRORLEVEL%

:find_tomcat_version
set "SEARCH_DIR=%~1"
set "MAJOR=%~2"
set "TOMCAT_VERSION="
for /f "delims=" %%F in ('dir /b /od "%SEARCH_DIR%\apache-tomcat-%MAJOR%*.tar.gz" 2^>nul') do set "LAST_TAR=%%F"
if defined LAST_TAR (
  set "FILE_NAME=!LAST_TAR!"
  for /f "tokens=3 delims=-" %%A in ("!FILE_NAME!") do set "VERSION_PART=%%A"
  set "TOMCAT_VERSION=!VERSION_PART:.tar.gz=!"
  set "LAST_TAR="
  exit /b 0
)
for /f %%A in ('powershell -NoProfile -Command "(Invoke-WebRequest -UseBasicParsing 'https://dlcdn.apache.org/tomcat/tomcat-%MAJOR%/').Links.href | Where-Object { $_ -like 'v*' } | ForEach-Object { $_.TrimEnd('/') } | Select-Object -Last 1 | ForEach-Object { $_.Substring(1) }"') do set "TOMCAT_VERSION=%%A"
if not defined TOMCAT_VERSION exit /b 1
exit /b 0

:shutdown_tomcat
if exist "%TBDIR%\%~1\bin\shutdown.bat" call "%TBDIR%\%~1\bin\shutdown.bat" >nul 2>&1
exit /b 0
