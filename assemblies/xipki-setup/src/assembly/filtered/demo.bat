@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "DATABASE_TYPE=h2"
set "DEMO_DIR=%USERPROFILE%\demo_xipki"
set "TOMCAT_MAJOR_VERSION=10"
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "LIB_DIR=%SCRIPT_DIR%\xipki-mgmt-cli\lib"
set "CLASSPATH=%LIB_DIR%\*"
set "JAVA_EXEC=%JAVA_HOME%\bin\java.exe"
if not exist "%JAVA_EXEC%" set "JAVA_EXEC=java"

"%JAVA_EXEC%" -cp "%CLASSPATH%" -Ddemo.dir="%DEMO_DIR%" org.xipki.util.extra.misc.BatchReplace "%SCRIPT_DIR%\setup\demo-conf.json"
if errorlevel 1 exit /b 1

call "%SCRIPT_DIR%\prepare.bat"
if errorlevel 1 exit /b 1

if not exist "%DEMO_DIR%" mkdir "%DEMO_DIR%"

call :find_tomcat_version "%DEMO_DIR%" %TOMCAT_MAJOR_VERSION%
if errorlevel 1 exit /b 1
echo Tomcat !TOMCAT_VERSION!

set "TOMCAT_DIR_NAME=apache-tomcat-!TOMCAT_VERSION!"
set "TOMCAT_BINARY=!TOMCAT_DIR_NAME!.tar.gz"

echo working dir: %SCRIPT_DIR%
cd /d "%DEMO_DIR%"
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

if exist "ca-tomcat" rd /s /q "ca-tomcat"
if exist "ocsp-tomcat" rd /s /q "ocsp-tomcat"
if exist "gateway-tomcat" rd /s /q "gateway-tomcat"
if exist "!TOMCAT_DIR_NAME!" rd /s /q "!TOMCAT_DIR_NAME!"
tar -xf "!TOMCAT_BINARY!"
if errorlevel 1 exit /b 1
if exist "!TOMCAT_DIR_NAME!\webapps" rd /s /q "!TOMCAT_DIR_NAME!\webapps"
mkdir "!TOMCAT_DIR_NAME!\webapps" >nul 2>&1
xcopy /E /I /Y "!TOMCAT_DIR_NAME!" "ca-tomcat" >nul
xcopy /E /I /Y "!TOMCAT_DIR_NAME!" "ocsp-tomcat" >nul
move /Y "!TOMCAT_DIR_NAME!" "gateway-tomcat" >nul

cd /d "%SCRIPT_DIR%"
echo change to folder: %CD%

call "%SCRIPT_DIR%\xipki-ca\install.bat" -t "%DEMO_DIR%\ca-tomcat"
if errorlevel 1 exit /b 1
call "%SCRIPT_DIR%\xipki-ocsp\install.bat" -t "%DEMO_DIR%\ocsp-tomcat"
if errorlevel 1 exit /b 1
call "%SCRIPT_DIR%\xipki-gateway\install.bat" -t "%DEMO_DIR%\gateway-tomcat"
if errorlevel 1 exit /b 1

set "DBCONF_DIR=%SCRIPT_DIR%\xipki-ca\tomcat\xipki\etc\ca\database\%DATABASE_TYPE%"
if /I "%DATABASE_TYPE%"=="h2" if exist "%USERPROFILE%\.xipki\db\h2" rd /s /q "%USERPROFILE%\.xipki\db\h2"

copy /Y "%DBCONF_DIR%\ca-db.properties" "%DEMO_DIR%\ca-tomcat\xipki\etc\ca\database\" >nul
copy /Y "%DBCONF_DIR%\caconf-db.properties" "%DEMO_DIR%\ca-tomcat\xipki\etc\ca\database\" >nul
copy /Y "%DBCONF_DIR%\ocsp-db.properties" "%DEMO_DIR%\ca-tomcat\xipki\etc\ca\database\" >nul
copy /Y "%DBCONF_DIR%\ca-db.properties" "%DEMO_DIR%\ocsp-tomcat\xipki\etc\ocsp\database\" >nul
copy /Y "%DBCONF_DIR%\ocsp-db.properties" "%DEMO_DIR%\ocsp-tomcat\xipki\etc\ocsp\database\" >nul

cd /d "%SCRIPT_DIR%\xipki-mgmt-cli"
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
if exist "%DEMO_DIR%\%~1\bin\shutdown.bat" call "%DEMO_DIR%\%~1\bin\shutdown.bat" >nul 2>&1
exit /b 0
