@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "DIST_DIR=%%~fI"
set "LIB_DIR=%DIST_DIR%\lib"

if not exist "%DIST_DIR%\logs\" mkdir "%DIST_DIR%\logs"
if not exist "%LIB_DIR%\" (
  >&2 echo library directory not found: "%LIB_DIR%"
  exit /b 1
)

set "JAVA_OPTS="
if exist "%LIB_DIR%\logging.properties" (
  set "JAVA_OPTS=-Djava.util.logging.config.file=%LIB_DIR%\logging.properties"
)

if /I "%~1"=="debug" (
  set "JAVA_OPTS=%JAVA_OPTS% -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005"
  shift /1
)

cd /d "%DIST_DIR%"
java %JAVA_OPTS% -Dorg.xipki.shell.home="%DIST_DIR%" -cp "%LIB_DIR%\*" org.xipki.shell.dist.XipkiQaCliMain %*
