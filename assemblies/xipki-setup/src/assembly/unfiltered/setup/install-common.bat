@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "COMPONENT="
set "TOMCAT_DIR="

:parse_args
if "%~1"=="" goto args_done
if /I "%~1"=="-component" (
  set "COMPONENT=%~2"
  shift
  shift
  goto parse_args
)
if /I "%~1"=="-t" (
  set "TOMCAT_DIR=%~f2"
  shift
  shift
  goto parse_args
)
goto usage

:args_done
if not defined COMPONENT goto usage
if not defined TOMCAT_DIR goto usage
if not exist "%TOMCAT_DIR%\bin\version.bat" (
  echo ERROR: Tomcat version script not found under "%TOMCAT_DIR%\bin". 1>&2
  exit /b 1
)

if /I "%COMPONENT%"=="ca" (
  call :require_no_conflicting_wars ocsp "OCSP responder is running in %TOMCAT_DIR%, please use other tomcat instance."
  if errorlevel 1 exit /b 1
  call :require_no_conflicting_wars gw "Protocol gateway is running in %TOMCAT_DIR%, please use other tomcat instance."
  if errorlevel 1 exit /b 1
) else if /I "%COMPONENT%"=="gateway" (
  call :require_no_conflicting_wars ca "CA is running in %TOMCAT_DIR%, please use other tomcat instance."
  if errorlevel 1 exit /b 1
  call :require_no_conflicting_wars ocsp "OCSP responder is running in %TOMCAT_DIR%, please use other tomcat instance."
  if errorlevel 1 exit /b 1
) else if /I "%COMPONENT%"=="ocsp" (
  call :require_no_conflicting_wars ca "CA is running in %TOMCAT_DIR%, please use other tomcat instance."
  if errorlevel 1 exit /b 1
  call :require_no_conflicting_wars gw "Protocol gateway is running in %TOMCAT_DIR%, please use other tomcat instance."
  if errorlevel 1 exit /b 1
) else (
  echo ERROR: unsupported component "%COMPONENT%". 1>&2
  exit /b 1
)

call :resolve_tomcat_major
if errorlevel 1 exit /b 1

if %TOMCAT_MAJOR% LSS 10 (
  echo Unsupported tomcat major version %TOMCAT_MAJOR%
  exit /b 1
)

call :create_backup_layout
call :backup_common_tomcat_files
if errorlevel 1 exit /b 1

if /I "%COMPONENT%"=="ca" (
  call :backup_war ca
  if errorlevel 1 exit /b 1
  if exist "%TOMCAT_DIR%\webapps\ca" rd /s /q "%TOMCAT_DIR%\webapps\ca"
  call :copy_tomcat_tree
  exit /b %ERRORLEVEL%
)

if /I "%COMPONENT%"=="gateway" (
  call :copy_tomcat_tree
  if errorlevel 1 exit /b 1
  xcopy /E /I /Y "%SCRIPT_DIR%xipki-gateway\tomcat\conf" "%TOMCAT_DIR%\conf" >nul
  for %%W in (gw acme cmp est rest scep) do (
    call :backup_war %%W
    if exist "%TOMCAT_DIR%\webapps\%%W" rd /s /q "%TOMCAT_DIR%\webapps\%%W"
  )
  copy /Y "%SCRIPT_DIR%xipki-gateway\tomcat\webapps\gw.war" "%TOMCAT_DIR%\webapps\" >nul
  exit /b %ERRORLEVEL%
)

call :backup_war ocsp
if errorlevel 1 exit /b 1
if exist "%TOMCAT_DIR%\webapps\ocsp" rd /s /q "%TOMCAT_DIR%\webapps\ocsp"
call :copy_tomcat_tree
exit /b %ERRORLEVEL%

:usage
echo.
echo Usage: %~nx0 -component ^<ca^|gateway^|ocsp^> -t ^<dir of destination tomcat^>
exit /b 1

:require_no_conflicting_wars
set "WAR_NAME=%~1"
set "WAR_MESSAGE=%~2"
if exist "%TOMCAT_DIR%\webapps\%WAR_NAME%.war" (
  echo %WAR_MESSAGE%
  exit /b 1
)
exit /b 0

:resolve_tomcat_major
set "TMP_FILE=%TEMP%\xipki-tomcat-version-%RANDOM%%RANDOM%.txt"
call "%TOMCAT_DIR%\bin\version.bat" > "%TMP_FILE%" 2>&1
if errorlevel 1 (
  type "%TMP_FILE%"
  del /q "%TMP_FILE%" >nul 2>&1
  exit /b 1
)
for /f "tokens=2 delims=:" %%A in ('findstr /C:"Server number:" "%TMP_FILE%"') do set "VERSION_LINE=%%A"
del /q "%TMP_FILE%" >nul 2>&1
if not defined VERSION_LINE (
  echo ERROR: could not determine Tomcat version. 1>&2
  exit /b 1
)
for /f "tokens=* delims= " %%A in ("%VERSION_LINE%") do set "VERSION_LINE=%%A"
echo Tomcat %VERSION_LINE%
for /f "tokens=1 delims=." %%A in ("%VERSION_LINE%") do set "TOMCAT_MAJOR=%%A"
exit /b 0

:create_backup_layout
for /f %%A in ('powershell -NoProfile -Command "(Get-Date).ToString('yyyyMMddTHHmmss')"') do set "STAMP=%%A"
set "BACKUP_DIR=%TOMCAT_DIR%\backup-%STAMP%"
mkdir "%BACKUP_DIR%\bin" "%BACKUP_DIR%\lib" "%BACKUP_DIR%\conf" "%BACKUP_DIR%\webapps" >nul 2>&1
echo backup dir: %BACKUP_DIR%
exit /b 0

:backup_common_tomcat_files
if exist "%TOMCAT_DIR%\xipki" xcopy /E /I /Y "%TOMCAT_DIR%\xipki" "%BACKUP_DIR%\xipki" >nul
if exist "%TOMCAT_DIR%\conf\catalina.properties" move /Y "%TOMCAT_DIR%\conf\catalina.properties" "%BACKUP_DIR%\conf\" >nul
if exist "%TOMCAT_DIR%\conf\server.xml" move /Y "%TOMCAT_DIR%\conf\server.xml" "%BACKUP_DIR%\conf\" >nul

call :move_glob "%BACKUP_DIR%\bin" "%TOMCAT_DIR%\bin\setenv.*"
call :move_glob "%BACKUP_DIR%\lib" "%TOMCAT_DIR%\lib\password-*.jar"
call :move_glob "%BACKUP_DIR%\lib" "%TOMCAT_DIR%\lib\passwords-*.jar"
call :move_glob "%BACKUP_DIR%\lib" "%TOMCAT_DIR%\lib\xipki-tomcat-password-*.jar"
call :move_glob "%BACKUP_DIR%\lib" "%TOMCAT_DIR%\lib\*pkcs11*.jar"
call :move_glob "%BACKUP_DIR%\lib" "%TOMCAT_DIR%\lib\bc*-jdk*.jar"
call :move_glob "%BACKUP_DIR%\lib" "%TOMCAT_DIR%\lib\bc*-lts*.jar"
call :move_glob "%BACKUP_DIR%\lib" "%TOMCAT_DIR%\lib\h2-*.jar"
call :move_glob "%BACKUP_DIR%\lib" "%TOMCAT_DIR%\lib\mariadb-java-*.jar"
exit /b 0

:move_glob
for %%F in (%~2) do (
  if exist "%%~fF" move /Y "%%~fF" "%~1\" >nul
)
exit /b 0

:backup_war
if exist "%TOMCAT_DIR%\webapps\%~1.war" move /Y "%TOMCAT_DIR%\webapps\%~1.war" "%BACKUP_DIR%\webapps\" >nul
exit /b 0

:copy_tomcat_tree
xcopy /E /I /Y "%SCRIPT_DIR%%COMPONENT%\tomcat\*" "%TOMCAT_DIR%\" >nul
exit /b %ERRORLEVEL%
