@echo off

setlocal

set MYPWD=%cd%
set DIRNAME=%~dp0%
set ARGS=%*

if not exist "%DIRNAME%\..\tmplib" (
    mkdir "%DIRNAME%\..\tmplib"
    cd "%DIRNAME%\..\tmplib"

    if exist "..\..\webapps\ca.war" (
        set WARFILE=..\..\webapps\ca.war
    ) else (
        set WARFILE=..\..\webapps\ocsp.war
    )

    jar xf %WARFILE% WEB-INF\lib
    cd %MYPWD%
)

rem Check/Set up JAVA exec
if "%JAVA_HOME%" == "" (
    set JAVA_EXEC=java
) else (
    set JAVA_EXEC="%JAVA_HOME%"\bin\java
)

set CLASSPATH=%DIRNAME%\..\lib\*;%DIRNAME%\..\..\lib\*;%DIRNAME%\..\tmplib\WEB-INF\lib\*

%JAVA_EXEC% -cp %CLASSPATH% org.xipki.dbtool.InitDbMain %ARGS%

endlocal
