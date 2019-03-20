@echo off

setlocal

set MYPWD=%cd%
set DIRNAME=%~dp0%
set ARGS=%*

if not exist "%DIRNAME%..\tmplib" (
    REM check whether the tool jar.exe exists
    where /q jar
    if ERRORLEVEL 1 (
        echo Could not find jar.exe in the PATH. Please either
        echo   1. Add it to the PATH or
        echo   2. Create a new folder %DIRNAME%..\tmplib,
        echo      unzip the webapps\ca.war or webapps\ocsp.war, and then
        echo      copy the unzipped sub-folder WEB-INF to %DIRNAME%..\tmplib.
        goto END
    ) 

    mkdir "%DIRNAME%..\tmplib"
    cd "%DIRNAME%..\tmplib"

    if exist "..\..\webapps\ca.war" (
        jar xf ..\..\webapps\ca.war WEB-INF\lib
    ) else (
        jar xf ..\..\webapps\ocsp.war WEB-INF\lib
    )

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

:END

endlocal
