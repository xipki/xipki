@echo off

setlocal

set MYPWD=%cd%
set DIRNAME=%~dp0%
set ARGS=%*

rem Check/Set up JAVA exec
if "%JAVA_HOME%" == "" (
    set JAVA_EXEC=java
) else (
    set JAVA_EXEC="%JAVA_HOME%"\bin\java
)

set CLASSPATH=%DIRNAME%\..\lib\;%DIRNAME%\..\lib\*;%DIRNAME%\..\lib\jdbc\*

%JAVA_EXEC% -cp %CLASSPATH% org.xipki.dbtool.RunScriptMain %ARGS%

:END

endlocal
