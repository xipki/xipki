@echo off

setlocal

set DIRNAME=%~dp0%
set ARGS=%*

rem Check/Set up JAVA exec
if "%JAVA_HOME%" == "" (
    set JAVA_EXEC=java
) else (
    set JAVA_EXEC="%JAVA_HOME%"\bin\java
)

%JAVA_EXEC% -cp "%DIRNAME%\..;%DIRNAME%\..\lib\*;%DIRNAME%\..\..\lib\*" org.xipki.dbtool.InitDbMain %ARGS%

endlocal
