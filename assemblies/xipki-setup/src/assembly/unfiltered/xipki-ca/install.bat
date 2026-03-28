@echo off
setlocal
call "%~dp0..\setup\install-common.bat" -component ca %*
exit /b %ERRORLEVEL%
