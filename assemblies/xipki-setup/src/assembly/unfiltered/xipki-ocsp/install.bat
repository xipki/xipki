@echo off
setlocal
call "%~dp0..\setup\install-common.bat" -component ocsp %*
exit /b %ERRORLEVEL%
