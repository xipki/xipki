@echo off
setlocal
call "%~dp0..\setup\install-common.bat" -component gateway %*
exit /b %ERRORLEVEL%
