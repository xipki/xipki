@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "CA_URL=https://$[gateway.host]:$[gateway.https.port]/.well-known/est/$[ca.alias]/tls"
set "DIR=%~dp0"
if "%DIR:~-1%"=="\" set "DIR=%DIR:~0,-1%"
set "OPTS=--insecure --user $[gateway.requestor.user1]:$[gateway.requestor.password1]"

echo CA URL: %CA_URL%
echo working dir: %DIR%

for /f %%A in ('powershell -NoProfile -Command "(Get-Date).ToString('yyyyMMdd-HHmmss')"') do set "CUR_TIME=%%A"
set "OUT_DIR=%DIR%\..\..\output\est-%CUR_TIME%"
echo output directory: %OUT_DIR%
mkdir "%OUT_DIR%" >nul 2>&1

echo #################################################################
echo #             Manage certificate via EST interface              #
echo #################################################################

set "CMD=csrattrs"
set "FILE=%OUT_DIR%\%CMD%"
echo -----%CMD%-----
curl.exe --insecure --output "%FILE%.csrattrs.b64" "%CA_URL%/%CMD%" || exit /b 1
openssl.exe enc -d -base64 -in "%FILE%.csrattrs.b64" -out "%FILE%.csrattrs" || exit /b 1

set "CMD=cacerts"
set "FILE=%OUT_DIR%\%CMD%"
echo -----%CMD%-----
curl.exe --insecure --output "%FILE%.p7m" "%CA_URL%/%CMD%" || exit /b 1

set "CMD=simpleenroll"
set "FILE=%OUT_DIR%\%CMD%"
set "CN=enroll-%CUR_TIME%"
echo -----%CMD%-----
call :generate_key_and_csr "%FILE%" "/C=DE/O=myorg/CN=%CN%.example.com"
call :pkcs10_request "%FILE%" "%CA_URL%/%CMD%" "%FILE%.p7m"

set "CMD=simplereenroll"
set "FILE=%OUT_DIR%\%CMD%"
echo -----%CMD%-----
copy /Y "%DIR%\template.openssl-san.cnf" "%OUT_DIR%\openssl-san.cnf" >nul
>>"%OUT_DIR%\openssl-san.cnf" echo DNS.1=%CN%.example.com
openssl.exe genrsa -out "%FILE%-key.pem" 2048 || exit /b 1
openssl.exe req -new -sha256 -key "%FILE%-key.pem" -outform der -out "%FILE%.csr" -subj "/C=DE/O=myorg/CN=%CN%.example.com" -config "%OUT_DIR%\openssl-san.cnf" || exit /b 1
call :pkcs10_request "%FILE%" "%CA_URL%/%CMD%" "%FILE%.p7m"

set "CMD=serverkeygen"
set "FILE=%OUT_DIR%\%CMD%"
set "CN=%CMD%-%CUR_TIME%"
echo -----%CMD%-----
echo generate dummy RSA keypair (will not be used by CA)
openssl.exe genrsa -out "%FILE%-dummy.pem" 2048 || exit /b 1
echo generate dummy CSR
openssl.exe req -new -sha256 -key "%FILE%-dummy.pem" -outform der -out "%FILE%.csr" -subj "/C=DE/O=myorg/CN=%CN%.example.com" || exit /b 1
call :pkcs10_request "%FILE%" "%CA_URL%/%CMD%" "%FILE%.p7m"

echo #################################################################
echo #      Manage certificate via EST interface (XiPKI extension)   #
echo #################################################################

set "CMD=ucacerts"
set "FILE=%OUT_DIR%\%CMD%"
echo -----%CMD%-----
curl.exe --insecure --output "%FILE%.pem" "%CA_URL%/%CMD%" || exit /b 1

set "CMD=ucacert"
set "FILE=%OUT_DIR%\%CMD%"
echo -----%CMD%-----
curl.exe --insecure --output "%FILE%.crt.b64" "%CA_URL%/%CMD%" || exit /b 1
openssl.exe enc -d -base64 -in "%FILE%.crt.b64" -out "%FILE%.crt" || exit /b 1

set "CMD=ucrl"
set "FILE=%OUT_DIR%\%CMD%"
echo -----%CMD%-----
curl.exe --insecure --output "%FILE%.crl.b64" "%CA_URL%/%CMD%" || exit /b 1
openssl.exe enc -d -base64 -in "%FILE%.crl.b64" -out "%FILE%.crl" || exit /b 1

set "CMD=usimpleenroll"
set "FILE=%OUT_DIR%\%CMD%"
set "CN=enroll-%CUR_TIME%"
echo -----%CMD%-----
call :generate_key_and_csr "%FILE%" "/C=DE/O=myorg/CN=%CN%.example.com"
call :pkcs10_request "%FILE%" "%CA_URL%/%CMD%" "%FILE%.crt.b64"
openssl.exe enc -d -base64 -in "%FILE%.crt.b64" -out "%FILE%.crt" || exit /b 1

set "CMD=usimplereenroll"
set "FILE=%OUT_DIR%\%CMD%"
echo -----%CMD%-----
copy /Y "%DIR%\template.openssl-san.cnf" "%OUT_DIR%\openssl-san.cnf" >nul
>>"%OUT_DIR%\openssl-san.cnf" echo DNS.1=%CN%.example.com
openssl.exe genrsa -out "%FILE%-key.pem" 2048 || exit /b 1
openssl.exe req -new -sha256 -key "%FILE%-key.pem" -outform der -out "%FILE%.csr" -subj "/C=DE/O=myorg/CN=%CN%.example.com" -config "%OUT_DIR%\openssl-san.cnf" || exit /b 1
call :pkcs10_request "%FILE%" "%CA_URL%/%CMD%" "%FILE%.crt.b64"
openssl.exe enc -d -base64 -in "%FILE%.crt.b64" -out "%FILE%.crt" || exit /b 1

set "CMD=userverkeygen"
set "FILE=%OUT_DIR%\%CMD%"
set "CN=%CMD%-%CUR_TIME%"
echo -----%CMD%-----
echo generate dummy RSA keypair (will not be used by CA)
openssl.exe genrsa -out "%FILE%-dummy.pem" 2048 || exit /b 1
echo generate dummy CSR
openssl.exe req -new -sha256 -key "%FILE%-dummy.pem" -outform der -out "%FILE%.csr" -subj "/C=DE/O=myorg/CN=%CN%.example.com" || exit /b 1
call :pkcs10_request "%FILE%" "%CA_URL%/%CMD%" "%FILE%.pem"
echo extract certificate
openssl.exe x509 -in "%FILE%.pem" -out "%FILE%-cert.pem" || exit /b 1
echo extract private key
openssl.exe pkey -in "%FILE%.pem" -out "%FILE%-key.pem" || exit /b 1
exit /b 0

:generate_key_and_csr
echo generate RSA keypair
openssl.exe genrsa -out "%~1-key.pem" 2048 || exit /b 1
echo generate CSR
openssl.exe req -new -sha256 -key "%~1-key.pem" -outform der -out "%~1.csr" -subj "%~2" || exit /b 1
exit /b 0

:pkcs10_request
echo enroll certificate
openssl.exe enc -base64 -in "%~1.csr" -out "%~1.csr.b64" || exit /b 1
curl.exe %OPTS% --header "Content-Type: application/pkcs10" --header "Content-Transfer-Encoding: base64" --data-binary "@%~1.csr.b64" --output "%~3" "%~2" || exit /b 1
exit /b 0
