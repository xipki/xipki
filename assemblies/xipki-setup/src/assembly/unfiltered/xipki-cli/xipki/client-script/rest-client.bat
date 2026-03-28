@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "OCSP=0"
if /I "%~1"=="help" goto usage
if /I "%~1"=="ocsp" set "OCSP=1"

set "CA_URL=https://$[gateway.host]:$[gateway.https.port]/gw/rest/$[ca.alias]"
set "OCSP_URL=http://$[ocsp.host]:$[ocsp.http.port]/ocsp/"
set "DIR=%~dp0"
if "%DIR:~-1%"=="\" set "DIR=%DIR:~0,-1%"
set "OPTS=--insecure --user $[gateway.requestor.user1]:$[gateway.requestor.password1]"

echo CA URL: %CA_URL%
echo OCSP URL: %OCSP_URL%
echo working dir: %DIR%

for /f %%A in ('powershell -NoProfile -Command "(Get-Date).ToString('yyyyMMdd-HHmmss')"') do set "CUR_TIME=%%A"
set "OUT_DIR=%DIR%\..\..\output\rest-%CUR_TIME%"
echo output directory: %OUT_DIR%
mkdir "%OUT_DIR%" >nul 2>&1

echo get CA certificate
curl.exe --insecure --output "%OUT_DIR%\cacert.der" "%CA_URL%/cacert" || exit /b 1
curl.exe --insecure --output "%OUT_DIR%\cacerts.pem" "%CA_URL%/cacerts" || exit /b 1

for /f "tokens=2 delims==" %%A in ('openssl.exe sha1 "%OUT_DIR%\cacert.der"') do for /f "tokens=* delims= " %%B in ("%%A") do set "CA_SHA1FP=%%B"
openssl.exe x509 -inform der -in "%OUT_DIR%\cacert.der" -out "%OUT_DIR%\cacert.pem" || exit /b 1

set "CN=smime-%CUR_TIME%"
echo generate RSA keypair
openssl.exe genrsa -out "%OUT_DIR%\%CN%-key.pem" 2048 || exit /b 1
echo generate CSR
openssl.exe req -new -sha256 -key "%OUT_DIR%\%CN%-key.pem" -outform der -out "%OUT_DIR%\%CN%.csr" -subj "/C=DE/O=myorg/CN=%CN%/emailAddress=info@example.com" || exit /b 1
echo enroll certificate
curl.exe %OPTS% --header "Content-Type: application/pkcs10" --data-binary "@%OUT_DIR%\%CN%.csr" --output "%OUT_DIR%\%CN%.der" "%CA_URL%/enroll-cert?profile=smime" || exit /b 1

set "CN=tls-genkey-%CUR_TIME%"
echo enroll certificate (CA generate keypair)
curl.exe %OPTS% --header "Content-Type: text/plain; encoding=utf-8" --data-ascii "subject=C=DE,O=example,CN=%CN%.example.org" --output "%OUT_DIR%\%CN%.pem" "%CA_URL%/enroll-serverkeygen?profile=tls" || exit /b 1

for /f "tokens=2 delims==" %%A in ('openssl.exe x509 -serial -noout -in "%OUT_DIR%\%CN%.pem"') do set "SERIAL=0X%%A"
set "REKEY_CN=tls-genkey-rekey-%CUR_TIME%"
echo rekey certificate (CA generate keypair)
curl.exe %OPTS% --header "Content-Type: text/plain; encoding=utf-8" --data-ascii "subject=C=DE,O=example,CN=%REKEY_CN%.example.org" --output "%OUT_DIR%\%REKEY_CN%.pem" "%CA_URL%/rekey-serverkeygen?ca-sha1=%CA_SHA1FP%&oldcert-serial=%SERIAL%" || exit /b 1

set "CN=tls-%CUR_TIME%"
echo generate RSA keypair
openssl.exe genrsa -out "%OUT_DIR%\%CN%-key.pem" 2048 || exit /b 1
echo generate CSR
openssl.exe req -new -sha256 -key "%OUT_DIR%\%CN%-key.pem" -outform der -out "%OUT_DIR%\%CN%.csr" -subj "/C=DE/O=myorg/CN=%CN%.example.org" || exit /b 1
echo enroll certificate
curl.exe %OPTS% --header "Content-Type: application/pkcs10" --data-binary "@%OUT_DIR%\%CN%.csr" --output "%OUT_DIR%\%CN%.der" "%CA_URL%/enroll-cert?profile=tls" || exit /b 1

for /f "tokens=2 delims==" %%A in ('openssl.exe x509 -inform der -serial -noout -in "%OUT_DIR%\%CN%.der"') do set "SERIAL=0X%%A"
set "REKEY_CN=tls-rekey-%CUR_TIME%"
echo generate RSA keypair
openssl.exe genrsa -out "%OUT_DIR%\%REKEY_CN%-key.pem" 2048 || exit /b 1
echo generate CSR
openssl.exe req -new -sha256 -key "%OUT_DIR%\%REKEY_CN%-key.pem" -outform der -out "%OUT_DIR%\%REKEY_CN%.csr" -subj "/C=DE/O=myorg/CN=%REKEY_CN%.example.org" || exit /b 1
echo rekey certificate
curl.exe %OPTS% --header "Content-Type: application/pkcs10" --data-binary "@%OUT_DIR%\%REKEY_CN%.csr" --output "%OUT_DIR%\%REKEY_CN%.der" "%CA_URL%/rekey-cert?ca-sha1=%CA_SHA1FP%&oldcert-serial=%SERIAL%" || exit /b 1

openssl.exe x509 -inform der -in "%OUT_DIR%\%CN%.der" -out "%OUT_DIR%\%CN%.pem" || exit /b 1

if "%OCSP%"=="1" (
  echo Current OCSP status
  openssl.exe ocsp -nonce -CAfile "%OUT_DIR%\cacert.pem" -url "%OCSP_URL%" -issuer "%OUT_DIR%\cacert.pem" -cert "%OUT_DIR%\%CN%.pem" || exit /b 1
)

echo suspend certificate
curl.exe %OPTS% "%CA_URL%/revoke-cert?ca-sha1=%CA_SHA1FP%&serial-number=%SERIAL%&reason=certificateHold" || exit /b 1
if "%OCSP%"=="1" (
  echo Current OCSP status
  openssl.exe ocsp -nonce -CAfile "%OUT_DIR%\cacert.pem" -url "%OCSP_URL%" -issuer "%OUT_DIR%\cacert.pem" -cert "%OUT_DIR%\%CN%.pem" || exit /b 1
)

echo unsuspend certificate
curl.exe %OPTS% "%CA_URL%/unsuspend-cert?ca-sha1=%CA_SHA1FP%&serial-number=%SERIAL%" || exit /b 1
if "%OCSP%"=="1" (
  echo Current OCSP status
  openssl.exe ocsp -nonce -CAfile "%OUT_DIR%\cacert.pem" -url "%OCSP_URL%" -issuer "%OUT_DIR%\cacert.pem" -cert "%OUT_DIR%\%CN%.pem" || exit /b 1
)

echo revoke certificate
curl.exe %OPTS% "%CA_URL%/revoke-cert?ca-sha1=%CA_SHA1FP%&serial-number=%SERIAL%&reason=keyCompromise" || exit /b 1
if "%OCSP%"=="1" (
  echo Current OCSP status
  openssl.exe ocsp -nonce -CAfile "%OUT_DIR%\cacert.pem" -url "%OCSP_URL%" -issuer "%OUT_DIR%\cacert.pem" -cert "%OUT_DIR%\%CN%.pem" || exit /b 1
)
exit /b 0

:usage
echo Usage:
echo.
echo %~f0 [help^|ocsp]
echo     help:      Print this usage
echo     ocsp:      Also test the OCSP status
exit /b 0
