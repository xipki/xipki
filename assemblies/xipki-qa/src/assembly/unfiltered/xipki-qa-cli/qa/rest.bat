@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "BASE_URL=https://localhost:$[gateway.https.port]/gw/rest/subcawithcrl"
set "CACERT=output\subcawithcrl1.der"
set "DIR=%~dp0"
if "%DIR:~-1%"=="\" set "DIR=%DIR:~0,-1%"
set "OPTS=--insecure --user $[gateway.requestor.user1]:$[gateway.requestor.password1]"

echo base url: %BASE_URL%
echo working dir: %DIR%

for /f "tokens=2 delims==" %%A in ('openssl.exe sha1 "%DIR%\..\..\%CACERT%"') do for /f "tokens=* delims= " %%B in ("%%A") do set "CA_SHA1FP=%%B"
for /f %%A in ('powershell -NoProfile -Command "[int][double]::Parse((Get-Date -UFormat %%s))"') do set "FILENAME=tls-%%A"

echo generate RSA keypair
openssl.exe genrsa -out "%FILENAME%-key.pem" 2048 || exit /b 1
echo generate CSR
openssl.exe req -new -sha256 -key "%FILENAME%-key.pem" -outform der -out "%FILENAME%.csr" -subj "/CN=%FILENAME%.example.org/O=myorg/C=DE" || exit /b 1

echo get CA certificate
curl.exe %OPTS% --output cacert.der "%BASE_URL%/cacert" || exit /b 1
echo get CA certificate chain
curl.exe %OPTS% --output cacerts.pem "%BASE_URL%/cacerts" || exit /b 1

echo enroll certificate (CA generate keypair)
curl.exe %OPTS% --header "Content-Type: text/plain; charset=utf-8" --data-ascii "subject=CN=%FILENAME%-genkey.example.org,O=myorg,C=DE" --output "%FILENAME%-genkey.pem" -v "%BASE_URL%/enroll-serverkeygen?profile=tls" || exit /b 1

echo enroll certificate
curl.exe %OPTS% --header "Content-Type: application/pkcs10" --data-binary "@%FILENAME%.csr" --output "%FILENAME%.der" -v "%BASE_URL%/enroll-cert?profile=tls" || exit /b 1

for /f "tokens=2 delims==" %%A in ('openssl.exe x509 -inform der -serial -noout -in "%FILENAME%.der"') do set "SERIAL=0x%%A"

echo suspend certificate
curl.exe %OPTS% "%BASE_URL%/revoke-cert?ca-sha1=%CA_SHA1FP%&serial-number=%SERIAL%&reason=certificateHold" || exit /b 1
echo unsuspend certificate
curl.exe %OPTS% "%BASE_URL%/unsuspend-cert?ca-sha1=%CA_SHA1FP%&serial-number=%SERIAL%" || exit /b 1
echo revoke certificate
curl.exe %OPTS% "%BASE_URL%/revoke-cert?ca-sha1=%CA_SHA1FP%&serial-number=%SERIAL%&reason=keyCompromise" || exit /b 1

echo generate new CRL
curl.exe %OPTS% --output new-crl.crl "%BASE_URL%/new-crl" || exit /b 1
echo get current CRL
curl.exe %OPTS% --output crl.crl "%BASE_URL%/crl" || exit /b 1
echo get CRL for given CRL number
for /f "tokens=2 delims==" %%A in ('openssl.exe crl -inform der -in crl.crl -crlnumber -noout') do set "CRLNUMBER=%%A"
curl.exe %OPTS% --output "crl-%CRLNUMBER%.crl" "%BASE_URL%/crl?crl-number=%CRLNUMBER%" || exit /b 1
exit /b 0
