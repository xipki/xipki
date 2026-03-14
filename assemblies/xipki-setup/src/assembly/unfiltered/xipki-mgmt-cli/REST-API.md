# XiPKI Gateway REST API

## Scope and Sources
This document is derived from:
- `gateway/src/main/java/org/xipki/ca/gateway/rest/RestResponder.java`
- `gateway/src/main/java/org/xipki/ca/gateway/rest/RestHttpServlet.java`
- `gateway/src/main/java/org/xipki/ca/gateway/rest/RestProtocolConf.java`
- `gateway/src/main/java/org/xipki/ca/gateway/GatewayHttpFilter.java`
- `servlets/gateway-servlet/src/main/java/org/xipki/ca/gateway/servlet/GatewayServletFilter.java`
- `servlets/gateway-servlet/src/main/webapp/WEB-INF/web.xml`

## Base Path and Routing
- Servlet filter is mapped to `/*`.
- REST requests are routed when servlet path starts with `/rest/`.
- Internal REST path is the servlet path without the `/rest` prefix.

Supported URI forms:
- `/rest/{command}`
  - Uses alias `default` from REST `caProfiles` config.
- `/rest/{aliasOrCa}/{command}`
  - If `{aliasOrCa}` is a configured alias, it resolves to mapped CA and certificate profile.
  - Otherwise `{aliasOrCa}` is treated as CA name, and `profile` can be supplied as a query parameter.

## HTTP Methods
- `GET` and `POST` are supported.
- Other methods return `405 Method Not Allowed`.

## Authentication and Authorization
Public commands (no requestor authentication required):
- `cacert`
- `cacerts`
- `crl`
- `dh-pop-certs`

Other commands require requestor authentication via one of:
- `Authorization: Basic base64(user:password)`
- TLS client certificate

Authorization checks are command-dependent and enforced via requestor permissions and allowed certificate profiles.

## Common Response Headers
Successful responses:
- `X-xipki-pkistatus: accepted`

Failure responses:
- `X-xipki-pkistatus: rejection`
- `X-xipki-fail-info: <failInfo>` (when available)

## Path and Query Parameters
Common query parameters used by commands:
- `profile`
- `not-before`
- `not-after`
- `ca-sha1`
- `serial-number`
- `oldcert-serial`
- `reason`
- `invalidity-time`
- `crl-number`

Time format for `not-before`, `not-after`, `invalidity-time`:
- Parsed by `DateUtil.parseUtcTimeyyyyMMddhhmmss`.

## REST Commands

### 1) `cacert`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/cacert`
- Methods: `GET`, `POST`
- Auth: Public
- Response: CA certificate
  - Content-Type: `application/pkix-cert`

### 2) `cacerts`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/cacerts`
- Methods: `GET`, `POST`
- Auth: Public
- Response: CA cert chain in PEM
  - Content-Type: `application/x-pem-file`

### 3) `crl`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/crl`
- Methods: `GET`, `POST`
- Auth: Public
- Query:
  - Optional `crl-number`
- Response: CRL bytes
  - Content-Type: `application/pkix-crl`

### 4) `dh-pop-certs`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/dh-pop-certs`
- Methods: `GET`, `POST`
- Auth: Public
- Response: DH POP certs in PEM
  - Content-Type: `application/x-pem-file`

### 5) `enroll-cert`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/enroll-cert`
- Methods: `POST` (request body required)
- Auth: Required
- Required profile: yes (via alias mapping or `profile` query)
- Request:
  - Content-Type: `application/pkcs10`
  - Body: PKCS#10 CSR
- Query:
  - Optional `not-before`, `not-after`
- Response:
  - Issued certificate
  - Content-Type: `application/pkix-cert`

### 6) `rekey-cert`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/rekey-cert`
- Methods: `POST`
- Auth: Required
- Required profile: no hard fail at dispatch, but profile checks apply when present
- Request:
  - Content-Type: `application/pkcs10`
  - Body: PKCS#10 CSR
- Query:
  - Required `oldcert-serial`
  - Required `ca-sha1`
  - Optional `not-before`, `not-after`
- Response:
  - Reissued certificate
  - Content-Type: `application/pkix-cert`

### 7) `enroll-serverkeygen`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/enroll-serverkeygen`
- Methods: `POST`
- Auth: Required
- Required profile: yes
- Request:
  - Content-Type either:
    - `text/plain` with Java properties (`subject` key), or
    - `application/pkcs10` (subject/extensions transport only; POP not used)
- Query:
  - Optional `not-before`, `not-after`
- Response:
  - PEM bundle containing generated private key and certificate
  - Content-Type: `application/x-pem-file`

### 8) `rekey-serverkeygen`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/rekey-serverkeygen`
- Methods: `POST`
- Auth: Required
- Request:
  - Content-Type either:
    - `text/plain` (subject optional for rekey), or
    - `application/pkcs10`
- Query:
  - Required `oldcert-serial`
  - Required `ca-sha1`
  - Optional `not-before`, `not-after`
- Response:
  - PEM bundle containing generated private key and certificate
  - Content-Type: `application/x-pem-file`

### 9) `enroll-cert-twin`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/enroll-cert-twin`
- Methods: `POST`
- Auth: Required
- Required profile: yes
- Request:
  - Content-Type: `application/pkcs10`
  - Body: PKCS#10 CSR
- Query:
  - Optional `not-before`, `not-after`
- Response:
  - PEM bundle with two certificates (and key blocks when applicable)
  - Content-Type: `application/x-pem-file`
- Notes:
  - Encryption profile is derived as `{profile}-enc`.

### 10) `enroll-serverkeygen-twin`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/enroll-serverkeygen-twin`
- Methods: `POST`
- Auth: Required
- Required profile: yes
- Request:
  - Content-Type `text/plain` or `application/pkcs10` (same semantics as `enroll-serverkeygen`)
- Query:
  - Optional `not-before`, `not-after`
- Response:
  - PEM bundle with generated private keys and twin certificates
  - Content-Type: `application/x-pem-file`

### 11) `enroll-cross-cert`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/enroll-cross-cert`
- Methods: `POST`
- Auth: Required
- Required profile: yes
- Request:
  - Content-Type: `application/x-pem-file`
  - Body: PEM containing exactly one `CERTIFICATE REQUEST` and one `CERTIFICATE`
- Query:
  - Optional `not-before`, `not-after`
- Behavior:
  - Verifies CSR POP.
  - Verifies CSR key matches target certificate.
  - Caps requested `not-after` to target certificate end date.
- Response:
  - Cross certificate
  - Content-Type: `application/pkix-cert`

### 12) `revoke-cert`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/revoke-cert`
- Methods: `GET`, `POST`
- Auth: Required
- Query:
  - Required `ca-sha1`
  - Required `serial-number`
  - Optional `reason` (default `UNSPECIFIED`, `REMOVE_FROM_CRL` rejected)
  - Optional `invalidity-time`
- Response:
  - Empty body on success

### 13) `unsuspend-cert`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/unsuspend-cert`
- Methods: `GET`, `POST`
- Auth: Required
- Query:
  - Required `ca-sha1`
  - Required `serial-number`
- Response:
  - Empty body on success

### 14) `kem-encapkey`
- Path: `/rest/{command}` or `/rest/{aliasOrCa}/kem-encapkey`
- Methods: `POST`
- Auth: Required
- Request:
  - Body: ASN.1 `SubjectPublicKeyInfo` bytes
- Response:
  - Encoded KEM encapsulation key bytes
  - Content-Type: `application/octet-stream`

## Error Behavior
Status and fail-info are mapped from internal errors. Key mappings:
- `400 Bad Request`: `badRequest`, `badCertTemplate`, `badCertId`, `badPOP`
- `401 Unauthorized`: `notAuthorized`
- `404 Not Found`: missing/invalid path or command
- `409 Conflict`: `certRevoked`
- `415 Unsupported Media Type`: unsupported request content type
- `500 Internal Server Error`: `systemFailure`
- `503 Service Unavailable`: `systemUnavail`

## Configuration Notes
From `RestProtocolConf`:
- REST protocol config includes:
  - `authenticator` (required)
  - optional `caProfiles`
  - inherited `logReqResp`, `pop`, `sdkClient`
