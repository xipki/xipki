# XiPKI Gateway EST API

## Scope and Sources
This document is derived from:
- `gateway/src/main/java/org/xipki/ca/gateway/est/EstResponder.java`
- `gateway/src/main/java/org/xipki/ca/gateway/est/EstHttpServlet.java`
- `gateway/src/main/java/org/xipki/ca/gateway/est/EstProtocolConf.java`
- `gateway/src/main/java/org/xipki/ca/gateway/GatewayHttpFilter.java`
- `servlets/gateway-servlet/src/main/java/org/xipki/ca/gateway/servlet/GatewayServletFilter.java`
- `servlets/gateway-servlet/src/main/webapp/WEB-INF/web.xml`

## Base Path and Routing
- Servlet filter is mapped to `/*`.
- EST requests are routed when servlet path starts with `/est/`.
- Internal EST path is servlet path without `/est` prefix.

Supported EST path forms:
- `/est/{command}`
  - Uses alias `default` from EST `caProfiles` config.
- `/est/{alias}/{command}`
  - Alias resolves to configured `ca` + `certprofile`.
- `/est/{ca}/{profile}/{command}`
  - Direct CA/profile form.

Notes:
- `ca`, `profile`, and `command` are normalized to lowercase in the 3-token path form.
- Unknown alias/path/command returns `404`.

## HTTP Methods
- `GET` and `POST` are accepted by servlet.
- Other methods return `405 Method Not Allowed`.
- Enrollment/re-enrollment/keygen commands require request body (`application/pkcs10`), so `POST` is the practical method.

## Authentication and Authorization
Public (no requestor authentication):
- `cacerts`
- `ucacerts`
- `ucacert`
- `ucrl`
- `csrattrs`
- `fullcmc` (known command but currently returns `404`)

Authenticated commands:
- `simpleenroll`
- `usimpleenroll`
- `simplereenroll`
- `usimplereenroll`
- `serverkeygen`
- `userverkeygen`

Supported authentication mechanisms:
- `Authorization: Basic base64(user:password)`
- TLS client certificate

Additional authorization checks:
- Requestor must have permission `ENROLL_CERT`.
- Requestor must be permitted for the resolved `{ca, profile}`.

## Commands

### `cacerts`
- Returns CA certificates as CMS certs-only payload.
- Response:
  - Content-Type: `application/pkcs7-mime`
  - Encoding flag: base64

### `ucacerts` (XiPKI extension)
- Returns CA certificates in PEM.
- Response:
  - Content-Type: `application/x-pem-file`

### `ucacert` (XiPKI extension)
- Returns CA certificate as raw certificate bytes.
- Response:
  - Content-Type: `application/pkix-cert`
  - Encoding flag: base64

### `ucrl` (XiPKI extension)
- Returns current CRL as raw bytes.
- Response:
  - Content-Type: `application/pkix-crl`
  - Encoding flag: base64

### `csrattrs`
- Returns CSR attributes based on CA/profile metadata (`profileInfo`).
- Includes extension request OIDs and supported key algorithm hints.
- Response:
  - Content-Type: `application/csrattrs`
  - Encoding flag: base64

### `fullcmc`
- Recognized command, currently not implemented.
- Response:
  - `404 Not Found`

### `simpleenroll`
- Enroll certificate using PKCS#10 CSR.
- Request:
  - Content-Type: `application/pkcs10`
  - Body: PKCS#10 CSR
  - POP verification: required
- Response:
  - Content-Type: `application/pkcs7-mime; smime-type=certs-only`
  - Encoding flag: base64

### `usimpleenroll` (XiPKI extension)
- Same enrollment flow as `simpleenroll`, raw certificate response.
- Request:
  - Content-Type: `application/pkcs10`
  - Body: PKCS#10 CSR
  - POP verification: required
- Response:
  - Content-Type: `application/pkix-cert`
  - Encoding flag: base64

### `simplereenroll`
- Re-enroll certificate using PKCS#10 CSR.
- Old certificate is identified by subject + SAN from CSR (`OldCertInfo.BySubject`).
- Supports CMC `id-cmc-changeSubjectName` attribute to request subject/SAN change.
- Request:
  - Content-Type: `application/pkcs10`
  - Body: PKCS#10 CSR
  - POP verification: required
- Response:
  - Content-Type: `application/pkcs7-mime; smime-type=certs-only`
  - Encoding flag: base64

### `usimplereenroll` (XiPKI extension)
- Same reenrollment flow as `simplereenroll`, raw certificate response.
- Request:
  - Content-Type: `application/pkcs10`
  - Body: PKCS#10 CSR
  - POP verification: required
- Response:
  - Content-Type: `application/pkix-cert`
  - Encoding flag: base64

### `serverkeygen`
- CA/server generates key pair and certificate.
- Request:
  - Content-Type: `application/pkcs10`
  - Body: PKCS#10 CSR (used for subject/extensions)
  - POP verification: skipped for this command
- Response:
  - Content-Type: `multipart/mixed; boundary=<generated>`
  - Part 1: private key (`application/pkcs8`, base64)
  - Part 2: certificate (`application/pkcs7-mime; smime-type=certs-only`, base64)

### `userverkeygen` (XiPKI extension)
- CA/server generates key pair and certificate.
- Request:
  - Content-Type: `application/pkcs10`
  - Body: PKCS#10 CSR
  - POP verification: performed by current implementation
- Response:
  - Content-Type: `application/x-pem-file`
  - Body: PEM `PRIVATE KEY` + PEM `CERTIFICATE`

## Request/Response Content Types
Request content types used:
- `application/pkcs10`

Response content types used:
- `application/pkcs7-mime`
- `application/pkcs7-mime; smime-type=certs-only`
- `multipart/mixed; boundary=...`
- `application/pkix-cert`
- `application/pkix-crl`
- `application/pkcs8` (multipart part)
- `application/x-pem-file`
- `application/csrattrs`

## Error Behavior
Primary HTTP status mappings:
- `400 Bad Request`:
  - `ALREADY_ISSUED`, `BAD_REQUEST`, `INVALID_EXTENSION`, `UNKNOWN_CERT_PROFILE`,
  - `CERT_UNREVOKED`, `BAD_CERT_TEMPLATE`, `UNKNOWN_CERT`, `BAD_POP`
- `401 Unauthorized`:
  - invalid/missing auth, `NOT_PERMITTED`, `UNAUTHORIZED`
- `404 Not Found`:
  - invalid path/alias/command, `PATH_NOT_FOUND`, unsupported `fullcmc`
- `409 Conflict`:
  - `CERT_REVOKED`
- `415 Unsupported Media Type`:
  - request content type is not `application/pkcs10` for authenticated enrollment flows
- `500 Internal Server Error`:
  - internal/system/database/CRL errors
- `503 Service Unavailable`:
  - `SYSTEM_UNAVAILABLE`

## Configuration Notes
From `EstProtocolConf`:
- EST protocol config includes:
  - `authenticator` (required)
  - optional `caProfiles`
  - inherited `logReqResp`, `pop`, `sdkClient`
