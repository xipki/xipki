[![GitHub release](https://img.shields.io/github/release/xipki/xipki.svg)](https://github.com/xipki/xipki/releases)
[![License](https://img.shields.io/badge/license-Apache%202-4EB1BA.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![Github forks](https://img.shields.io/github/forks/xipki/xipki.svg)](https://github.com/xipki/xipki/network)
[![Github stars](https://img.shields.io/github/stars/xipki/xipki.svg)](https://github.com/xipki/xipki/stargazers)


# XiPKI
XiPKI (e**X**tensible s**I**mple **P**ublic **K**ey **I**nfrastructure)
is a high-performance, open source PKI (CA, RA, OCSP) designed for critical infrastructure. 
Built with minimal dependencies and a compact codebase of ~120,000 lines, it offers native support
for post-quantum algorithms (ML-DSA, ML-KEM, composite), HSM integration via PKCS#11, 
SM2/SM3 for Chinese national standards, and fast OCSP at scale. 
Bouncy Castle can be switched between LTS and FIPS variants to meet different compliance 
requirements. 

The project author actively contributes to IETF standardization, including co-authoring the 
C509 specification (CBOR-encoded X.509 certificates) and its test vectors in the COSE Working 
Group.

## License
* The Apache Software License, Version 2.0

## Support
Just [create new issue](https://github.com/xipki/xipki/issues).

For bug-report please upload the test data and log files, describe the version of XiPKI, OS and
JRE/JDK, and the steps to reproduce the bug.

## Get Started

### Binaries
The binaries `xipki-setup-<version>-bclts.tar.gz` (using bouncycastle LTS libraries) and 
`xipki-setup-<version>-bcfips.tar.gz` (using bouncycastle FIPS libraries) can be retrieved using 
one of the following methods
  - Download the binary from https://github.com/xipki/xipki/releases
  - Build it from source code
    - Get a copy of project code, e.g.
      ```sh
      git clone https://github.com/xipki/xipki
      ```

    - Build the project
      * In folder `xipki`
        ```sh
        ./install.sh
        ```
 
      Then you will find the binaries in the folder `assemblies/xipki-setup/target/`

### Just Try The Demo

1. Unpack `xipki-setup-<version>-bclts.tar.gz` or `xipki-setup-<version>-fips.tar.gz`,
2. In the unpacked folder `xipki-setup-<version>`:  
   Call `./demo.sh` to prepare the systems and start the karaf console.
   
   Once the systems have been prepared, you need only to start the karaf 
   console by calling `./xipki-setup-<version>/xipki-mgmt-cli/bin/karaf`.
3. In the karaf console:  
   Call `source demo/demo-single.script` to print the usage, and 
   then follow the usage, e.g.
   `source demo/demo-single.script DB PKCS12 RSA2048`
4. (Optional) Point the browser to http://localhost:8282 to open the H2 database
   console. You can view the database content using username `root` and 
   password `123456` with following JDBC URLs:
   - Database CA configuration: `jdbc:h2:~/.xipki/db/h2/caconf`
   - Database CA data: `jdbc:h2:~/.xipki/db/h2/ca`
   - Database OCSP data: `jdbc:h2:~/.xipki/db/h2/ocsp`

The generated keys, certificate requests (CSR) and certificates are in
the folder `xipki-mgmt-cli/output`. The CA, OCSP, gateway instances are in
the folders `~/xipki_demo/ca-tomcat`, `~/xipki_demo/ocsp-tomcat`, and 
`~/xipki_demo/gateway-tomcat` respectively.

### Install and Setup

Unpack `xipki-setup-<version>-lts.tar.gz` or `xipki-setup-<version>-fips.tar.gz` and follow 
the `xipki-setup-<version>/INSTALL.md`.

## Features

### Supported Platform
* OS
  * Linux, Windows, MacOS
* JRE / JDK
  * Java 11+.
* Database
  * DB2, MariaDB, MySQL, Oracle, PostgreSQL, H2, HSQLDB
* Hardware
  * Any available hardware 
* Servlet Container
  * Tomcat 10, 11
* HSM Devices
  - [AWS CloudHSM](https://aws.amazon.com/cloudhsm)
  - [Nitrokey HSM 2](https://www.nitrokey.com/#comparison) / [Smartcard HSM EA+](http://www.smartcard-hsm.com/features.html#usbstick)
  - nCipher [Connect](https://www.ncipher.com/products/general-purpose-hsms/nshield-connect) / [Solo](https://www.ncipher.com/products/general-purpose-hsms/nshield-solo)
  - [Sansec HSM](https://en.sansec.com.cn)
  - [Softhsm v1 & v2](https://www.opendnssec.org/download/packages/)
  - [TASS HSM](https://www.tass.com.cn/portal/list/index/id/15.html)
  - Thales [LUNA](https://cpl.thalesgroup.com/encryption/hardware-security-modules/general-purpose-hsms) / [ProtectServer](https://cpl.thalesgroup.com/encryption/hardware-security-modules/protectserver-hsms)
  - [Utimaco Se](https://hsm.utimaco.com/products-hardware-security-modules/general-purpose-hsm/)
  - And shall also work on other HSMs with PKCS#11 support.

### CA Protocol Gateway
  - EST (RFC 7030)
  - SCEP (RFC 8894)
  - CMP (RFC 4210, RFC 4211, RFC 9045, RFC 9480, RFC 9810, RFC 9811)
  - ACME (RFC 8555, RFC 8737)
    - Challenge types: dns-01, http-01, tls-apln-01
  - RESTful API (XiPKI own API)

### CA (Certification Authority)
  - X.509 Certificate v3 (RFC 5280)
  - X.509 CRL v2 (RFC 5280)
  - EdDSA Certificates (RFC 8410, RFC 8032)
  - SHAKE Certificates (RFC 8692)
  - Diffie-Hellman Proof-of-Possession Algorithms (RFC 6955)
  - EN 319 411 and 319 412 (eIDAS)
  - Direct and indirect CRL
  - FullCRL and DeltaCRL
  - API to specify customized certificate profiles
  - Support of JSON-based certificate profile
  - API to specify customized publisher, e.g. for LDAP and OCSP responder
  - Support of publisher for OCSP responder
  - Public key types of certificates: RSA, EC, Ed25519, Ed448, SM2, X25519, X448,
    MLDSA / ML-DSA / CRYSTALS‑Dilithium (ML-DSA-44, ML-DSA-65, ML-DSA-87),
    MLKEM / ML-KEM / CRYSTALS‑Kyber (ML-KEM-512, ML-KEM-768, ML-KEM-1024),
    composite MLDSA (in draft-ietf-lamps-pq-composite-sigs),
    composite MLKEM (in draft-ietf-lamps-pq-composite-kem)
  - Signature algorithms of certificates
    - MLDSA / ML-DSA (ML-DSA-44, ML-DSA-65, ML-DSA-87),
    - Composite MLDSA (in draft-ietf-lamps-pq-composite-sigs),
    - ECDSA with hash algorithms: SHA-1, SHA-2, SHA-3, and SHAKE
    - Ed25519, Ed448
    - RSA PKCS1v1.5 with hash algorithms: SHA-1, SHA-2, and SHA-3
    - RSA PSS with hash algorithms: SHA-1, SHA-2, and SHA-3, and SHAKE
    - SM3withSM2
  - Native support of X.509 extensions (other extensions can be supported by 
    configuring it as blob)
    - RFC 3739
      - BiometricInfo
      - QCStatements (also in eIDAS standard EN 319 412)
    - RFC 4262
      - SMIMECapabilities
    - RFC 5280
      - AuthorityInformationAccess, AuthorityKeyIdentifier
      - BasicConstraints
      - CertificatePolicies, CRLDistributionPoints
      - ExtendedKeyUsage
      - FreshestCRL
      - InhibitAnyPolicy, IssuerAltName
      - KeyUsage
      - NameConstraints
      - PolicyConstrains, PolicyMappings, PrivateKeyUsagePeriod
      - SubjectAltName, SubjectInfoAccess, SubjectKeyIdentifier
    - RFC 6960
      - OcspNoCheck
    - RFC 6962
      - CT Pre-certificate SCTs
    - RfC 7633
      - TLSFeature
    - Car Connectivity Consortium
      - ExtensionSchema
  - Management of multiple CAs in one software instance
    - Support of database cluster
    - Multiple software instances (all can be in active mode) for the same CA
    - Native support of management of CA via embedded OSGi commands
    - API to manage CA. This allows one to implement proprietary CLI, e.g.
      Website, to manage CA.
    - Database tool (export and import CA database) simplifies the switch of
      databases, upgrade of XiPKi and switch from other CA system to XiPKI CA
    - All configuration of CA except those of databases is saved in database

### OCSP Responder
  - OCSP Responder (RFC 2560 and RFC 6960)
  - Lightweight OCSP Profile for High-Volume Environments (RFC 5019)
  - Configurable Length of Nonce (RFC 8954)
  - Support of Common PKI 2.0
  - Management of multiple certificate status sources
  - Support of certificate status sources
    - Database of XiPKI CA
    - OCSP database published by XiPKI CA
    - CRL and DeltaCRL
    - Database of EJBCA
  - API to support proprietary certificate sources
  - Support of both unsigned and signed OCSP requests
  - Multiple software instances (all can be in active mode) for the same OCSP
    signer and certificate status sources.
  - Database tool (export and import OCSP database) simplifies the switch of
    databases, upgrade of XiPKi and switch from other OCSP system to XiPKI OCSP.
  - High performance
  - Support of health check

### Mgmt CLI (Management Client)
  - Configuring CA
  - Generating keypairs of RSA, EC, Ed25519, Ed448, X25519, X448, ML-DSA, ML-KEM, 
    composite-MLDSA and composite-MLKEM in token
  - Deleting keypairs and certificates from token
  - Updating certificates in token
  - Generating CSR (PKCS#10 request)
  - Exporting certificate from token

### CLI (CA/OCSP Client)
  - Client to enroll, revoke, and unrevoke (unsuspend) certificates, to download CRLs
  - Client to send OCSP request
  - Updating certificates in token
  - Generating CSR (PKCS#10 request)
  - Exporting certificate from token

### TODO
  - Write a simple and strictly trusted RequestorAuthenticator used default.
    Remove the DummyRequestorAuthenticator.