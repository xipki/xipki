[![GitHub release](https://img.shields.io/github/release/xipki/xipki.svg)](https://github.com/xipki/xipki/releases)
[![License](https://img.shields.io/badge/license-Apache%202-4EB1BA.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![Github forks](https://img.shields.io/github/forks/xipki/xipki.svg)](https://github.com/xipki/xipki/network)
[![Github stars](https://img.shields.io/github/stars/xipki/xipki.svg)](https://github.com/xipki/xipki/stargazers)


# XiPKI
XiPKI (e**X**tensible s**I**mple **P**ublic **K**ey **I**nfrastructure) is
a highly scalable and high-performance open source PKI (CA and OCSP responder).

## License
* The Apache Software License, Version 2.0

## Support
Just [create new issue](https://github.com/xipki/xipki/issues).

For bug-report please upload the test data and log files, describe the version of XiPKI, OS and
JRE/JDK, and the steps to reproduce the bug.

## Get Started

### Binaries
The binary `xipki-setup-<version>.zip` can be retrieved using one of the following methods
 - Download the binary from https://github.com/xipki/xipki/releases
 - Download the binary from the maven repositories
   - Directly via HTTP download
     - Release version: https://repo.maven.apache.org/maven2/org/xipki/assembly/xipki-setup/ 
     - SNASPSHOT version: https://oss.sonatype.org/content/repositories/snapshots/org/xipki/assembly/xipki-setup/
   - Via the `maven-dependency-plugin`
     ```
     <artifactItem>
       <groupId>org.xipki.assembly</groupId>
       <artifactId>xipki-setup</artifactId>
       <version>..version..</version>
       <type>zip</type>
     </artifactItem>
     ```
  - Build it from source code
    - Get a copy of project code, e.g.
      ```sh
      git clone https://github.com/xipki/xipki
      ```
    - Build the project

      In folder `xipki`
      ```sh
      ./install.sh
      ```
 
      Then you will find the binary `assemblies/xipki-setup/target/xipki-setup-<version>.zip`

### Install and Setup

Unpack `xipki-setup-<version>.zip` and follow the `xipki-setup-<version>/INSTALL.md`.

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
  - CMP (RFC 4210, 4211, 9045, 9480)
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
    ML-DSA-44, ML-DSA-65, ML-DSA-87, ML-KEM-512, ML-KEM-768, ML-KEM-1024,
    composite MLDSA (in draft-ietf-lamps-pq-composite-sigs),
    composite MLKEM (in draft-ietf-lamps-pq-composite-kem)
  - Signature algorithms of certificates
    - ML-DSA-44, ML-DSA-65, ML-DSA-87,
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
    and composite-MLDSA in token
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
