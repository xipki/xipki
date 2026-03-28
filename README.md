[![GitHub release](https://img.shields.io/github/release/xipki/xipki.svg)](https://github.com/xipki/xipki/releases)
[![License](https://img.shields.io/badge/license-Apache%202-4EB1BA.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![Github forks](https://img.shields.io/github/forks/xipki/xipki.svg)](https://github.com/xipki/xipki/network)
[![Github stars](https://img.shields.io/github/stars/xipki/xipki.svg)](https://github.com/xipki/xipki/stargazers)


# XiPKI
XiPKI (e**X**tensible s**I**mple **P**ublic **K**ey **I**nfrastructure)
is a high-performance, open-source PKI (CA, RA, OCSP) designed for critical infrastructure.
Built with minimal dependencies and a compact codebase of ~120,000 lines, it offers native support
for post-quantum algorithms (ML-DSA, ML-KEM, composite), HSM integration via PKCS#11, 
SM2/SM3 for Chinese national standards, and fast OCSP at scale. 
Bouncy Castle can be switched between LTS and FIPS variants to meet different compliance 
requirements. 

The thin XiPKI distribution is now under 6 MB without bundled JDBC drivers and
Bouncy Castle jars.

The project author actively contributes to IETF standardization, including co-authoring the 
C509 specification (CBOR-encoded X.509 certificates) and its test vectors in the COSE Working 
Group.

## License
* The Apache Software License, Version 2.0

## Support
Please [create a new issue](https://github.com/xipki/xipki/issues).

For bug reports, please upload the test data and log files, and describe the XiPKI version, OS,
JRE/JDK, and the steps required to reproduce the bug.

## Get Started

### Binaries
The binaries `xipki-setup-<version>-bclts.tar.gz` (using bouncycastle LTS libraries), 
`xipki-setup-<version>-bcfips.tar.gz` (using bouncycastle FIPS libraries), and 
`xipki-setup-<version>-thin.tar.gz` (without embedded JDBC drivers and bouncycastle libraries) 
can be obtained in one of the following ways:
  - Download the binary from https://github.com/xipki/xipki/releases
  - Download the binary from the central maven repository.
    ```
    <dependency>
      <groupId>org.xipki.assembly</groupId>
      <artifactId>xipki-setup</artifactId>
      <package>tar.gz</package>
      <version>placeholder-version</version>
      <classifier>placeholder-classifier</classifier>
    </dependency>
    ```
    Where `placeholder-version` is the version, e.g. 6.6.1; and 
    `placeholder-classifier`is either `thin`, `bclts` and `bcfips`.
  - Build it from source
    - Get a copy of the project code, for example:
      ```sh
      git clone https://github.com/xipki/xipki
      ```

    - Build the project
      * In the `xipki` folder:
        ```sh
        ./install.sh
        ```
 
      The binaries will then be available in `assemblies/xipki-setup/target/`.

### Just Try The Demo

1. Unpack the binary.
   - For `xipki-setup-<version>-bclts.tar.gz` and `xipki-setup-<version>-fips.tar.gz`
     just unpack it.
   - For `xipki-setup-<version>-thin.tar.gz`
     1. Unpack
     2. Copy the JDBC drivers to `setup/jars/jdbc`.
        See `README.md` in the target folder.
     3. Copy the Bouncy Castle jars to `setup/jars/bouncycastle`. 
        See `README.md` in the target folder.
2. In the unpacked folder `xipki-setup-<version>`:  
   Run `./demo.sh` to prepare the system and start the XiPKI console.
   
   Once the system has been prepared, you only need to start the XiPKI
   console by running `./xipki-setup-<version>/xipki-mgmt-cli/bin/xipki`.
3. In the xipki console:  
   Run `source demo/demo-single.script` to print the usage information, and 
   then follow it, for example:
   `source demo/demo-single.script DB PKCS12 RSA2048`
4. (Optional) Point the browser to http://localhost:8282 to open the H2 database
   console. You can view the database content using username `root` and 
   password `123456` with the following JDBC URLs:
   - Database CA configuration: `jdbc:h2:~/.xipki/db/h2/caconf`
   - Database CA data: `jdbc:h2:~/.xipki/db/h2/ca`
   - Database OCSP data: `jdbc:h2:~/.xipki/db/h2/ocsp`

The generated keys, certificate requests (CSRs), and certificates are in
`xipki-mgmt-cli/output`. The CA, OCSP, and gateway instances are in
the folders `~/xipki_demo/ca-tomcat`, `~/xipki_demo/ocsp-tomcat`, and 
`~/xipki_demo/gateway-tomcat` respectively.

### Install and Setup

Unpack `xipki-setup-<version>-lts.tar.gz` or `xipki-setup-<version>-fips.tar.gz`, and then follow
the instructions in `xipki-setup-<version>/INSTALL.md`.

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
  - It should also work with other HSMs that support PKCS#11.

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
  - API to specify customized publishers, for example for LDAP and the OCSP responder
  - Support for publishers for the OCSP responder
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
  - Native support for X.509 extensions (other extensions can also be supported by 
    configuring them as blobs)
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
    - Support for database clusters
    - Multiple software instances (all can be in active mode) for the same CA
    - Native support for CA management via embedded OSGi commands
    - API to manage the CA. This allows implementation of a proprietary CLI or
      website to manage the CA.
    - A database tool (export and import of the CA database) simplifies switching
      databases, upgrading XiPKI, and migrating from another CA system to XiPKI CA
    - All CA configuration except database configuration is stored in the database

### OCSP Responder
  - OCSP Responder (RFC 2560 and RFC 6960)
  - Lightweight OCSP Profile for High-Volume Environments (RFC 5019)
  - Configurable nonce length (RFC 8954)
  - Support for Common PKI 2.0
  - Management of multiple certificate status sources
  - Support for certificate status sources
    - Database of XiPKI CA
    - OCSP database published by XiPKI CA
    - CRL and DeltaCRL
    - Database of EJBCA
  - API to support proprietary certificate sources
  - Support of both unsigned and signed OCSP requests
  - Multiple software instances (all can be in active mode) for the same OCSP
    signer and certificate status sources.
  - A database tool (export and import of the OCSP database) simplifies switching
    databases, upgrading XiPKI, and migrating from another OCSP system to XiPKI OCSP.
  - High performance
  - Support for health checks

### Mgmt CLI (Management Client)
  - Configuring CA
  - Generating key pairs of RSA, EC, Ed25519, Ed448, X25519, X448, ML-DSA, ML-KEM, 
    composite-MLDSA, and composite-MLKEM in the token
  - Deleting key pairs and certificates from the token
  - Updating certificates in the token
  - Generating CSR (PKCS#10 request)
  - Exporting certificates from the token

### CLI (CA/OCSP Client)
  - Client for enrolling, revoking, and unrevoking (unsuspending) certificates, and downloading CRLs
  - Client for sending OCSP requests
  - Updating certificates in the token
  - Generating CSR (PKCS#10 request)
  - Exporting certificates from the token
