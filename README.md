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
The binary `xipki-setup-<version>.tar.gz` can be obtained in one of the following ways: 
  - Download the binary from https://github.com/xipki/xipki/releases
  - Download the binary from the central maven repository.
    ```
    <dependency>
      <groupId>org.xipki.assembly</groupId>
      <artifactId>xipki-setup</artifactId>
      <type>tar.gz</type>
      <version>placeholder-version</version>
    </dependency>
    ```
    Where `placeholder-version` is the version, e.g. 6.7.0.
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
   - Unpack `xipki-setup-<version>.tar.gz` 
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

Unpack `xipki-setup-<version>.tar.gz` and then follow
the instructions in `xipki-setup-<version>/INSTALL.md`.

## Features

### Supported Platform
* OS
  * Linux, MacOS
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
  - Native support for X.509 extensions (other extensions can also be supported by configuring them as blobs)
    - RFC 3739
      - BiometricInfo (1.3.6.1.5.5.7.1.2)
      - QCStatements (also in eIDAS standard EN 319 412, 1.3.6.1.5.5.7.1.3)
      - SubjectDirectoryAttributes with attribute types
        - dateOfBirth  (1.3.6.1.5.5.7.9.1)
        - placeOfBirth (1.3.6.1.5.5.7.9.2)
        - gender       (1.3.6.1.5.5.7.9.3)
        - countryOfCitizenship (1.3.6.1.5.5.7.9.4)
        - countryOfResidence   (1.3.6.1.5.5.7.9.5)
    - RFC 4262
      - SMIMECapabilities (1.2.840.113549.1.9.15)
    - RFC 5280
      - AuthorityInformationAccess (1.3.6.1.5.5.7.1.1)
      - AuthorityKeyIdentifier (2.5.29.35)
      - BasicConstraints (2.5.29.19)
      - CertificatePolicies (2.5.29.32)
      - CRLDistributionPoints (2.5.29.31)
      - ExtendedKeyUsage (2.5.29.37)
      - FreshestCRL (2.5.29.46)
      - InhibitAnyPolicy (2.5.29.54)
      - IssuerAltName (2.5.29.18)
      - KeyUsage (2.5.29.15)
      - NameConstraints (2.5.29.30)
      - PolicyConstrains (2.5.29.36)
      - PolicyMappings (2.5.29.33)
      - PrivateKeyUsagePeriod (2.5.29.16)
      - SubjectAltName (2.5.29.17)
      - SubjectDirectoryAttributes (2.5.29.9)
      - SubjectInfoAccess (1.3.6.1.5.5.7.1.11)
      - SubjectKeyIdentifier (2.5.29.14)
    - RFC 6960
      - OcspNoCheck (1.3.6.1.5.5.7.48.1.5)
    - RFC 6962
      - CT Pre-certificate SCTs (1.3.6.1.4.1.11129.2.4.2)
    - RfC 7633
      - TLSFeature (1.3.6.1.5.5.7.1.24)
    - Car Connectivity Consortium
      - CCC-K-Vehicle-Cert     (1.3.6.1.4.1.41577.5.1)
      - CCC-F-External-CA-Cert (1.3.6.1.4.1.41577.5.2)
      - CCC-E-Instance-CA-Cert (1.3.6.1.4.1.41577.5.3)
      - CCC-H-Endpoint-Cert    (1.3.6.1.4.1.41577.5.4)
      - CCC-P-VehicleOEM-Enc-Cert (1.3.6.1.4.1.41577.5.5)
      - CCC-Q-VehicleOEM-Sig-Cert (1.3.6.1.4.1.41577.5.6)
      - CCC-Device-Enc-Cert       ( 1.3.6.1.4.1.41577.5.7)
      - CCC-Vehicle-Intermediate-Cert (1.3.6.1.4.1.41577.5.8)
      - CCC-J-VehicleOEM-CA-Cert (1.3.6.1.4.1.41577.5.9)
      - CCC-M-VehicleOEM-CA-Cert (1.3.6.1.4.1.41577.5.10)
      - CCC-R-Certification-Body-Cert (1.3.6.1.4.1.41577.5.14)
      - CCC-S-SBxD/KIS-Intermediate-CA-Cert (1.3.6.1.4.1.41577.5.15)
      - CCC-T-SBxD/KIS-Endpoint-Cert (1.3.6.1.4.1.41577.5.16)
      - CCC-U-SBxD/KIS-RootCA-Cert (1.3.6.1.4.1.41577.5.17)
    - Microsoft
      - Certificate Template Name (1.3.1.6.1.311.20.2)
      - Certificate Template Information (1.3.1.6.1.311.21.7)
      - Security Identifier (SID, 1.3.1.6.1.311.25.2)
    - China GM/T 0015-2023
      - Resident Identity Card Number (1.2.156.10260.4.1.1.1)
      - Passport Number (1.2.156.10260.4.1.1.2)
      - Social Insurance Number (1.2.156.10260.4.1.2)
      - Unified Social Credit Code  (1.2.156.10260.4.4)
    - RPKI
      - IPAddrBlocks    (1.3.6.1.5.5.7.1.7)
      - IPAddrBlocksV2  (1.3.6.1.5.5.7.1.28)
      - ASIdentifiers   (1.3.6.1.5.5.7.1.8)
      - ASIdentifiersV2 (1.3.6.1.5.5.7.1.29)
    - SPDM (https://www.dmtf.org/standards/spdm)
      - spdm-cert-oids (1.3.6.1.4.1.412.274.6)
      - SubjectAltNames with otherName types
        - DMTF-device-info (1.3.6.1.4.1.412.274.1)
    - STIR (RFC8226)
      - TNAuthList (1.3.6.1.5.5.7.1.26)
      - JWTClaimConstraints (1.3.6.1.5.5.7.1.27)
    - RFC 4108
      - SubjectAltNames with otherName types
        - id-on-hardwareModuleName (1.3.6.1.5.5.7.8.4)
    - RFC 9608
      - noRevAvail (2.5.29.56)
    - RFC 9598
      - SubjectAltNames with otherName types
        - id-on-SmtpUTF8Mailbox (1.3.6.1.5.5.7.8.9)
    - BRSKI (RFC 8995)
      - MASA-URL (1.3.6.1.5.5.7.1.32)
    - RFC 10031
      - SubjectAltNames with otherName types
        - id-on-MACAddress (1.3.6.1.5.5.7.8.12)
    - TCG DICE (Calipta)
      - dice-ueid (2.23.133.5.4.4)
    - TCG Platform Certificate Profile
      - SubjectAltNames with OtherName types
        - TCG-platformIdentifier (2.23.133.5.1.8)
      - SubjectDirectoryAttributes with attribute types
        - TCG-PlatformSpecification        (2.23.133.2.17)
        - TCG-CredentialSpecification      (2.23.133.2.23)
        - TCG-CredentialType               (2.23.133.2.25)
        - TCG-PreviousPlatformCertificates (2.23.133.2.26)
        - TCG-TbbSecurityAssertions-v3     (2.23.133.2.27)
        - TCG-CryptographicAnchors         (2.23.133.2.28)
        - TCG-PlatformOwnership            (2.23.133.2.29)
        - TCG-ManufacturingAssertions      (2.23.133.2.30)
        - TCG-PlatformConfiguration-v3     (2.23.133.5.1.7.3)
        - TCG-PlatformConfigUri-v3         (2.23.133.5.1.7.4)
  - Native support for X.509 RDN attributes
    - Common attributes
      - c, countryName (2.5.4.6)
      - dc, domainComponent (0.9.2342.19200300.100.1.25)
      - st, stateOrProvinceName (2.5.4.8)
      - l, localityName (2.5.4.7)
      - postalCode (2.5.4.17)
      - street, streetAddress (2.5.4.9)
      - jurisdictionCountryName, jurisdictionOfIncorporationCountryName (1.3.6.1.4.1.311.60.2.1.3)
      - jurisdictionStateOrProvinceName, jurisdictionOfIncorporationStateOrProvinceName (1.3.6.1.4.1.311.60.2.1.2)
      - jurisdictionLocalityName, jurisdictionOfIncorporationLocalityName (1.3.6.1.4.1.311.60.2.1.1)
      - o, organizationName (2.5.4.10)
      - organizationIdentifier (2.5.4.97)
      - ou, organizationalUnitName (2.5.4.11)
      - serialNumber (2.5.4.5)
      - sn, surName (2.5.4.4)
      - initials (2.5.4.43)
      - givenName (2.5.4.42)
      - title (2.5.4.12)
      - pseudonym (2.5.4.65)
      - name (2.5.4.41)
      - cn, commonName (2.5.4.3)
      - uid, userId (0.9.2342.19200300.100.1.1)
      - dmdName (2.5.4.54)
      - emailAddress (1.2.840.113549.1.9.1)
      - unstructuredName (1.2.840.113549.1.9.2)
      - unstructuredAddress (1.2.840.113549.1.9.8)
      - telephoneNumber (2.5.4.20)
      - businessCategory (2.5.4.15)
    - CSA Matter (https://csa-iot.org/developer-resource/specifications-download-request)
      - matter-node-id (1.3.6.1.4.1.37244.1.1)
      - matter-firmware-signing-id (1.3.6.1.4.1.37244.1.2)
      - matter-icac-id (1.3.6.1.4.1.37244.1.3)
      - matter-rcac-id (1.3.6.1.4.1.37244.1.4)
      - matter-fabric-id (1.3.6.1.4.1.37244.1.5)
      - matter-noc-cat (1.3.6.1.4.1.37244.1.6)
      - matter-vvs-id (1.3.6.1.4.1.37244.1.7)
      - matter-oid-vid (1.3.6.1.4.1.37244.2.1)
      - matter-oid-pid (1.3.6.1.4.1.37244.2.2)
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
