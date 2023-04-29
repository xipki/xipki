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
Just [create issue](https://github.com/xipki/xipki/issues).

For bug-report please upload the test data and log files, describe the version of XiPKI, OS and
JRE/JDK, and the steps to reproduce the bug.

## Prerequisite
* OS: Linux, Windows, MacOS
* JRE / JDK: for `xipki-mgmt-cli` and `xipki-cli`: JDK 11+; for others: JDK 8+.
* Database: DB2, MariaDB, MySQL, Oracle, PostgreSQL, H2, HSQLDB
* Hardware: Any available hardware (tested on Raspberry Pi 2 Model B with 900MHz quad-core ARM CPU and 1 GB Memory)

## Tested PKCS#11 Devices
* [AWS CloudHSM](https://aws.amazon.com/cloudhsm)
* [Nitrokey HSM 2](https://www.nitrokey.com/#comparison) / [Smartcard HSM EA+](http://www.smartcard-hsm.com/features.html#usbstick)
* [nCipher Connect](https://www.ncipher.com/products/general-purpose-hsms/nshield-connect)
* [nCipher Solo](https://www.ncipher.com/products/general-purpose-hsms/nshield-solo)
* [Sansec HSM](https://en.sansec.com.cn)
* [Softhsm v1 & v2](https://www.opendnssec.org/download/packages/)
* [TASS HSM](https://www.tass.com.cn/portal/list/index/id/15.html)
* [Thales LUNA](https://cpl.thalesgroup.com/encryption/hardware-security-modules/general-purpose-hsms)
* [Thales ProtectServer](https://cpl.thalesgroup.com/encryption/hardware-security-modules/protectserver-hsms)
* [Utimaco Se](https://hsm.utimaco.com/products-hardware-security-modules/general-purpose-hsm/)

## Get Started

### JAVA_HOME
  Set the environment variable `JAVA_HOME` to the root directory of JRE/JDK installation.

### Binaries

Download the binary `xipki-setup-<version>.zip`from [releases](https://github.com/xipki/xipki/releases).

Only if you want to use the development version, build it from source code as
follows.

- Get a copy of project code, e.g.
  ```sh
  git clone https://github.com/xipki/xipki
  ```
- Build the project

  In folder `xipki`
  ```sh
  mvn clean install -DskipTests
  ```
 
  Then you will find the binary `assemblies/xipki-setup/target/xipki-setup-<version>.zip`


## Prepare

1. Unpack the binary `xipki-setup-<version>.zip`. To restore the files to a destination 
   folder, run the script `bin/restore.sh /path/to/dest-dir` (or `bin\restore.bat` in Windows).

**Note that all keys and certificates in the binary are only for demo purpose. In production environment
they MUST be replaced.**

**In the following sections, we assume the destination folder is `xipki-install`**.

## Install CA Server

JDK 8+ is required.

1. Unpack tomcat to a new folder
2. Install CA as described in the `xipki-install/xipki-ca/README` file.

## Install OCSP Responder

JDK 8+ is required.

1. Unpack tomcat to a new folder
2. Install CA as described in the `xipki-install/xipki-ocsp/README` file.

## Install Protocol Gateway

JDK 8+ is required.

1. Unpack tomcat to a new folder
2. Install protocol gateway as described in the `xipki-install/xipki-gateway/README` file.

## Install Management Command Line Interface

JDK 11+ is required.

## Install Command Line Interface

JDK 11+ is required.


## Configure PKCS#11 device (optional)

   This step is only required if the real PKCS#11 device instead of the emulator
   is used. **Note that this step should be applied to all components (tomcat, xipki-mgmt-cli, and xipki-cli)**.

  * Copy `xipki/security/example/pkcs11-hsm.json` to `xipki/security/pkcs11.json`, and adapt the PKCS#11 configuration.

## Configure how to handle SSL client certificate (optional)

  This step is only required if the tomcat is behind a reverse proxy apache httpd.

  * Add the java property org.xipki.reverseproxy.mode
    ```sh
    -Dorg.xipki.reverseproxy.mode=APACHE
    ```

  * configure the proxy to forward the headers via mod_proxy with the following
    configuration

   ```sh
   # Require SSL Client verification
   SSLVerifyClient		require

   #initialize the special headers to a blank value to avoid http header forgeries 
   RequestHeader set SSL_CLIENT_VERIFY  "" 
   RequestHeader set SSL_CLIENT_CERT  "" 
   
   <Location / >
    RequestHeader set SSL_CLIENT_VERIFY "%{SSL_CLIENT_VERIFY}s"
    RequestHeader set SSL_CLIENT_CERT "%{SSL_CLIENT_CERT}s"
    ...
   </Location>
   ```

  For more details please refer to
    * [Jetty/Howto/Configure mod proxy](https://wiki.eclipse.org/Jetty/Howto/Configure_mod_proxy)
    * [Jetty: Tricks to do client certificate authentications behind a reverse proxy](http://www.zeitoun.net/articles/client-certificate-x509-authentication-behind-reverse-proxy/start)
    * [Apache Module mod_ssl](http://httpd.apache.org/docs/2.2/mod/mod_ssl.html#envvars)

## Setup CA Server

1. Start the servlet container, e.g. tomcat.

2. Setup CA in Management CLI (in folder `xipki-mgmt-cli`)
    * _(If error like "Identity or Certificate with label=mylabel already exists" occurs,
      you need to comment the line which generate the key (e.g. dsa-p11 ec-p11, rsa-p11, sm2-p12)
      or delete the existing key using command `delete-key-p11`)_.

   * Start Management CLI.

     `bin/karaf`
 
   * Setup CA (choose p11 if the key is saved in PKCS#11 device, p12 in PKCS#12 device)
      * In case of using new keys and certificates, in CLI:  
        `source xipki/ca-setup/cacert-none/setup-*-*.script`
         where * is place holder.

      * In case of using existing keys and certificates, in CLI:  
        `source xipki/ca-setup/cacert-present/setup-*-*.script`
         where * is place holder.

      * If you wish to generate the signing key and certificate for the OCSP responder, in CLI:  
         `source xipki/ca-setup/setup-ocsp-*.script`.

   * Verify the installation, execute the command in CLI:  
     `ca-info myca1`

## Enroll/Revoke Certificate (in folder `xipki-cli`)

* EST  
  Use any EST client.

  The folder `xipki-cli` contains an example script in the folder xipki/client-script.
  It can be executed in the CLI as follows:
  - `source xipki/client-script/est-client.script`

* SCEP  
  Use any SCEP client. XiPKI provides also a SCEP client.

  The folder `xipki-cli` contains an example script in the folder xipki/client-script.
  It can be executed in the CLI as follows:  
  - `source xipki/client-script/scep-client.script`

* CMP  
  Use any CMP client. XiPKI provides also a CMP client.

  The folder `xipki-cli` contains an example script in the folder xipki/client-script.
  It can be executed in the CLI as follows:  
  - `source xipki/client-script/cmp-client.script` (use argument 'help' to print the usage)

* REST API  
  The shell script `xipki/client-script/rest.sh` of the `xipki-cli` demonstrates
  the use of REST API.

  The binary `xipki-cli-<version>`.tar.gz contains an example script in the folder xipki/client-script.
  It can be executed in the CLI as follows:  
  - `source xipki/client-script/rest-client.script` (use argument 'help' to print the usage)

Management CLI Commands
-----
Please refer to [commands.md](commands.md) for more details.
 
CLI Commands
-----
Please refer to [commands.md](commands.md) for more details.

Docker container
-----
See discussion in [discussion #205](https://github.com/xipki/xipki/discussions/249).

Features
-----
- CA Protocol Gateway
  - EST (RFC 7030)
  - SCEP (RFC 8894)
  - CMP (RFC 4210 and RFC 4211)
  - RESTful API

- CA (Certification Authority)
  - X.509 Certificate v3 (RFC 5280)
  - X.509 CRL v2 (RFC 5280)
  - EdDSA Certificates (RFC 8410, RFC 8032)
  - SHAKE Certificates (RFC 8692)
  - Diffie-Hellman Proof-of-Possession Algorithms (RFC 6955)
  - EN 319 411 (eIDAS)
  - EN 319 412 (eIDAS)
  - Supported databases: DB2, MariaDB, MySQL, Oracle, PostgreSQL, H2, HSQLDB
  - Direct and indirect CRL
  - FullCRL and DeltaCRL
  - Customized extension to embed certificates in CRL
  - API to specify customized certificate profiles
  - Support of JSON-based certificate profile
  - API to specify customized publisher, e.g. for LDAP and OCSP responder
  - Support of publisher for OCSP responder
  - Public key types of certificates
    - RSA
    - EC
    - DSA
    - Ed25519, Ed448
    - SM2
    - X25519, X448
  - Signature algorithms of certificates
    - Ed25519, Ed448
    - SHAKE128withRSAPSS, SHAKE256withRSAPSS, 
    - SHA3-*withRSA: where * is 224, 256, 384 and 512
    - SHA3-*withRSAandMGF1: where * is 224, 256, 384 and 512
    - SHA3-*withECDSA: where * is 224, 256, 384 and 512
    - SHA3-*withDSA: where * is 224, 256, 384 and 512
    - SHAKE128withECDSA, SHAKE256withECDSA, 
    - SHA*withRSA: where * is 1, 224, 256, 384 and 512
    - SHA*withRSAandMGF1: where * is 1, 224, 256, 384 and 512
    - SHA*withECDSA: where * is 1, 224, 256, 384 and 512
    - SHA*withPlainECDSA: where * is 1, 224, 256, 384 and 512
    - SHA*withDSA: where * is 1, 224, 256, 384 and 512
    - SM3withSM2
  - Native support of X.509 extensions (other extensions can be supported by
    configuring it as blob)
    - AdditionalInformation (German national standard CommonPKI)
    - Admission (German national standard CommonPKI)
    - AuthorityInformationAccess (RFC 5280)
    - AuthorityKeyIdentifier (RFC 5280)
    - BasicConstraints (RFC 5280)
    - BiometricInfo (RFC 3739)
    - CertificatePolicies (RFC 5280)
    - CRLDistributionPoints (RFC 5280)
    - CT Precertificate SCTs (RFC 6962)
    - ExtendedKeyUsage (RFC 5280)
    - FreshestCRL (RFC 5280)
    - ICRegistrationNumber (GM/T 0015-2012)
    - IdentityCode (GM/T 0015-2012)
    - InsuranceNumber (GM/T 0015-2012)
    - OrganizationCode (GM/T 0015-2012)
    - TaxationNumber (GM/T 0015-2012)
    - InhibitAnyPolicy (RFC 5280)
    - IssuerAltName (RFC 5280)
    - KeyUsage (RFC 5280)
    - NameConstraints (RFC 5280)
    - OcspNoCheck (RFC 6960)
    - PolicyConstrains (RFC 5280)
    - PolicyMappings (RFC 5280)
    - PrivateKeyUsagePeriod (RFC 5280)
    - QCStatements (RFC 3739, eIDAS standard EN 319 412)
    - Restriction (German national standard CommonPKI)
    - SMIMECapabilities (RFC 4262)
    - SubjectAltName (RFC 5280)
    - SubjectDirectoryAttributes (RFC 3739)
    - SubjectInfoAccess (RFC 5280)
    - SubjectKeyIdentifier (RFC 5280)
    - TLSFeature (RFC 7633)
    - ValidityModel (German national standard CommonPKI)
    - ExtensionSchema (Car Connectivity Consortium)
  - Management of multiple CAs in one software instance
    - Support of database cluster
    - Multiple software instances (all can be in active mode) for the same CA
    - Native support of management of CA via embedded OSGi commands
    - API to manage CA. This allows one to implement proprietary CLI, e.g. Website, to manage CA.
    - Database tool (export and import CA database) simplifies the switch of
      databases, upgrade of XiPKi and switch from other CA system to XiPKI CA
    - All configuration of CA except those of databases is saved in database

- OCSP Responder
  - OCSP Responder (RFC 2560 and RFC 6960)
  - Configurable Length of Nonce (RFC 8954)
  - Support of Common PKI 2.0
  - Management of multiple certificate status sources
  - Support of certificate status source based on the database of XiPKI CA
  - Support of certificate status source based on the OCSP database published by XiPKI CA
  - Support of certificate status source CRL and DeltaCRL
  - Support of certificate status source published by EJBCA
  - API to support proprietary certificate sources
  - Support of both unsigned and signed OCSP requests
  - Multiple software instances (all can be in active mode) for the same OCSP
    signer and certificate status sources.
  - Supported databases: DB2, MariaDB, MySQL, Oracle, PostgreSQL, H2, HSQLDB
  - Database tool (export and import OCSP database) simplifies the switch of
    databases, upgrade of XiPKi and switch from other OCSP system to XiPKI OCSP.
  - High performance
  - Support of health check

- CLI
  - Configuring CA
  - Client to enroll, revoke, unrevoke and remove certificates, to generate and download CRLs
  - Client to send OCSP request
  - Generating keypairs of RSA, EC and DSA in token
  - Deleting keypairs and certificates from token
  - Updating certificates in token
  - Generating CSR (PKCS#10 request)
  - Exporting certificate from token
  - High performance
  - Support of health check

- For CA, OCSP Responder, Protocol Gateway and CLI
  - Support of PKCS#12 and JCEKS keystore
  - Support of PKCS#11 devices, e.g. HSM
  - API to use customized key types, e.g. smart card
  - API to resolve password
  - Support of PBE (password based encryption) password resolver
     - All passwords can be encrypted by the master password
  - Support of OBF (as in jetty) password resolver

Use OCSP with customized Certificate Status Source (OcspStore)
-----
  - See the example modules
    - `ocsp-store-example`: implementation of a customized OcspStore.
    - `ocsp-store-example-assembly`: assembly the binaries.
