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
* JRE / JDK: Java 11+.
* Database: DB2, MariaDB, MySQL, Oracle, PostgreSQL, H2, HSQLDB
* Hardware: Any available hardware (tested on Raspberry Pi 2 Model B with 900MHz quad-core ARM CPU and 1 GB Memory)
* Servlet Container: Tomcat 8, 9, 10

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
The binary `xipki-setup-<version>.zip` can be retrieved using one of the following methods
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
      mvn clean install -DskipTests -Passembly
      ```
 
      Then you will find the binary `assemblies/xipki-setup/target/xipki-setup-<version>.zip`


## Prepare

1. Unpack the binary `xipki-setup-<version>.zip`. To restore the files to a destination 
   folder, run the script `bin/restore.sh /path/to/destination-dir` (or `bin\restore.bat` in Windows).

**In the following sections, we assume the destination directory (`destination-dir`) is `xipki-install`**.

## Prepare Keys and certificates for the Communication between XiPKI Components

1. Change the password (`"CHANGEIT"`), and subject in `xipki-install/setup/keycerts.json` and the XiPKI components.
2. Generate keys and certificates:  
  `xipki-install/setup/generate-keycerts.sh`.
3. Copy the keys and certificates to the target components:  
   `xipki-install/setup/provision-keycerts.sh`.

## Install CA Server

1. Unpack tomcat to a new folder
2. Install CA as described in the `xipki-install/xipki-ca/README.md` file.

## Install OCSP Responder

1. Unpack tomcat to a new folder
2. Install CA as described in the `xipki-install/xipki-ocsp/README.md` file.

## Install Protocol Gateway

1. Unpack tomcat to a new folder.
2. Install protocol gateway as described in the `xipki-install/xipki-gateway/README.md` file.

## Install HSM Proxy Server

1. Unpack tomcat to a new folder
2. Install CA as described in the `xipki-install/xipki-hsmproxy/README.md` file.

## Install Management Command Line Interface
   void

## Install Command Line Interface
   void

## Configure PKCS#11 device (optional)

   This step is only required if the real PKCS#11 device instead of the emulator
   is used. **Note that this step should be applied to all components (tomcat, xipki-mgmt-cli, and xipki-cli)**.

  * Copy the corresponding configuration file in the folder `xipki/security/example/` to `xipki/security/pkcs11.json`,
    and adapt the PKCS#11 configuration.
    - For HSM device: `pkcs11-hsm.json`
    - For HSM proxy client: `pkcs11-hsmproxy.json`
    - For HSM emulaor: `pkcs11-emulator.json`

## Configure how to handle SSL client certificate behind reverse proxy

### For reverse proxy apache httpd

* Set the `reverseProxyMode` field in the json configuration file to `APACHE`:
  - CA: `xipki/etc/ca/ca.json`
  - HSM Proxy: `xipki/etc/hsmproxy.json`
  - CA Gateway
    - CMP: `xipki/gatway/cmp-gateway.json`
    - EST: `xipki/gatway/est-gateway.json`
    - REST: `xipki/gatway/rest-gateway.json`

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

### For reverse proxy apache nginx

* Set the `reverseProxyMode` in the json configuration file (e.g. `ca.json`) to `NGINX`.

* configure the proxy to forward the headers with the following
  configuration

   ```sh
   # Require SSL Client verification
   ssl_verify_client on;

   location / {
     ...
     #initialize the special headers to a blank value to avoid http header forgeries 
     proxy_set_header set SSL_CLIENT_VERIFY  "";
     proxy_set_header set SSL_CLIENT_CERT  "";

     # if the client certificate verified 
     # will have the value of 'SUCCESS' and 'NONE' otherwise
     proxy_set_header SSL_CLIENT_VERIFY $ssl_client_verify;
    
     # client certificate
     proxy_set_header SSL_CLIENT_CERT $ssl_client_escaped_cert;
     ...
   }
   ...
  ```

  For more details please refer to
  * [NGINX Reverse Proxy](https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/)
  * [Module ngx_http_ssl_module](http://nginx.org/en/docs/http/ngx_http_ssl_module.html)

## Setup CA Server

As described in the `xipki-install/xipki-mgmt-cli/README.md` file.

## Enroll/Revoke Certificate

As described in the `xipki-install/xipki-cli/README.md` file.

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
  - CMP (RFC 4210, 4211, 9045, draft-ietf-lamps-cmp-updates)
  - ACME (RFC 8555, RFC 8737)
    - Challenge types: dns-01, http-01, tls-apln-01
  - RESTful API

- CA (Certification Authority)
  - X.509 Certificate v3 (RFC 5280)
  - X.509 CRL v2 (RFC 5280)
  - EdDSA Certificates (RFC 8410, RFC 8032)
  - SHAKE Certificates (RFC 8692)
  - Diffie-Hellman Proof-of-Possession Algorithms (RFC 6955)
  - EN 319 411 (eIDAS)
  - EN 319 412 (eIDAS)
  - Direct and indirect CRL
  - FullCRL and DeltaCRL
  - Customized extension to embed certificates in CRL
  - API to specify customized certificate profiles
  - Support of JSON-based certificate profile
  - API to specify customized publisher, e.g. for LDAP and OCSP responder
  - Support of publisher for OCSP responder
  - Public key types of certificates: RSA, EC, DSA, Ed25519, Ed448, SM2, X25519, X448
  - Signature algorithms of certificates
    - DSA with hash algorithms: SHA-1, SHA-2, and SHA-3
    - ECDSA with hash algorithms: SHA-1, SHA-2, SHA-3, and SHAKE
    - Ed25519, Ed448
    - Plain ECDSA with hash algorithms: SHA-1, and SHA-2
    - RSA PKCS1v1.5 with hash algorithms: SHA-1, SHA-2, and SHA-3
    - RSA PSS with hash algorithms: SHA-1, SHA-2, and SHA-3, and SHAKE
    - SM3withSM2
  - Native support of X.509 extensions (other extensions can be supported by
    configuring it as blob)
    - RFC 3739
      - BiometricInfo
      - QCStatements (also in eIDAS standard EN 319 412)
      - SubjectDirectoryAttributes
    - RFC 4262
      - SMIMECapabilities
    - RFC 5280
      - AuthorityInformationAccess
      - AuthorityKeyIdentifier
      - BasicConstraints
      - CertificatePolicies
      - CRLDistributionPoints
      - ExtendedKeyUsage
      - FreshestCRL
      - InhibitAnyPolicy
      - IssuerAltName
      - KeyUsage
      - NameConstraints
      - PolicyConstrains
      - PolicyMappings
      - PrivateKeyUsagePeriod
      - SubjectAltName
      - SubjectInfoAccess
      - SubjectKeyIdentifier
    - RFC 6960
      - OcspNoCheck
    - RFC 6962
      - CT Precertificate SCTs
    - RfC 7633
      - TLSFeature
    - Car Connectivity Consortium
      - ExtensionSchema
    - Common PKI (German national standard)
      - AdditionalInformation
      - Admission
      - Restriction
      - ValidityModel
    - GM/T 0015-2012 (Chinese national standard)
      - ICRegistrationNumber
      - IdentityCode
      - InsuranceNumber
      - OrganizationCode
      - TaxationNumber
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

- Mgmt CLI (Management Client)
  - Configuring CA
  - Generating keypairs of RSA, EC and DSA in token
  - Deleting keypairs and certificates from token
  - Updating certificates in token
  - Generating CSR (PKCS#10 request)
  - Exporting certificate from token

- CLI (CA/OCSP Client)
  - Client to enroll, revoke, unrevoke (unsuspend) and remove certificates, to generate and download CRLs
  - Client to send OCSP request
  - Updating certificates in token
  - Generating CSR (PKCS#10 request)
  - Exporting certificate from token

- HSM Proxy
  - Provide service to access to the HSM remotely.

- For CA, OCSP Responder, CA Protocol Gateway, Management Client, Client, and HSM Proxy
  - Support of PKCS#12 and JCEKS keystore
  - Support of PKCS#11 devices, e.g. HSM
  - API to use customized key types, e.g. smart card
  - API to resolve password
  - Support of PBE (password based encryption) password resolver
     - All passwords can be encrypted by the master password
  - Support of OBF (as in jetty) password resolver
