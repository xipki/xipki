XiPKI
=========
eXtensible sImple Public Key Infrastructure consists of CA and OCSP responder.

Highly scalable and high-performance open source PKI (Certification Authority and OCSP responder), especially suitable for IoT, M2M and V2X.

License
-----------

* XiPKI Commercial License
* GNU AFFERO GENERAL PUBLIC LICENSE (AGPL) version 3

Owner
-----------
Lijun Liao (lijun.liao -A-T- gmail -D-O-T- com), [LinkedIn](https://www.linkedin.com/in/lijun-liao-644696b8)

Community Support
-----------
Just drop me an email.

Prerequisite
------------
* JRE / JDK 8
  * OpenJDK: none
  * Oracle: [JCE Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/index.html)

Tested Platforms
----------------
* Database
  * DB2
  * Oracle
  * Oracle RAC
  * PostgreSQL
  * MySQL
  * MariaDB
  * H2
  * HSQLDB

* HSM
  * Thales nCipher Solo (PCI Card)
  * Thales nCipher Connect (network)
  * Utimaco Se
  * [Softhsm v2](https://www.opendnssec.org/download/packages/)

* JVM
  * OpenJDK 8
  * Oracle JRE/JDK 8
* OS
  * CentOS
  * Fedora
  * Redhat
  * SLES
  * Ubuntu
  * Windows
  * Mac OS
  * Raspbian (tested on Raspberry Pi 2 Model B)

Alternative: Download the Released Binary Package
------

Download the released binary package `xipki-pki-<version>.tar.gz` from the URL https://github.com/xipki/xipki/releases

Alternative: Build and Assembly from Source Code
------------------
* Get a copy of XiPKI code
  ```sh
  git clone git://github.com/xipki/xipki
  ```

* Build
  * Install the third party artifacts that are not availablle in maven repositories

    * In folder `xipki/ext`
      ```sh
      ./install.sh
      ```

  * Compile and install the artifacts

    In folder `xipki`
    ```sh
    mvn clean install
    ```

  * Assembly

    In folder `xipki/dist/xipki-pki`
    ```sh
    mvn clean package
    ```

Install
-------

* Copy the file `xipki-pki-<version>.tar.gz` to the destination folder

* Unpack the assembled file

    In destination folder of the installation
    ```sh
    tar xvf xipki-pki-<version>.tar.gz
    ```
    The following steps use `$XIPKI_HOME` to point to the unpacked folder

* Adapt the database configuration (access rights read and write of database are required)

    ```sh
    $XIPKI_HOME/xipki/ca-config/ca-db.properties
    $XIPKI_HOME/xipki/ca-config/ocsp-db.properties
    ```
* In case if the real PKCS#11 device instead of the emulator is used:

  * In file etc/org.xipki.commons.security.pkcs11.cfg, change the pkcs11.confFile as follows:

    ```sh
    pkcs11.confFile = xipki/security/pkcs11-conf-hsm.xml

    #pkcs11.confFile = xipki/security/pkcs11-conf-emulator.xml
    ```
  * In file xipki/security/pkcs11-conf-hsm.xml, change the PKCS#11 configuration.

Run Demo
-----

* Delete folders `$XIPKI_HOME/data` and `$XIPKI_HOME/output`

* Start XiPKI

    In folder `$XIPKI_HOME`
    ```sh
    bin/karaf
    ```

    HSM devices of Thales, e.g. nCipher, uses Thales preload to manage the PKCS#11 session. In this case, XiPKI should be started as follows
    ```sh
    preload bin/karaf
    ```

    If you get error like
    ```sh
    Error occurred during initialization of VM
    Could not reserve enough space for 2097152KB object heap
    ```
    please change the value of JAVA_MAX_MEM in the file `bin/setenv` or `bin/setenv.bat`.

    If you have changed the content within folder `$XIPKI_HOME/etc` or `$XIPKI_HOME/system`, please delete the folder `$XIPKI_HOME/data` before starting XiPKI.

* Run the pre-configured OSGi-commands in OSGi console

In the OSGi console, call `source xipki/demo/demo.script` to demonstrate the whole life-cycle (key generation, database initialization, CA installation, certificate enrollment, OCSP server installation, OCSP status, etc.). The generated keys, certificates and CRLs are saved in folder `output`, and the log files are located in the folder data/log.

Components
-----
- CA (Certification Authority)

  - X.509 Certificate v3 (RFC 5280)
  - X.509 CRL v2 (RFC 5280)
  - SCEP (draft-gutmann-scep-00, draft-nourse-scep-23)
  - EN 319 411 (eIDAS)
  - EN 319 412 (eIDAS)
  - Supported databases
    - Oracle
    - DB2
    - PostgreSQL
    - MySQL
    - MariaDB
    - H2
    - HSQLDB
  - Direct and indirect CRL
  - FullCRL and DeltaCRL
  - Customized extension to embed certificates in CRL
  - CMP (RFC 4210 and RFC 4211)
  - API to specify customized certificate profiles
  - Embedded support of XML-based certificate profile
  - API to specify customized publisher, e.g. for LDAP and OCSP responder
  - Embedded support of publisher for OCSP responder
  - Signature algorithms of certificates
    - SHA*withRSA: where * is 1, 224, 256, 384 and 512
    - SHA*withRSAandMGF1: where * is 1, 224, 256, 384 and 512
    - SHA*withECDSA: where * is 1, 224, 256, 384 and 512
    - SHA*withPlainECDSA: where * is 1, 224, 256, 384 and 512
    - SHA*withDSA: where * is 1, 224, 256, 384 and 512
 - Embedded support of X.509 extensions
    - AdditionalInformation (German national standard CommonPKI)
    - Admission (German national standard CommonPKI)
    - AuthorityInformationAccess (RFC 5280)
    - AuthorityKeyIdentifier (RFC 5280)
    - BasicConstraints (RFC 5280)
    - BiometricInfo (RFC 3739)
    - CertificatePolicies (RFC 5280)
    - CRLDistributionPoints (RFC 5280)
    - ExtendedKeyUsage (RFC 5280)
    - FreshestCRL (RFC 5280)
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
    - SubjectInfoAccess (RFC 5280)
    - SubjectKeyIdentifier (RFC 5280)
    - TLSFeature (RFC 7633)
    - ValidityModel (German national standard CommonPKI)
 - Management of multiple CAs in one software instance
 - Multiple software instances (all can be in active mode) for the same CA
 - Embedded support of management of CA via embedded OSGi commands
 - API to specify CA management, e.g. GUI
 - Embedded database tool (export and import CA database) simplifies the switch of databases, upgrade of XiPKi and switch from other CA system to XiPKI CA
 - Embedded client to enroll, revoke, unrevoke and remove certificates, to generate and download CRLs
 - All configuration of CA except those of databases is saved in database

- OCSP Responder
  - OCSP Responder (RFC 2560 and RFC 6960)
  - Support of Common PKI 2.0
  - Management of multiple certificate status sources
  - Embedded support of certificate status source published by XiPKI CA
  - Embedded support of certificate status source CRL and DeltaCRL
  - API to support proprietary certificate sources
  - Support of both unsigned and signed OCSP requests
  - Multiple software instances (all can be in active mode) for the same OCSP signer and certificate status sources.
  - Supported databases
    - Oracle
    - DB2
    - PostgreSQL
    - MySQL
    - MariaDB
    - H2
    - HSQLDB
  - Embedded database tool (export and import OCSP database) simplifies the switch of databases, upgrade of XiPKi and switch from other OCSP system to XiPKI OCSP.
  - Embedded client to send OCSP request

- Key Tool (for both PKCS#12 and PKCS#11 tokens)
  - Generating keypairs of RSA, EC and DSA in token
  - Deleting keypairs and certificates from token
  - Updating certificates in token
  - Generating PKCS#10 request
  - Exporting certificate from token

- For both CA and OCSP Responder
  - Support of PKCS#12 and JKS keystore
  - Support of PKCS#11 devices, e.g. HSM
  - API to use customized key types, e.g. smartcard
  - High performance
  - OSGi-based (java), OS independent
  - Support of health check
  - Audit with syslog and slf4j

- For CA, OCSP Responder and Key Tool
  - API to resolve password
  - Embedded support of PBE (password based encryption) password resolver
     - All passwords can be encrypted by the master password
  - Embedded support of OBF (as in jetty) password resolver
