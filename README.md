XiPKI
=========
eXtensible sImple Public Key Infrastructure consists of CA and OCSP responder.

- CA (Certification Authority)

  - X.509 Certificate v3 (RFC5280)
  - X.509 CRL v2 (RFC5280)
  - SCEP (draft-gutmann-scep-00, draft-nourse-scep-23)
  - Supported databases
    - Oracle
    - DB2
    - PostgreSQL
    - MySQL
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
    - SHA1withRSA
    - SHA224withRSA
    - SHA256withRSA
    - SHA384withRSA
    - SHA512withRSA
    - SHA1withRSAandMGF1
    - SHA224withRSAandMGF1
    - SHA256withRSAandMGF1
    - SHA384withRSAandMGF1
    - SHA512withRSAandMGF1
    - SHA1withECDSA
    - SHA224withECDSA
    - SHA256withECDSA
    - SHA384withECDSA
    - SHA512withECDSA
    - SHA1withPlainECDSA
    - SHA224withPlainECDSA
    - SHA256withPlainECDSA
    - SHA384withPlainECDSA
    - SHA512withPlainECDSA
    - SHA1withDSA
    - SHA224withDSA
    - SHA256withDSA
    - SHA384withDSA
    - SHA512withDSA
 - Native support of X.509 extensions
    - TLSFeature (RFC 7633)
    - AuthorityKeyIdentifier
    - SubjectKeyIdentifier
    - KeyUsage
    - CertificatePolicies
    - PolicyMappings
    - SubjectAltName
    - IssuerAltName
    - BasicConstraints
    - NameConstraints
    - PolicyConstrains
    - ExtendedKeyUsage
    - CRLDistributionPoints
    - InhibitAnyPolicy
    - FreshestCRL
    - AuthorityInformationAccess
    - SubjectInfoAccess
    - Admission
    - OcspNoCheck
    - Restriction
    - AdditionalInformation
    - ValidityModel
    - PrivateKeyUsagePeriod
    - QCStatements
    - BiometricInfo
    - SMIMECapabilities
 - Support of both random and sequential certificate serial number assignment
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
  - Support of both unsigned and signed OCSP requests
  - Multiple software instances (all can be in active mode) for the same OCSP signer and certifcate status sources.
  - Supported databases
    - Oracle
    - DB2
    - PostgreSQL
    - MySQL
    - H2
    - HSQLDB
  - Embedded database tool (export and import OCSP database) simplifies the switch of databases, upgrade of XiPKi and switch from other OCSP system to XiPKI OCSP.
  - Embedded client to send OCSP request

- Key Tool (for both PKCS#12 and PKCS#11 tokens)
  - Generation of keypairs and self-signed certificates of RSA, EC and DSA in token
  - Deletation of keypairs and certificates from token
  - Update of certificates in token
  - Generation of PKCS#10 request
  - Export of certificate from token

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

Version
----

2.0

License
-----------

* XiPKI Commercial License
* GNU AFFERO GENERAL PUBLIC LICENSE (AGPL) version 3

Owner
-----------
Dr. Lijun Liao (lijun.liao -A-T- gmail -D-O-T- com)

Prerequisite
------------
* JRE / JDK 8
 * OpenJDK: none
 * Oracle: [JCE Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/index.html)
 * IBM J9: [JCE Unlimited Jurisdiction Policy File](https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=jcesdk) 

Tested Platforms
----------------
* Database
 * DB2
 * Oracle
 * Oracle RAC
 * PostgreSQL
 * MySQL
 * H2
 * HSQLDB
 
* HSM
 * Thales nCipher Solo (PCI Card)
 * Thales nCipher Connect (network)

* JVM
 * OpenJDK JRE/JDK 8
 * Oracle JRE/JDK 8
 * IBM J9 JRE/JDK 8
* OS
 * CentOS
 * Fedora
 * Redhat
 * SLES
 * Ubuntu
 * Windows
 * Mac OS
 * Raspbian (tested on Raspberry Pi 2 Model B)

Build and Assembly from Source Code
------------------
* Get a copy of XiPKI code
  ```sh
  git clone git://github.com/xipki/xipki xipki
  ```

* Prepare
  * Install the third party artifacts that are not availablle in maven repositories
    
    In folder `xipki/ext`
    ```sh
    ./install.sh
    ```
 
* Build
  * Compile and install the artifacts
    
    In folder `xipki`
    ```sh
    mvn clean install
    ```
    
  * Assembly
  
    In folder `xipki/dist`
    ```sh
    mvn clean install
    ```

Download the Released Binary Package
------

Download the released binary package `xipki-pki-<version>.tar.gz` from the URL https://github.com/xipki/xipki/releases

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

    If you have changed the content within folder `$XIPKI_HOME/etc` or `$XIPKI_HOME/system`, please delete the folder `$XIPKI_HOME/data` before starting XiPKI.

* Run the pre-configured OSGi-commands in OSGi console

In the OSGi console, call `source <OSGi batch script file>`, the demo script files are in folder `xipki/demo` and can be retrieved from the following table. The generated keys, certificates and CRLs are saved in folder `output`.

|Signature Algorithm \ Key container |  PKCS#12  | PKCS#11 (HSM simulator)|
|:----------------:|:----------------------:|:-----------------------:|
|RSA PKCS#1v1.5    | p12-rsa-demo.script    | hsm-rsa-demo.script     |
|RSA PSS           | p12-rsapss-demo.script | hsm-rsapss-demo.script  |
|DSA               | p12-dsa-demo.script    | hsm-dsa-demo.script     |
|ECDSA             | p12-ec-demo.script     | hsm-ec-demo.script      |
|PlainECDSA (BSI)  | p12-plainec-demo.script| hsm-plainec-demo.script |
