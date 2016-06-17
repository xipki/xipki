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


Karaf Features and Commands
-----

The karaf feature can be installed via the command `feature:install <feature name>` and uninstalled
in the OSGi console via the command `feature:uninstall <feature name>`. The possible feature can be
auto-completed by typing the `TAB` key.

Some features in XiPKI are listed below, a list of all available features can be retrieved via the
command `feature:list  | grep xipki` in OSGi console.

For the usage of OSGi commands, just use the option `--help``. Most XiPKI commands can 
auto-completing the options and arguments by the `TAB` key.

* xipki-caserver

  CA server

* xipki-ocspserver

  OCSP server

* xipki-shell-base

  Provides OSGi commands

   * `xipki-cmd:confirm`

     Confirm an action

   * `xipki-cmd:copy-dir`

     Copy content of the directory to destination

   * `xipki-cmd:copy-file`

     Copy file

   * `xipki-cmd:ls`

     List directory contents

   * `xipki-cmd:rm`

     Remove file or directory

   * `xipki-cmd:mkdir`

     Make directories

   * `xipki-cmd:produce-password`

     Produce password

   * `xipki-cmd:replace`

     Replace text in file

* xipki-database-tool

  Provides OSGi commands

   * `xipki-db:diff-digest-db`

     diff digest XiPKI/EJBCA databas

   * `xipki-db:digest-db`

     digest XiPKI/EJBCA database

   * `xipki-db:export-ca`

     export CA database

   * `xipki-db:export-ocsp`

     export OCSP database

   * `xipki-db:import-ca`

     import CA database

   * `xipki-db:import-ocsp`

     import OCSP database

   * `xipki-db:import-ocspfromca`

     reset and initialize the CA and OCSP databases

   * `xipki-db:initdb-ca`

     reset and initialize the CA database

   * `xipki-db:initdb-ocsp`

     reset and initialize the OCSP databases

   * `xipki-db:updatedb-ca`
     update the CA database schema

   * `xipki-db:updatedb-ocsp`

     update the OCSP database schema

* xipki-security-shell

  Provides OSGi commands

   * `xipki-tk:validate-req`

     validate PKCS#10 request

   * `xipki-tk:deobfuscate`

     deobfuscate password

   * `xipki-tk:extract-cert`

     extract certificates from CRL

   * `xipki-tk:obfuscate`

     obfuscate password

   * `xipki-tk:pbe-dec`

     decrypt password with master password

   * `xipki-tk:pbe-enc`

     encrypt password with master password

   * `xipki-tk:add-cert`

     add certificate to PKCS#11 device

   * `xipki-tk:rm-cert`

     remove certificate from PKCS#11 device

   * `xipki-tk:export-cert`

     export certificate from PKCS#11 device

   * `xipki-tk:export-cert-p12`

     export certificate from PKCS#12 keystore

   * `xipki-tk:req`

     generate PKCS#10 request with PKCS#11 device

   * `xipki-tk:req-p12`

     generate PKCS#10 request with PKCS#12 keystore

   * `xipki-tk:update-cert`

     update certificate in PKCS#11 device

   * `xipki-tk:update-cert-p12`

     update certificate in PKCS#12 keystore

   * `xipki-tk:dsa`

     generate DSA keypair in PKCS#11 device

   * `xipki-tk:dsa-p12`

     generate RSA keypair in PKCS#12 keystore

   * `xipki-tk:ec`

     generate EC keypair in PKCS#11 device

   * `xipki-tk:ec-p12`

     generate EC keypair in PKCS#12 keystore

   * `xipki-tk:delete-key`

     delete key and cert in PKCS#11 device

   * `xipki-tk:token-info`

     list objects in PKCS#11 device

   * `xipki-tk:delete-objects`

     delete objects in PKCS#11 device

   * `xipki-tk:provider-test`

     test the Xipki JCA/JCE provider

   * `xipki-tk:refresh`

     refresh PKCS#11 module

   * `xipki-tk:rsa`

     generate RSA keypair in PKCS#11 device

   * `xipki-tk:rsa-p12`

     generate RSA keypair in PKCS#12 keystore

* xipki-camgmt-shell

  Provides OSGi commands

   * `xipki-ca:ca-add`

     add CA

   * `xipki-ca:ca-addf`

     add CA from configuration file

   * `xipki-ca:caalias-add`

     add CA alias

   * `xipki-ca:caalias-info`

     show information of CA alias

   * `xipki-ca:caalias-rm`

     remove CA alias

   * `xipki-ca:ca-export`

     export CA configuration

   * `xipki-ca:gen-rca`

     generate selfsigned CA

   * `xipki-ca:gen-rcaf`

     generate selfsigned CA from configuration file

   * `xipki-ca:ca-info`

     show information of CA

   * `xipki-ca:caprofile-add`

     add certificate profile to CA

   * `xipki-ca:caprofile-info`

     show information of certificate profile in given CA

   * `xipki-ca:caprofile-rm`

     remove certificate profile from CA

   * `xipki-ca:capub-add`

     add publisher to CA

   * `xipki-ca:capub-info`

     show information of publisher in given CA

   * `xipki-ca:capub-rm`

     remove publisher from CA

   * `xipki-ca:publish-self`

     publish the certificate of root CA

   * `xipki-ca:ca-rm`

     remove CA

   * `xipki-ca:careq-add`

     add requestor to CA

   * `xipki-ca:add requestor to CA`

     show information of requestor in CA

   * `xipki-ca:careq-rm`

     remove requestor from CA

   * `xipki-ca:ca-revoke`

     revoke CA

   * `xipki-ca:notify-change`

     notify the change of CA system

   * `xipki-ca:restart`

     restart CA system

   * `xipki-ca:system-status`

     show CA system status

   * `xipki-ca:unlock`

     unlock CA system

   * `xipki-ca:ca-unrevoke`

     unrevoke CA

   * `xipki-ca:ca-up`

     update CA

   * `xipki-ca:clear-publishqueue`

     clear publish queue

   * `xipki-ca:cmpcontrol-add`

     add CMP control

   * `xipki-ca:cmpcontrol-info`

     show information of CMP control

   * `xipki-ca:cmpcontrol-rm`

     remove CMP control

   * `xipki-ca:cmpcontrol-up`

     update CMP control

   * `xipki-ca:crlsigner-add`

     add CRL signer

   * `xipki-ca:crlsigner-info`

     show information of CRL signer

   * `xipki-ca:crlsigner-rm`

     remove CRL signer

   * `xipki-ca:crlsigner-up`

     update CRL signer

   * `xipki-ca:env-add`

     add CA environment parameter

   * `xipki-ca:env-info`

     show information of CA environment parameter

   * `xipki-ca:env-rm`

     remove CA environment parameter

   * `xipki-ca:env-up`

     update CA environment parameter

   * `xipki-ca:profile-add`

     add certificate profile

   * `xipki-ca:profile-export`

     export certificate profile configuration

   * `xipki-ca:profile-info`

     show information of certifiate profile

   * `xipki-ca:profile-rm`

     remove certifiate profile

   * `xipki-ca:profile-up`

     update certificate profile

   * `xipki-ca:publisher-add`

     add publisher

   * `xipki-ca:publisher-export`

     export publisher configuration

   * `xipki-ca:publisher-info`

     show information of publisher

   * `xipki-ca:publisher-rm`

     remove publisher

   * `xipki-ca:publisher-up`

     update publisher

   * `xipki-ca:republish`

     republish certificates

   * `xipki-ca:requestor-add`

     add requestor

   * `xipki-ca:requestor-info`

     show information of requestor

   * `xipki-ca:requestor-rm`

     remove requestor

   * `xipki-ca:requestor-up`

     update requestor

   * `xipki-ca:responder-add`

     add responder

   * `xipki-ca:responder-info`

     show information of responder

   * `xipki-ca:responder-rm`

     remove responder

   * `xipki-ca:responder-up`

     update responder

   * `xipki-ca:scep-add`

     add SCEP

   * `xipki-ca:scep-info`

     show information of SCEP

   * `xipki-ca:scep-rm`

     remove SCEP

   * `xipki-ca:scep-up`

     update SCEP

   * `xipki-ca:user-add`

     add user

   * `xipki-ca:user-info`

     show information of user

   * `xipki-ca:user-rm`
 
    remove user

   * `xipki-ca:user-up`

     update user

   * `xipki-ca:cert-status`

     show certificate status

   * `xipki-ca:enroll-cert`

     enroll certificate

   * `xipki-ca:gencrl`

     generate CRL

   * `xipki-ca:getcrl`

     download CRL

   * `xipki-ca:remove-cert`

     remove certificate

   * `xipki-ca:revoke-cert`

     revoke certificate

   * `xipki-ca:unrevoke-cert`

     unrevoke certificate

   * xipki-camgmt-qa-shell

     Provides OSGi commands

   * xipki-caclient-shell

     Provides OSGi commands
  
   * `xipki-cli:gencrl`

     generate CRL

   * `xipki-cli:getcrl`

     download CRL

   * `xipki-cli:health`

     check healty status of CA

   * `xipki-cli:p10-enroll`

     enroll certificate via PKCS#10 request

   * `xipki-cli:enroll`

     enroll certificate (PKCS#11 token)

   * `xipki-cli:enroll-p12`

     enroll certificate (PKCS#12 keystore)

   * `xipki-cli:remove-cert`

     remove certificate

   * `xipki-cli:revoke-cert`

     revoke certificate

   * `xipki-cli:unrevoke-cert`

     unrevoke certificate

   * `xipki-cli:loadtest-enroll`

     CA client enroll load test

   * `xipki-cli:loadtest-loadtest-revoke`

     CA client revoke load test

   * `xipki-cli:loadtest-template-enroll`

     CA client template enroll load test

   * xipki-scepclient-shell

     Provides OSGi commands

   * `xipki-scep:certpoll`

     poll certificate

   * `xipki-scep:enroll`

     enroll certificate via automic selected messageType

   * `xipki-scep:getcert`

     download certificate

   * `xipki-scep:getcert-qa`

     download certificate (only used for QA)

   * `xipki-scep:getcrl`

	 download CRL

   * `xipki-scep:pkcs-req`

	 enroll certificate via messageType PkcsReq

   * `xipki-enroll:renewal-req`

	 enroll certificate via messageType RenewalReq

   * `xipki-cli:update-req`

	 enroll certificate via messageType UpdateReq

* xipki-ocspclient-shell

  Provides OSGi commands
  
   * `xipki-ocsp:status`

	 request certificate status

   * `xipki-ocsp:loadtest-status`

	 OCSP Load test

* xipki-ocspqa-shell

  Provides OSGi commands

   * `xipki-qa:ocsp-status`

	 request certificate status (QA)
