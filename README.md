# XiPKI
XiPKI (e**X**tensible s**I**mple **P**ublic **K**ey **I**nfrastructure) is
a highly scalable and high-performance open source PKI (CA and OCSP responder).

## License
* The Apache Software License, Version 2.0

## Owner
Lijun Liao (lijun.liao -A-T- gmail -D-O-T- com), [LinkedIn](https://www.linkedin.com/in/lijun-liao-644696b8)

## Support
Just drop me an email.

## Prerequisite
* JRE / JDK 8
  * [Oracle](http://www.oracle.com/technetwork/java/javase/downloads/index.html) / [Zulu](https://www.azul.com/downloads/zulu/): [JCE Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/index.html)
  * OpenJDK (via linux package manager): No policy files are required
## Tested Platforms

- Database: DB2, H2, HSQLDB, MariaDB, MySQL, Oracle, PostgreSQL
- HSM: [Softhsm v1 & v2](https://www.opendnssec.org/download/packages/),
  [Smartcard HSM EA+](http://www.smartcard-hsm.com/features.html#usbstick),
  Thales nCipher Connect, Thales nCipher Solo, Utimaco Se
- JVM: OpenJDK JDK/JRE 8, Oracle JDK/JRE 8, Zulu JDK 8
- OS: Linux (CentOS, Fedora, Redhat, SLES, Ubuntu, Raspbian)

## Get Started

### JAVA_HOME
  Set the environment variable `JAVA_HOME` to point to root directory of the to
  the JRE/JDK installation.

### CA and OCSP Responder

Download the binary package `xipki-pki-<version>.tar.gz` from
[XiPKI releases](https://github.com/xipki/xipki/releases).

Only if you want to use the development version, build it from source code as
follows.

- Get a copy of project code
  ```sh
  git clone https://github.com/xipki/xipki
  ```
- Build the project

  In folder `xipki`
  ```sh
  mvn clean install -Pdist -DskipTests
  ```

  Then you will find `xipki-pki-*.tar.gz` in the directory
  `dist/xipki-pki/target`.

## Configure the CA and OCSP Responder

1. Unpack the binary `xipki-pki-<version>.tar.gz` file

    ```sh
    tar xvf xipki-pki-<version>.tar.gz
    ```
    The following steps use `$XIPKI_HOME` to point to the unpacked root folder.
    
    **The next steps can be skipped if you just want to try out.**

2. Adapt the database configuration (optional)

  This step may be skipped if you just want to try out XiPKI.

  In the folder `$XIPKI_HOME/xipki/ca-config`, copy the CA database
  configuration template file `example/ca-db.properties-<type>` to
  `ca-db.properties`, and the OCSP database configuration file
  `example/ocsp-db.properties-<type>` to `ocsp-db.properties`, and then adapt
  them.

  The database users must have both the read and right permissions.

3. Configure PKCS#11 device (optional)

   This step is only required if the real PKCS#11 device instead of the emulator
   is used.

  * In file etc/org.xipki.security.pkcs11.cfg, change the pkcs11.confFile as
    follows:

    ```sh
    pkcs11.confFile = xipki/security/pkcs11-conf-hsm.xml

    #pkcs11.confFile = xipki/security/pkcs11-conf-emulator.xml
    ```
  * In file xipki/security/pkcs11-conf-hsm.xml, change the PKCS#11
    configuration.

4. Configure how to handle SSL client certificate (optional)

  This step is only required if the CA is behind a reverse proxy apache httpd.

  * In file etc/org.xipki.ca.server.cfg, change the sslCertInHttpHeader as
    follows:

    ```sh
    sslCertInHttpHeader = true
    ```

  * configure the proxy to forward the headers via mod_proxy with the following
    configuration

    ```sh
    RequestHeader set SSL_CLIENT_VERIFY "%{SSL_CLIENT_VERIFY}s"
    RequestHeader set SSL_CLIENT_CERT "%{SSL_CLIENT_CERT}s"
    ```

    For more details please refer to

      * [Jetty/Howto/Configure mod proxy](https://wiki.eclipse.org/Jetty/Howto/Configure_mod_proxy)
      * [Jetty: Tricks to do client certificate authentications behind a reverse proxy](http://www.zeitoun.net/articles/client-certificate-x509-authentication-behind-reverse-proxy/start)
      * [Apache Module mod_ssl](http://httpd.apache.org/docs/2.2/mod/mod_ssl.html#envvars)

5. Add JDBC drivers (optional)

  This step is only required if you want to use database other than H2.

Database Software | Driver | Download URL
------------------|--------|-------------
Oracle | ojdbc7.jar | http://www.oracle.com/technetwork/database/features/jdbc/jdbc-drivers-12c-download-1958347.html
DB2 | db2jcc4.jar |
MySQL | mysql-connector-java.jar | https://dev.mysql.com/downloads/connector/j, In debian, use the `mysql-connector-java.jar` from the package `libmysql-java` (e.g. under /usr/share/java/mysql-connector-java.jar)
MariaDB | mariadb-java-client-`<version>`.jar | https://downloads.mariadb.org/connector-java/
PostgreSQL | postgresql-`<version>`.jar | https://jdbc.postgresql.org/download.html
HSQLDB | hsqldb-`<version>`.jar | http://hsqldb.org

  * Copy the jar file to the folder `lib/jdbc`.

  * Append the bundle URL to the feature `xipki-jdbc` in the file
    `lib/jdbc/features.xml`, And comment the unneeded jdbc drivers.

    ```sh
    <feature name="xipki-jdbc" description="JDBC drivers">
      ...
      <bundle start-level="75">file:lib/jdbc/....jar</bundle>
    </feature>
    ```
    Note that if the bundle is not an OSGi-bundle, the URL must be prepended by
    the prefix "wrap:". In general, a bundle contains the header Export-Package
    in the manifest file META-INF/MANIFEST.MF.

    ```sh
    <feature name="xipki-jdbc" description="JDBC drivers">
      ...
      <bundle start-level="75">wrap:file:..</bundle>
    </feature>
    ```

6. Use the native features (optional)

  In Linux-X86_64 and OSX-X56_64 environment, openssl as SSL engine and the OS
  native transport mechanism (Epoll in Linux and KQueue in OSX) can be used in
  XiPKI. Please refer to the configuration file
  `etc/org.apache.karaf.features.cfg` for more details.


## Setup CA and OCSP Responder

1. Prepare the configuration and scripts

  This step is not required if you setup a new root CA (self-signed) using
  RSA keys which will be generated during the installation process, and the keys
  are saved in PKCS#12 keystore.

  - If you use the existing CA certificate, OCSP Responder certificate, and SCEP
    certificate

     - Copy the certificates to the directory to `xipki/setup/keycerts`.

     - In case of the key and certificate are saved in PKCS#12 keystore file,
      copy the PKCS#12 files to the directory `xipki/setup/keycerts`.
      Note that the key and certificate must be under the same alias in keystore.

     - Adapt the CA configuration file `xipki/setup/cacert-present-ca-conf.xml`

 - If you use non-RSA keys (e.g. EC and DSA) or PKCS#11 device, adapt the CA
   configuration file `xipki/setup/cacert-none-ca-conf.xml` and the scripts in
   `xipki/setup/cacert-none-setup.script`

2. Start XiPKI

2.1 Alternative: Start XiPKI as a normal application

In folder `xipki-pki-<version>`
```sh
bin/karaf
```

HSM devices of Thales, e.g. nCipher, can use Thales preload to manage the
PKCS#11 sessions. In this case, XiPKI should be started as follows
```sh
preload bin/karaf
```
2.2 Alternative: Start XiPKI as a daemon

The same as Alternative 1 except the command `bin/start` instead of
`bin/karaf` is used.
    
For both alternatives, if the content within folder `etc` or `system` has been
changed, please delete the folder `data/cache` before starting XiPKI.

3. Setup the CA and OCSP responder

3.1. In case XiPKI is started as a normal application 

 * In case of using new keys and certificates, in OSGi console:  
   `source file:./xipki/setup/cacert-none/setup-*.script`
   where * is place holder.

 * In case of using existing keys and certificates, in OSGi console:  
    `source file:./xipki/setup/cacert-present/setup-*.script`
   where * is place holder.

 * Verify the installation, execute the OSGi command  
   `ca-info MYCA1`

3.2. In case XiPKI is started as a daemon 

 * In case of using new keys and certificates, in shell console:
   `bin/client "sourcefile:./xipki/setup/cacert-none/setup-*.script"`

 * In case of using existing keys and certificates, in shell console:  
   `bin/client "sourcefile:./xipki/setup/cacert-present/setup*.script"`

4. Enroll/Revoke Certificate and Get CRL via Shell (optional)

- The following shell script demonstrates how to enroll and revoke certificates, and how to get the current CRL:
  `xipki/client-script/rest.sh`
  
  Note that this script tells CA to generate real certificates. DO NOT use it in the production environment.

## Enroll/Revoke Certificate

* SCEP  
  Any SCEP client. XiPKI provides also a SCEP client in
  [xipki/xiscep](https://github.com/xipki/xiscep).

* XiPKI SDK  
  The SDK ([xipki/xisdk](https://github.com/xipki/xisdk))
  provides both the full-featured CA client and the lite version to enroll and
  revoke certificates via CMP.

  The binary `xipki-sdk-<version>`.tar.gz contains several example scripts in the folder xipki/client-script.
  They can be executed in the karaf shell as follows:  
  - `source file:./xipki/client-script/cmp-client.script` 
  - `source file:./xipki/client-script/rest-client.script`
  - `source file:./xipki/client-script/scep-client.script`

* REST API  
  The shell script `xipki/client-script/rest.sh` of the `xipki-pki` demonstrates
  the use of REST API.

Karaf Features
-----

The karaf feature can be installed via the command
`feature:install -r <feature name>` (the flag -r disables the refreshing of
already installed bundles) and uninstalled in the OSGi console via the command
`feature:uninstall <feature name>`. The possible feature can be auto-completed
by typing the `TAB` key.

A list of all available XiPKI features can be retrieved via the command
`feature:list  | grep xipki` in OSGi console.

For details of karaf features please refer to
[Karaf Manuel Provisioning](https://karaf.apache.org/manual/latest/provisioning)

Karaf Commands
-----
Please refer to [commands.md](commands.md) for more details.

Components
-----
- CA (Certification Authority)

  - X.509 Certificate v3 (RFC 5280)
  - X.509 CRL v2 (RFC 5280)
  - SCEP (draft-gutmann-scep-00, draft-nourse-scep-23)
  - EN 319 411 (eIDAS)
  - EN 319 412 (eIDAS)
  - Supported databases: DB2, H2, HSQLDB, MariaDB, MySQL, Oracle
  - Direct and indirect CRL
  - FullCRL and DeltaCRL
  - Customized extension to embed certificates in CRL
  - CMP (RFC 4210 and RFC 4211)
  - API to specify customized certificate profiles
  - Support of XML-based certificate profile
  - API to specify customized publisher, e.g. for LDAP and OCSP responder
  - Support of publisher for OCSP responder
  - Signature algorithms of certificates
    - SM3withSM2
    - SHA3-*withRSA: where * is 224, 256, 384 and 512
    - SHA3-*withRSAandMGF1: where * is 224, 256, 384 and 512
    - SHA3-*withECDSA: where * is 224, 256, 384 and 512
    - SHA3-*withDSA: where * is 224, 256, 384 and 512
    - SHA*withRSA: where * is 1, 224, 256, 384 and 512
    - SHA*withRSAandMGF1: where * is 1, 224, 256, 384 and 512
    - SHA*withECDSA: where * is 1, 224, 256, 384 and 512
    - SHA*withPlainECDSA: where * is 1, 224, 256, 384 and 512
    - SHA*withDSA: where * is 1, 224, 256, 384 and 512
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
    - SubjectDirectoryAttributes (RFC 3739)
    - SubjectInfoAccess (RFC 5280)
    - SubjectKeyIdentifier (RFC 5280)
    - TLSFeature (RFC 7633)
    - ValidityModel (German national standard CommonPKI)
 - Management of multiple CAs in one software instance
 - Support of database cluster
 - Multiple software instances (all can be in active mode) for the same CA
 - Native support of management of CA via embedded OSGi commands
 - API to specify CA management, e.g. GUI
 - Database tool (export and import CA database) simplifies the switch of
   databases, upgrade of XiPKi and switch from other CA system to XiPKI CA
 - Client to enroll, revoke, unrevoke and remove certificates, to generate and
   download CRLs
 - All configuration of CA except those of databases is saved in database

- OCSP Responder
  - OCSP Responder (RFC 2560 and RFC 6960)
  - Support of Common PKI 2.0
  - Management of multiple certificate status sources
  - Support of certificate status source published by XiPKI CA
  - Support of certificate status source CRL and DeltaCRL
  - API to support proprietary certificate sources
  - Support of both unsigned and signed OCSP requests
  - Multiple software instances (all can be in active mode) for the same OCSP
    signer and certificate status sources.
  - Supported databases: DB2, H2, HSQLDB, MariaDB, MySQL, Oracle
  - Database tool (export and import OCSP database) simplifies the switch of
    databases, upgrade of XiPKi and switch from other OCSP system to XiPKI OCSP.
  - Client to send OCSP request

- Key Tool (for both PKCS#12 and PKCS#11 tokens)
  - Generating keypairs of RSA, EC and DSA in token
  - Deleting keypairs and certificates from token
  - Updating certificates in token
  - Generating CSR (PKCS#10 request)
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
  - Support of PBE (password based encryption) password resolver
     - All passwords can be encrypted by the master password
  - Support of OBF (as in jetty) password resolver
