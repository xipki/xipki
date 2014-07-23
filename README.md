XiPKI
=========

eXtensible sImple Public Key Infrastructure

  - Certificate Authority (RFC 5280)
  - OCSP Responder (RFC 2560 and RFC 6960)
  - CMP (RFC 4210 and RFC 4211)
  - Support of direct and inderect CRL
  - Support of PKCS#12 and JKS keystore
  - Support of PKCS#11 devices, e.g. HSM, tested with nCipher of Thales
  - API to use customized key types, e.g. smartcard
  - API to specify customized certificate profiles
  - API to specify customized publisher, e.g. for LDAP and OCSP responder
  - Support of most popular databases
  - High performance
  - Java based, OS independent
  - OSGi-based
  - Health check embedded
  - Audit with syslog and slf4j
  
Version
----

1.0.0-SNAPSHOT

License
-----------

TBD

Owner
-----------
Dr. Lijun Liao (lijun.liao -A-T- gmail -D-O-T- com)

Prerequisite
------------
* JRE / JDK 1.7+
* For OpenJDK: none
* For Oracle JRE / JDK: JCE Unlimited Strength Jurisdiction Policy Files
*    (see http://www.oracle.com/technetwork/java/javase/downloads/index.html)
* For IBM JRE / JDK:  JCE Unlimited Jurisdiction Policy File
*    (see https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=jcesdk) 

Tested Platforms
----------------
* Database: DB2, H2, MySQL, Oracle, Oracle RAC and PostgreSQL
* HSM: Thales nCipher Solo (PCI Card) and nCipher Connect (network)
* JVM: OpenJDK JRE/JDK 7 and 8, Oracle JRE/JDK 7 and 8, IBM J9 JRE/JDK 7 and 8
* OS: CentOS, Fedora, Redhat, SLES, Ubuntu

Build and Assembly
------------------
* Get a copy of XiPKI code
  ```sh
  git clone git://github.com/xipki/xipki xipki
  ```

* Prepare
  * Install the third party artifacts that are not availablle in maven repositories
    
    In folder xipki/ext
    ```sh
    ./install.sh
    ```
 
* Build
  * Compile and install the artifacts
    
    In folder xipki
    ```sh
    mvn clean install
    ```
    
  * Assembly
  
    In folder xipki/dist
    ```sh
    mvn clean install
    ```

Install
-------

* Unpack the assembled file
 
    In destination folder of the installation
    ```sh
    tar xvf xipki-<version>.tar.gz
    ```
    The following steps use $XIPKI_HOME to point to the unpacked folder

* Adapt the database configuration (access rights read and write of database are required)

    ```sh
    $XIPKI_HOME/ca-config/ca-db.properties
    $XIPKI_HOME/ocsp-config/ocsp-publisher.properties
    ```

Run Demo
-----

* Initialize the databases

    In folder $XIPKI_HOME/sql
    ```sh
    ./reset.sh
    ```
* Delete folders $XIPKI_HOME/data and $XIPKI_HOME/output

* Start XiPKI
  
    In folder $XIPKI_HOME
    ```sh
    bin/karaf
    ```

    HSM devices of Thales, e.g. nCipher, uses preload to manage the PKCS#11 session. In this case, XiPKI should be started as follows
    ```sh
    preload bin/karaf
    ```

    If you have changed the content within folder $XIPKI_HOME/etc or $XIPKI_HOME/system, please delete the folder $XIPKI_HOME/data before starting XiPKI.

* If you use keys in PKCS#11 device

    Generate keypair with self-signed certificate in PKCS#11 device in karaf terminal
    ```sh
    features:install xipki-security-shell
    # RSA key, the default labels for demo are RCA1, SubCA1 and SubCAwithCRL1, and the default slot is 1
    keytool:rsa -slot <slot index> -key-label <label> [-pwd <password>]
    # EC key, the default labels for demo are RCA1-EC, SubCA1-EC and SubCAwithCRL1-EC, and the default slot is 1
    keytool:ec  -slot <slot index> -key-label <label> -curve secp256r1 [-pwd <password>]
    ```
* Run the pre-configured OSGi-commands in karaf terminal
  
    ```sh
    source <OSGi batch script file>
    ```
    The script file is
     * For RSA key in PKCS#12 file
     
      ```sh
      ca-demo/rsa-demo.script
      ```
       
     * For EC key in PKCS#12 file
     
      ```sh
      ca-demo/ec-demo.script
      ```
       
     * For RSA key in PKCS#11 device
     
      ```sh
      ca-demo/hsm-rsa-demo.script
      ```
       
     * For EC key in PKCS#11 device
     
      ```sh
      ca-demo/hsm-ec-demo.script
      ```
    The generated keys, certificates, CRLs are saved in folder $XIPKI_HOME/output
  

