XiPKI
=========

eXtensible sImple Public Key Infrastructure

  - Certificate Authority
  - OCSP Responder
  - Support of direct and inderect CRL
  - Support of PKCS#12 and PKCS#11 devices
  - API to use customized key types, e.g. smartcard
  - API to specify customized certificate profiles
  - API to specify customized publisher, e.g. for LDAP and OCSP responder
  - Support of most popular databases
  - High performance
  - Java based, OS independent
  - OSGi-based
  
Version
----

1.0.0

License
-----------

Apache License 2.0

Installation
------------
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

* Install
  * Unpack the assembled file
 
    In destination folder of the installation
    ```sh
    tar xvf xipki-<version>.tar.gz
    ```
    The following steps use $XIPKI_HOME to point to the unpacked folder

  * Copy the JDBC drivers to folder, currently only databas types MySQL, DB2, Oracle and PostgreSQL 
    are configured. The JDBC driver of MySQL is contained and this step can be skipped.

    ```sh
    $XIPKI_HOME/lib/ext
    ```

  * Configure one database for the CA (required) and one for the OCSP responder (optional)
  * Adapt the database configuration (access rights read and write of database are required)
    ```sh
    $XIPKI_HOME/ca-config/ca-db.properties
    $XIPKI_HOME/ocsp-config/ocsp-db.properties
    ```
  * Initialize the dabases

    In folder $XIPKI_HOME/sql
    ```sh
    ./reset.sh
    ```

  * Start XiPKI as daemon
  
    In folder $XIPKI_HOME
    ```sh
    bin/start    
    ```
    If you have changed the content within folder $XIPKI_HOME/etc or $XIPKI_HOME/system, please delete the folder $XIPKI_HOME/data before starting XiPKI.
  * Log into the XiPKI via SSH
    ```sh
    ssh -p 8101 admin@localhost
    ```
    with username 'admin' and password 'admin'. SSH users are configured in $XIPKI_HOME/etc/users.properties

  * If you use keys in PKCS#11 device
  
    Generate keypair with self-signed certificate in PKCS#11 device
    ```sh
    features:install xipki-security-shell
    # RSA key, the default label for demo is RCA1, and default slot is 1
    keytool:rsa -slot <slot index> -key-label <label> 
    # EC key, the default label for demo is RCA1-EC, and default slot is 1
    keytool:ec  -slot <slot index> -key-label <label> -curve secp256r1
    ```
  * Run the demo
  
    ```sh
    source <OSGi batch script file>
    ```
    The script file is
     * For RSA key in PKCS#12 file
     
      ```sh
      ca-demo/demo.script
      ```
       
     * For EC key in PKCS#12 file
     
      ```sh
      ca-demo/ec-demo.script
      ```
       
     * For RSA key in PKCS#11 device
     
      ```sh
      ca-demo/hsm-demo.script
      ```
       
     * For EC key in PKCS#11 device
     
      ```sh
      ca-demo/hsm-ec-demo.script
      ```
    The generated keys, certificates, CRLs are saved in folder $XIPKI_HOME/output  
  

