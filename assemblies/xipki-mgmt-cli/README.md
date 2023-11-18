## Setup CA Server

* _(If error like "Identity or Certificate with label=mylabel already exists" occurs,
      you need to comment the line in the file `setup-p11.scrip` which generate the key (e.g. dsa-p11 ec-p11, rsa-p11, sm2-p12)
      or delete the existing key using command `delete-key-p11`)_.

* Start Management CLI.

  `bin/karaf`

* Setup CA (MGMT-CLI shall be on the same machine as the tomcat CA server)  
    `source xipki/ca-setup/<folder>/setup-{p11|p12}.script {rsa|ec|dsa|sm2|eddsa} <tomcat-dir> [<xipki-dir>]`,  
  `xipki-dir` is optional and has default value `<tomca-dir>/xipki`.
  And `<folder>` is:
    * If the CA configuration is saved in the database (2 database instances are needed, 
      as specified in `caconf-db.properties` and `ca-db.properties`):
      * In case of using new keys and certificates, in the Management CLI:  
        `cacert-none`
      * In case of using existing keys and certificates, in the Management CLI:  
        `cacert-present`
  * If the CA configuration is read from configuration files (CA itself is not configurable, only 1
    database instance is needed, as specified in `ca-db.properties`):
      * In case of using new keys and certificates, in the Management CLI:  
        `cacert-none-filebased`
      * In case of using existing keys and certificates, in the Management CLI:  
        `cacert-present-filebased`

* (Optional) Generate Key and Certificate for OCSP Responder
    * If you wish to generate the signing key and certificate for the OCSP responder, in the Management CLI:  
      `source xipki/ca-setup/setup-ocsp-{p11|p12}.script`.

* (Optional) Generate Key and Certificate for SCEP Gateway
    * If you wish to generate the signing key and certificate for the SCEP gateway, in the Management CLI:  
      `source xipki/ca-setup/setup-scep-p12.script`.

* Verify the installation, execute the command in the Management CLI:  
  `ca-info myca1`

* Note: You may access the Management CLI via SSH.
    * Configure karaf to start the SSH server.
        * Add `"ssh,"` to the field `featuresBoot` in the file `etc/org.apache.karaf.features.cfg`.
        * Configure the SSH server. See https://karaf.apache.org/manual/latest/security for details.
    * Use a SSH client (either `bin/client` or any ssh client) to access the SSH service. Supported authentication
      methods are
        * username and password
        * public key (see Section `Managing authentication by key` at https://karaf.apache.org/manual/latest/security).
