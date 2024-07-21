## How to start XiPKI MGMT CLI

`bin/karaf`

* Note: You may access the CLI via SSH.
    * Configure karaf to start the SSH server.
        * Add `"ssh,"` to the field `featuresBoot` in the file `etc/org.apache.karaf.features.cfg`.
        * Configure the SSH server. See https://karaf.apache.org/manual/latest/security for details.
    * Start and stop karaf via `bin/start` and `bin/stop`.
    * Use a SSH client (either `bin/client` or any ssh client) to access the SSH service. Supported authentication
      methods are
        * username and password
        * public key (see Section `Managing authentication by key` at https://karaf.apache.org/manual/latest/security).

## Available Karaf Commands

Please refer to [commands.md](commands.md) for more details.

## Setup CA Server

* Start Management CLI.

  `bin/karaf`

* Setup CA (MGMT-CLI shall be on the same machine as the tomcat CA server)  
  Edit (e.g. subject and password) and execcute the script file `xipki/ca-setup/<folder>/setup-p12.script` 
  `source <script-file> {rsa|ec|dsa|sm2|eddsa} <tomcat-dir> [<xipki-dir>]`,  
  `xipki-dir` is optional and has default value `<tomca-dir>/xipki`.
  And `<folder>` is:
  * If the CA configuration is saved in the database (2 database instances are needed, 
      as specified in `caconf-db.properties` and `ca-db.properties`):
      * In case of using new keys and certificates:  
        `cacert-none-dbbased`
      * In case of using existing keys and certificates:  
        `cacert-present-dbbased`
  * If the CA configuration is read from configuration files (CA itself is not configurable, only 1
    database instance is needed, as specified in `ca-db.properties`):
      * In case of using new keys and certificates:  
        `cacert-none-filebased`
      * In case of using existing keys and certificates:  
        `cacert-present-filebased`

* (Optional) Generate Key and Certificate for OCSP Responder
    * If you wish to generate the signing key and certificate for the OCSP responder, in the Management CLI:  
      `source xipki/ca-setup/setup-ocsp-p12.script`.

* (Optional) Generate Key and Certificate for SCEP Gateway
    * If you wish to generate the signing key and certificate for the SCEP gateway, in the Management CLI:  
      `source xipki/ca-setup/setup-scep-p12.script`.

* Verify the installation, execute the command in the Management CLI:  
  `ca-info <ca-name>`
