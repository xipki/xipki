Deployment in Tomcat (10 and 11)
----
1. (Optional) Replace
  `org.xipki.security.auth.SimpleRequestorAuthenticator` with your own
   implementation in the following files:
  - `xipki/etc/cmp-gateway.json`
  - `xipki/etc/est-gateway.json`
  - `xipki/etc/rest-gateway.json`
  - `xipki/etc/scep-gateway.json`
  After the replacement, you may delete configuration file 
  `xipki/etc/simple-requestors.json`.

2. (Optional) If SCEP is supported:  
   You need to have a SCEP certificate with private key. For the demo you may generate this
   certificate in the `xipki-mgmt-cli` via the command:  
   `source xipki/ca-setup/setup-scep-p12.script`,
   and then copy the generated file `scep1.p12` to the folder `xipki/keycerts`.
3. (Optional) If ACME is supported (The server URL is https://<host>:<HTTPS-port>/acme/ or http://<host>:<HTTP-port>/acme/.):  
   1. Initialize the database configured in `acme-db.properties`:    
      In xipki-mgmt-cli, call `ca:sql --db-conf /path/to/acme-db.properties xipki/sql/acme-init.sql`
   2. Adapt the `acme`-block in the `tomcat/xipki/etc/acme-gateway.json`.
4. Execute the command  
   `./install.sh -t <tomcat dir of proocol gaeway server>`.
