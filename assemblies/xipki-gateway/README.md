Deployment in Tomcat (8, 9 and 10)
----
1. (Optiona) If SCEP is supported:  
   You need to have a SCEP server certificate with private key. For the demo you may generate this
   certificate in the `xipki-mgmt-cli` via the command:  
   `ca:enroll-cert --ca myca1 --subject "CN=scep responder" --profile scep --key-password CHANGEIT --out output/scep1.der`,
   and then copy the generated file `scep1.p12` to the folder `xipki/keycerts`.
2. (Optional) If ACME is supported (The server URL is https://<host>:<HTTPS-port>/acme/ or http://<host>:<HTTP-port>/acme/.):  
   1. (Optional) If you use database other than H2, PostgreSQL, MariaDB and MySQL:
      Download the JDBC driver to the folder `tomcat/lib`.  
   2. (Optional) If you use database other than MariaDB and MySQL:  
      Overwrite the configuration files `acme-db.properties` in the folder `tomcat/xipki/etc/acme/database`
      with those in the corresponding sub folder.
   3. Adapt the database configuration `acme-db.properties`.
   4. Create new database configured in `acme-db.properties`.
   5. Initialize the database configured in `acme-db.properties`:    
      In xipki-mgmt-cli, call `ca:sql --db-conf /path/to/acme-db.properties xipki/sql/acme-init.sql`
   6. Adapt the `acme`-block in the `tomcat/xipki/etc/acme-gateway.json`.
5. Execute the command  
   `./install.sh [OPTION]... -t <tomcat dir of proocol gaeway server>`,  
   where OPTION specifies which protocols shall be installed. An empty OPTION indicates to install
   all protocols.