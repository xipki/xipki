Deployment in Tomcat (8, 9 and 10)
----
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
   `./install.sh -t <tomcat dir of proocol gaeway server>`.
