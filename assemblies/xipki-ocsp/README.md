Deployment in Tomcat (10 and 11)
----
1. (Optional) If you use OCSP store type other than `xipki-ca-db`, 
   (namely `xipki-db`, `ejbca-db`, and `crl`):  
   Overwrite the `ocsp-responder.json` in `tomcat/xipki/etc/ocsp/` from the sub-folder in 
   `tomca/xipki/etc/ocsp/example`.
2. Adapt the configuration file `tomcat/xipki/etc/ocsp-responder.json`.
3. (Optional) If you use database other than H2, PostgreSQL, MariaDB and MySQL:
   Download the JDBC driver to the folder `tomcat/lib`.
4. (Optional) If you use database other than MariaDB and MySQL:  
   Overwrite the configuration files `*-db.properties` in the folder `tomcat/xipki/etc/ca/database`
   with those in the corresponding sub folder.
5. Adapt the database configurations `*-db.properties`, which are referenced in 
   `tomcat/xipki/etc/ocsp-responder.json`, in the folder `tomcat/xipki/etc/ca/database`.
6. Create new databases configured in Step 5.
7. (Optional), required only when OCSP cache will be activated):  
   To activate the OCSP cache:
    1) Uncomment the `responseCache` block in the configuration file `ocsp-responder.json`;
    2) In xipki-mgmt-cli, call
       `ca:sql --db-conf /path/to/ocsp-cache-db.json xipki/sql/ocsp-cache-init.sql`.
8. (Optional), required only when CRL is used as OCSPSore:  
   1) In xipki-mgmt-cli, call 
      `ca:sql --db-conf /path/to/ocsp-crl-db.json xipki/ocsp-init.sql`.
9. Execute the command  
   `./install.sh -t <tomcat dir of OCSP server>`

After the deployment
-----
You can use the openssl command to check whether the OCSP server answers as expected:
  `openssl ocsp -VAfile <PEM encoded OCSP signer certificate> -issuer <PEM encoded CA certificate> -url <URL> --serial <hex serial number>`
  
e.g.
  `openssl ocsp -VAfile ocsp-signer.pem -issuer ca.pem -url http://localhost:8080/ocsp/ -serial 0x123456789abc`

Access URL
-----
By default, the OCSP responder is reachable under `http://<host>:<port>/ocsp/<path>`.
- Rename `webapps/ocsp.war` to `webapps/ROOT.war` to change the URL to
  `http://<host>:<port>/<path>`.
- The path can be changed by the `"servletPaths":["/..."]` in the configuration
  file `xipki/etc/ocsp-responder.json`.
- With `webapps/ROOT.war` and `"servletPaths":["/"]` the OCSP responder is reachable
  under `http://<host>:<port>`.
