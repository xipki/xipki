Prepare
-----
- The `xipki/etc/ocsp/ocsp-responder.json` is for the OCSP store type `xipki-ca-db`. If you use
  other type (namely `xipki-db`, `ejbca-db`, and `crl`), please copy the `ocsp-responder.json` from
  the corresponding sub-folder in `xipki/etc/ocsp/example` to replace it.
- Adapt the configuration file `xipki/etc/ocsp-responder.json`.

Access URL
-----
By default, the OCSP responder is reachable under `http://<host>:<port>/ocsp/<path>`.
 - Rename `webapps/ocsp.war` to `webapps/ROOT.war` to change the URL to
   `http://<host>:<port>/<path>`.
 - The path can be changed by the `"servletPaths":["/..."]` in the configuration
   file `xipki/etc/ocsp-responder.json`.
 - With `webapps/ROOT.war` and `"servletPaths":["/"]` the OCSP responder is reachable
   under `http://<host>:<port>`.

Deployment in Tomcat (8, 9 and 10)
----
1. Copy the war-files in `webapps` for tomcat 8/9 or `webapps-tomcat10on` for tomcat 10+,
   to the tomcat folder `${CATALINA_HOME}/webapps`:
    - In `${CATALINA_HOME}/webapps`, delete the folder `<some-app>` if the same named `<some-app>.war` file exists.
2. Copy (and overwrite if files already exist) the sub-folders `bin`, `xipki` and `lib `
   to the tomcat root folder `${CATALINA_HOME}`.
    - The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
      `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
    - In `${CATALINA_HOME}/lib`, if an old version of a jar file exists, remove it first.
3. (Optional) If you use database other than PostgreSQL, MariaDB and MySQL, you need to download
   the JDBC driver to the folder `${CATALINA_HOME}/lib`.
4. (Optional) If you use database other than H2, PostgreSQL, MariaDB and MySQL, you need to overwrite the
   configuration files `ca-db.properties`, `ocsp-db.properties` with those in the corresponding sub
   folder in `${CONTAINER_ROOT}/xipki/etc/ocsp/database`. Adapt the configuration.
5. (Optional, required only when OCSP cache will be activated) 
   To activate the OCSP cache:
   1) Uncomment the `responseCache` block in the configuration file `ocsp-responder.json`;
   2) In xipki-mgmt-cli, call
      `ca:sql --db-conf /path/to/ocsp-cache-db.json xipki/sql/ocsp-cache-init.sql`.
6. (Optional, required only when CRL is used as OCSPSore) 
   1) In xipki-mgmt-cli, call 
      `ca:sql --db-conf /path/to/ocsp-crl-db.json xipki/ocsp-init.sql`.
7. If OCSP over HTTP GET support is activated: Add attribute `encodedSolidusHandling="decode"` to the 
  `Connector`-element in the file `conf/server.xml`
8. (optional) To accelerate the start process, append the following block to the property
`tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.
9. If you have multiple tomcat instances, change the listing port for SHUTDOWN to be unique.

```
audit-*.jar,\
bcpkix-*.jar,\
bcprov-*.jar,\
bcutil-*.jar,\
datasource-*.jar,\
h2-*.jar \
HikariCP-*.jar,\
*pkcs11wrapper-*.jar,\
jackson-*.jar,\
license-*.jar,\
mariadb-*.jar,\
mysql-*.jar,\
ocsp-api-*.jar,\
ocsp-server-*.jar,\
password-*.jar,\
postgresql-*.jar,\
security-*.jar,\
servlet*-common-*.jar,\
util-*.jar,\
xipki-tomcat-password-*.jar
```

After the deployment
-----
You can use the openssl command to check whether the OCSP server answers as expected:
  `openssl ocsp -VAfile <PEM encoded OCSP signer certificate> -issuer <PEM encoded CA certificate> -url <URL> --serial <hex serial number>`
  
e.g.
  `openssl ocsp -VAfile ocsp-signer.pem -issuer ca.pem -url http://localhost:8080/ocsp/ -serial 0x123456789abc`
