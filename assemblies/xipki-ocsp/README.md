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

Deployment in Tomcat 8 and 9
----
1. Copy the sub-folders `bin`, `webapps`, `xipki` and `lib ` to the folder `${CATALINA_HOME}`.
  The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
  `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
2. (Optional) If you use database other than H2, PostgreSQL, MariaDB and MySQL, you need to download
   the JDBC driver to the folder `${CATALINA_HOME}/lib`.
3. (Optional) If you use database other than MariaDB and MySQL, you need to overwrite the
   configuration files `ca-db.properties`, `ocsp-db.properties` with those in the corresponding sub
   folder in `${CONTAINER_ROOT}/xipki/etc/ocsp/database`. Adapt the configuration.
4. (Optional, required only when OCSP cache will be activated) 
   To activate the OCSP cache:
   1) Uncomment the `responseCache` block in the configuration file `ocsp-responder.json`;
   2) In xipki-mgmt-cli, call
      `ca:sql --db-conf /path/to/ocsp-cache-db.json xipki/sql/ocsp-cache-init.sql`.
5. (Optional, required only when CRL is used as OCSPSore) 
   1) In xipki-mgmt-cli, call 
      `ca:sql --db-conf /path/to/ocsp-crl-db.json xipki/ocsp-init.sql`.
6. Add the line `org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=true`
   to the file `conf/catalina.properties` if OCSP over HTTP GET support is activated.
7. (optional) To accelerate the start process, append the following block to the property
`tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.

```
animal-sniffer-annotations*.jar,\
audit-*.jar,\
bcpkix-*.jar,\
bcprov-*.jar,\
bcutil-*.jar,\
ca-*.jar,\
certprofile-*.jar,\
datasource-*.jar,\
gson-*.jar,\
HikariCP-*.jar,\
license-*,jar,\
log4j-*.jar,\
mariadb-java-client-*.jar,\
mysql-connector-j-*.jar,\
ocsp-*.jar,\
postgresql-*.jar,\
scep-client-*.jar,\
security-*.jar,\
slf4j-*.jar,\
*pkcs11wrapper-*.jar,\
util-*.jar,\
xipki-tomcat-password-*.jar
```

- Start tomcat

```sh
  bin/start.sh
```

After the deployment
-----
You can use the openssl command to check whether the OCSP server answers as expected:
  `openssl ocsp -VAfile <PEM encoded OCSP signer certificate> -issuer <PEM encoded CA certificate> -url <URL> --serial <hex serial number>`
  
e.g.
  `openssl ocsp -VAfile ocsp-signer.pem -issuer ca.pem -url http://localhost:8080/ocsp/ -serial 0x123456789abc`
