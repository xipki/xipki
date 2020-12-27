Prepare
-----
- The `/opt/xipki/ocsp/etc/ocsp-responder.json` is for the OCSP store type `xipki-ca-db`. If you use
  other type (namely `xipki-db`, `ejbca-db`, and `crl`), please copy the `ocsp-responder.json` from
  the corresponding sub-folder in `/opt/xipki/ocsp/etc/example` to replace it.
- If you use CRL as OCSP store
    - Initialize the database which will be used to import the CRLs.
      In dbtool, call
      `bin/initdb.sh --db-schema /opt/xipki/ocsp/sql/ocsp-init.xml --db-conf /opt/xipki/ocsp/etc/database/ocsp-crl-db.properties`

- If you cache the OCSP responses
    - Initialize the database which will be used to store the cached OCSP responses.
      In dbtool, call
      `bin/initdb.sh --db-schema /opt/xipki/ocsp/sql/ocsp-cache-init.xml --db-conf /opt/xipki/ocsp/etc/database/ocsp-cache-db.properties`

- Adapt the configuration file `/opt/xipki/ocsp/etc/ocsp-responder.json`.

Access URL
-----
By default, the OCSP responder is reachable under `http://<host>:<port>/ocsp/<path>`.
 - Rename `webapps/ocsp.war` to `webapps/ROOT.war` to change the URL to
   `http://<host>:<port>/<path>`.
 - The path can be changed by the `"servletPaths":["/..."]` in the configuration
   file `/opt/xipki/ocsp/etc/ocsp-responder.json`.
 - With `webapps/ROOT.war` and `"servletPaths":["/"]` the OCSP responder is reachable
   under `http://<host>:<port>`.

Deployment in Tomcat 8 and 9
----
1. Copy the sub-folder `xipki` to the folder `/opt`.
2. Copy the sub-folders `webapps` and `lib ` to the tomcat root folder `${CATALINA_HOME}`.
3. Download the `bcprov-jdk15on-<version>.jar` and `bcpkix-jdk15on-<version>.jar` from
  [BouncyCastle Latest Release](https://www.bouncycastle.org/latest_releases.html) to the folder
  `${CATALINA_HOME}/lib`. The cryptographic libraries are not included since we need the latest release.
4. (Optional) If you use database other than MariaDB and MySQL, you need to overwrite the
   configuration templates with those in the corresponding sub folder in `/opt/xipki/ocsp/etc/database`,
   and download the JDBC driver to the folder `${CATALINA_HOME}/lib`.
5. Add the line `org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=true`
   to the file `conf/catalina.properties` if OCSP over HTTP supported is activated.
6. (optional) To accelerate the start process, append the following block to the property
`tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.

```
bcprov-*.jar,\
bcpkix-*.jar,\
datasource-*.jar,\
fastjson-*.jar,\
HikariCP-*.jar,\
log4j-*.jar,\
mariadb-java-client-*.jar,\
ocsp-*.jar,\
password-*.jar,\
postgresql-*.jar,\
security-*.jar,\
slf4j-*.jar,\
sunpkcs11-wrapper-*.jar,\
*-tinylog.jar,\
tinylog*.jar,\
util-*.jar
```
- Start tomcat
  <span style="color:red">**In the tomcat root folder ${CATALINA_HOME}** (Otherwise the file path
  cannot be interpreted correctly.)</span>

```sh
  bin/start.sh
```

  Note that the start script of tomcat does not set the working directory to the tomcat root
  directory, you have to start tomcat as above so that the XiPKI can retrieve files correctly.


After the deployment
-----
You can use the openssl command to check whether the OCSP server answers as expected:
  `openssl ocsp -VAfile <PEM encoded OCSP signer certificate> -issuer <PEM encoded CA certificate> -url <URL> --serial <hex serial number>`
  
e.g.
  `openssl ocsp -VAfile ocsp-signer.pem -issuer ca.pem -url http://localhost:8080/ocsp/ -serial 0x123456789abc`
