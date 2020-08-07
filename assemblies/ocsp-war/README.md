Migration
----
- From v5.3.0 - v5.3.6 to v5.3.7+
  - Remove the path prefix `xipki/` in all configuration files (`*.json`, `*.properties`, `*.cfg`)
    in the folder `xipki/`.

Prepare
-----
- The `xipki/etc/ocsp/ocsp-responder.json` is for the OCSP store type `xipki-ca-db`. If you use
  other type (namely `xipki-db`, `ejbca-db`, and `crl`), please copy the `ocsp-responder.json` from
  the corresponding sub-folder in `xipki/etc/ocsp/example` to replace it.
- If you use CRL as OCSP store
    - Initialize the database which will be used to import the CRLs.
      In dbtool, call
      `bin/initdb.sh --db-schema sql/ocsp-init.xml --db-conf /path/to/ocsp-crl-db.properties`

- If you cache the OCSP responses
    - Initialize the database which will be used to store the cached OCSP responses.
      In dbtool, call
      `bin/initdb.sh --db-schema sql/ocsp-cache-init.xml --db-conf /path/to/ocsp-cache-db.properties`

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
1. Copy the files `setenv.sh` and `setenv.bat` in the folder `tomcat/bin` to the folder
  `${CATALINA_HOME}/bin`.
2. Copy the sub-folders `webapps`, `xipki` and `lib ` to the folder `${CATALINA_HOME}`.
  The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
  `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
3. Download the `bcprov-jdk15on-<version>.jar` and `bcpkix-jdk15on-<version>.jar` from
  [BouncyCastle Latest Release](https://www.bouncycastle.org/latest_releases.html) to the folder
  `${CATALINA_HOME}/lib`. The cryptographic libraries are not included since we need the latest release.
4. (Optional) If you use database other than MariaDB and MySQL, you need to overwrite the
   configuration templates with those in the corresponding sub folder in `${CONTAINER_ROOT}/xipki/etc/ocsp/database`,
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

Deployment in Jetty 9
----
1. Copy the sub-folders `webapps` and `xipki` to the jetty root folder `${JETTY_BASE}`, and the files
  in sub-folder `lib` to the sub-folder `${JETTY_BASE}lib/ext` of jetty.
2. Download the `bcprov-jdk15on-<version>.jar` and `bcpkix-jdk15on-<version>.jar` from
  [BouncyCastle Latest Release](https://www.bouncycastle.org/latest_releases.html) to the folder
  `${JETTY_HOME}/lib/ext`. The cryptographic libraries are not included since we need the latest release.
3. (Optional) If you use database other than MariaDB and MySQL, you need to overwrite the
   configuration templates with those in the corresponding sub folder in `${JETTY_BASE}/xipki/etc/ocsp/database`,
   and download the JDBC driver to the folder `${JETTY_BASE}/lib/ext`.   
4. Configure the XIPKI_BASE by adding the following block to the file `start.ini`. Please configure
  XIPKI_BASE correctly.

```sh
--module=https
XIPKI_BASE=<path/to/folder/xipki>
```
- For jetty 9.4.15 - 9.4.18
  There is a bug in these versions, you need to remove the `default="HTTPS"` block from the
  line `EndpointIdentificationAlgorithm` in the file `etc/jetty-ssl-context.xml`, namely from

```
 <Set name="EndpointIdentificationAlgorithm"><Property name="jetty.sslContext.endpointIdentificationAlgorithm" default="HTTPS"/></Set>
```
to

```
 <Set name="EndpointIdentificationAlgorithm"><Property name="jetty.sslContext.endpointIdentificationAlgorithm"/></Set>
```

After the deployment
-----
You can use the openssl command to check whether the OCSP server answers as expected:
  `openssl ocsp -VAfile <PEM encoded OCSP signer certificate> -issuer <PEM encoded CA certificate> -url <URL> --serial <hex serial number>`
  
e.g.
  `openssl ocsp -VAfile ocsp-signer.pem -issuer ca.pem -url http://localhost:8080/ocsp/ -serial 0x123456789abc`
