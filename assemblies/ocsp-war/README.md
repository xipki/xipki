Migration
----
- From v5.3.0 - v5.3.6 to v5.3.7+
  - Remove the path prefix `xipki/` in all configuration files (`*.json`, `*.properties`, `*.cfg`) in the folder `xipki/`.
- For v5.3.7+, the folder `xipki` may be placed anywhere, it must be pointed to by the java property `XIPKI_BASE`.
  It can be configured as follows:
  - Tomcat: in the file `bin\setevn.*`
  - Jetty: in the file `start.ini`.

Prepare
-----
- The `xipki/etc/ocsp/ocsp-responder.json` is for the OCSP store type `xipki-ca-db`. If you use
  other type (namely `xipki-db`, `ejbca-db`, and `crl`), please copy the `ocsp-responder.json` from the sub-folder `xipki/etc/ocsp/example` to replace it.
- If you use CRL as OCSP store
    - Initialize the database which will be used to import the CRLs.
      `dbtool/bin/initdb.sh --db-schema xipki/sql/ocsp-init.xml --db-conf <xipki/etc/ocsp/database/ocsp-crl-db.properties`

- If you cache the OCSP responses
    - Initialize the database which will be used to store the cached OCSP responses.
      `dbtool/bin/initdb.sh --db-schema xipki/sql/ocsp-cache-init.xml --db-conf <xipki/etc/ocsp/database/ocsp-cache-db.properties`

- Adapt the configuration file `xipki/etc/ocsp-responder.json`.

Deployment in Tomcat 8 and 9
----
- Copy the files `setenv.sh` and `setenv.bat` in the folder `tomcat/bin` to the folder `${CATALINA_HOME}/bin`.
- Copy the sub-folders `webapps`, `xipki` and `lib ` to the folder `${CATALINA_HOME}`.
  The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
  `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
     - The OCSP responder is reachable under `http://<host>:<port>/ocsp/<path>`.
     - Rename `webapps/ocsp.war` to `webapps/ROOT.war` to change the URL to
       `http://<host>:<port>/<path>`.
     - The path can be changed by the `"servletPaths":["/..."]` in the configuration
       file `xipki/etc/ocsp-responder.json`.
     - With `webapps/ROOT.war` and `"servletPaths":["/"]` the OCSP responder is reachable
       under `http://<host>:<port>`.

- Add the line `org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=true`
   to the file `conf/catalina.properties` if OCSP over HTTP supported is activated.
- (optional) To accelerate the start process, append the following block to the property
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
util-*.jar
```
- Start tomcat
  <span style="color:red">**In the tomcat root folder ${CATALINA_HOME}** (Otherwise the file path cannot be interpreted correctly.)</span>

```sh
  bin/start.sh
```

  Note that the start script of tomcat does not set the working directory to the tomcat root directory, you have to start tomcat as above so that the XiPKI can retrieve files correctly.

- Shutdown tomcat
   Shutdown tomcat from any folder
```sh
  /path/to/tomcat/bin/shutdown.sh
```

Deployment in Jetty 9
----
- Copy the sub-folders `webapps` and `xipki` to the jetty root folder `${JETTY_BASE}`, and the files in sub-folder `lib` to the sub-folder `${JETTY_BASE}lib/ext` of jetty.
- Copy the sub-folder `xipki` to any position you wished.
- Configure the XIPKI_BASE by adding the following block to the file `start.ini`. Please configure
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

- Start jetty
   Start jetty from any folder
```sh
  /path/to/jetty/bin/jetty.sh start
```

- Shutdown jetty
   Shutdown jetty from any folder
```sh
  /path/to/jetty/bin/jetty.sh stop
```

After the deployment
-----
You can use the openssl command to check whether the OCSP server answers as expected:  
  `openssl ocsp -VAfile <PEM encoded OCSP signer certificate> -issuer <PEM encoded CA certificate> -url <URL> --serial <hex serial number>`
  
e.g.
  `openssl ocsp -VAfile ocsp-signer.pem -issuer ca.pem -url http://localhost:8080/ocsp/ -serial 0x123456789abc`
