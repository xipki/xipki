Prepare
-----
- The `xipki/etc/ocsp/ocsp-responder.json` is for the OCSP store type `xipki-ca-db`. If you use
  other type (namely `xipki-db`, `ejbca`, and `crl`), please copy the `ocsp-responder.json` from the sub-folder `xipki/etc/ocsp/example` to replace it. 
- If you use CRL as OCSP store
    - Initialize the database which will be used to import the CRLs.
      `dbtool/bin/initdb.sh --db-schema xipki/sql/ocsp-init.xml --db-conf <xipki/etc/ocsp/database/ocsp-crl-db.properties`

- If you cache the OCSP responses
    - Initialize the database which will be used to store the cached OCSP responses.
      `dbtool/bin/initdb.sh --db-schema xipki/sql/ocsp-cache-init.xml --db-conf <xipki/etc/ocsp/database/ocsp-cache-db.properties`

- Adapt the configuration file `xipki/etc/ocsp-responder.json`.

Deployment in Tomcat 8 and 9
----
- Copy the sub-folders `webapps`, `xipki` and `lib ` to the tomcat root folder
     - The OCSP responder is reachable under `http://<host>:<port>/ocsp/<path>`.
     - Rename `webapps/ocsp.war` to `webapps/ROOT.war` to change the URL to
       `http://<host>:<port>/<path>`.
     - The path can be changed by the `"servletPaths":["/..."]` in the configuration
       file `xipki/etc/ocsp-responder.json`.
     - With `webapps/ROOT.war` and `"servletPaths":["/"]` the OCSP responder is reachable
       under `http://<host>:<port>`.
- Add the line `org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=true`
   to the file `conf/catalina.properties` if OCSP over HTTP supported is activated.
- (optiona) add `maxKeepAliveRequests="-1"` to the HTTP Connector in the file `conf/server`.
   This step is only required for the benchmark test.
- (optional) To accelerate the start process, append the following block to the property
`tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.

```
audit-*.jar,\
bcprov-jdk15on-*.jar,\
bcpkix-jdk15on-*.jar,\
ca-*.jar,\
certprofile-xijson-*.jar,\
datasource-*.jar,\
fastjson-*.jar,\
HikariCP-*.jar,\
log4j-core-*.jar,\
log4j-api-*.jar,\
log4j-slf4j-impl-*.jar,\
mariadb-java-client-*.jar,\
ocsp-api-*.jar,\
ocsp-server-*.jar,\
password-*.jar,\
postgresql-*.jar,\
scep-client-*.jar,\
security-*.jar,\
sunpkcs11-wrapper-*.jar,\
syslog-java-client-*.jar,\
util-*.jar
```
- Start tomcat
  In the tomcat root folder

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
- Copy the sub-folders `webapps` and `xipki` to the jetty root folder, and the files in sub-folder `lib` to the sub-folder `lib/ext` of jetty.
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
