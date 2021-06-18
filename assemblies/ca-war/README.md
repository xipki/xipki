Migration
----
- From v5.3.0 - v5.3.6 to v5.3.7+
  - Remove the path prefix `xipki/` in all configuration files (`*.json`, `*.properties`, `*.cfg`)
    in the folder `xipki/`.

Deployment in Tomcat 8 and 9
----
1. Copy the files `setenv.sh` and `setenv.bat` in the folder `tomcat/bin` to the folder
  `${CATALINA_HOME}/bin`.
2. Copy the sub-folders `webapps`, `xipki` and `lib ` to the tomcat root folder `${CATALINA_HOME}`.
  The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
  `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
3. Download the `bcutil-jdk15on-<version>.jar`, `bcprov-jdk15on-<version>.jar` and `bcpkix-jdk15on-<version>.jar` from
  [BouncyCastle Latest Release](https://www.bouncycastle.org/latest_releases.html) to the folder
  `${CATALINA_HOME}/lib`. The cryptographic libraries are not included since we need the latest release.
4. (Optional) If you use database other than MariaDB and MySQL, you need to overwrite the
   configuration templates with those in the corresponding sub folder in `${CONTAINER_ROOT}/xipki/etc/ca/database`,
   and download the JDBC driver to the folder `${CATALINA_HOME}/lib`.
5. Adapt the database configurations `${CONTAINER_ROOT}/xipki/etc/ca/database/ca-db.properties`.
6. Create new databases configured in Step 5.
7. Initialize the databases configured in Step 5.
   In dbtool, call `bin/initdb.sh --db-schema sql/ca-init.xml --db-conf /path/to/ca-db.properties`
8. Configure the TLS listener in the file `${CATALINA_HOME}conf/server.xml`
   - Use NIO connector
```sh
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               connectionTimeout="4000">
        <SSLHostConfig
                certificateVerification="optional"
                protocols="TLSv1.2"
                ciphers="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                truststoreFile="${XIPKI_BASE}/keycerts/tlskeys/ca/tls-ca-cert.p12"
                truststorePassword="1234"
                truststoreType="PKCS12">
            <Certificate
                         certificateKeystoreFile="${XIPKI_BASE}/keycerts/tlskeys/server/tls-server.p12"
                         certificateKeystorePassword="1234"
                         certificateKeystoreType="PKCS12"/>
        </SSLHostConfig>
    </Connector>
```
    - Use APR connector (fast)
```sh
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11AprProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               connectionTimeout="4000">
        <SSLHostConfig
                certificateVerification="optional"
                protocols="TLSv1.2"
                ciphers="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                caCertificateFile="${XIPKI_BASE}/keycerts/tlskeys/ca/tls-ca-cert.pem">
            <Certificate
                         certificateKeyFile="${XIPKI_BASE}/keycerts/tlskeys/server/tls-server-key.pem"
                         certificateFile="${XIPKI_BASE}/keycerts/tlskeys/server/tls-server-cert.pem"/>
        </SSLHostConfig>
    </Connector>
```
9. (optional) To accelerate the start process, append the following block to the property
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
fastjson-*.jar,\
HikariCP-*.jar,\
log4j-*.jar,\
mariadb-java-client-*.jar,\
password-*.jar,\
postgresql-*.jar,\
scep-client-*.jar,\
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


Deployment in Jetty 9
1. Copy the sub-folders `webapps` and `xipki` to the jetty root folder `${JETTY_BASE}`, and `lib` to
   `${JETTY_BASE}/lib/ext`.
   The folder `xipki` can be moved to other location, in this case a new property `XIPKI_BASE`
   pointing to point to the new position must be added to the file `start.ini`.
2. Download the `bcprov-jdk15on-<version>.jar` and `bcpkix-jdk15on-<version>.jar` from
  [BouncyCastle Latest Release](https://www.bouncycastle.org/latest_releases.html) to the folder
  `${JETTY_BASE}/lib/ext`. The cryptographic libraries are not included since we need the latest release.
3. (Optional) If you use database other than MariaDB and MySQL, you need to overwrite the
   configuration templates with those in the corresponding sub folder in `${JETTY_BASE}/xipki/etc/ca/database`,
   and download the JDBC driver to the folder `${JETTY_BASE}/lib/ext`.   
4. Adapt the database configurations `${JETTY_BASE}/xipki/etc/ca/database/ca-db.properties`.
5. Create new databases configured in Step 4.
6. Initialize the databases configured in Step 4.
   In dbtool, call `bin/initdb.sh --db-schema sql/ca-init.xml --db-conf /path/to/ca-db.properties`
7. Configure the TLS listener by adding the following block to the file `start.ini`. Please configure
  XIPKI_BASE correctly.

```sh
--module=https
XIPKI_BASE=<path/to/folder/xipki>
jetty.sslContext.keyStorePath=${XIPKI_BASE}/keycerts/tlskeys/server/tls-server.p12
jetty.sslContext.keyStorePassword=1234
jetty.sslContext.keyStoreType=PKCS12
jetty.sslContext.keyManagerPassword=1234
jetty.sslContext.trustStorePath=${XIPKI_BASE}/keycerts/tlskeys/ca/tls-ca-cert.p12
jetty.sslContext.trustStorePassword=1234
jetty.sslContext.trustStoreType=PKCS12
jetty.sslContext.needClientAuth=false
jetty.sslContext.wantClientAuth=true
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
