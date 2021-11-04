Migration
----
- From v5.3.0 - v5.3.6 to v5.3.7+
  - Remove the path prefix `xipki/` in all configuration files (`*.json`, `*.properties`, `*.cfg`)
    in the folder `xipki/`.

Deployment in Tomcat 8 and 9
----
1. Copy the sub-folders `bin`, `webapps`, `xipki` and `lib ` to the tomcat root folder `${CATALINA_HOME}`.
  The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
  `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
2. Download the `bcutil-jdk15on-<version>.jar`, `bcprov-jdk15on-<version>.jar` and `bcpkix-jdk15on-<version>.jar` from
  [BouncyCastle Latest Release](https://www.bouncycastle.org/latest_releases.html) to the folder
  `${CATALINA_HOME}/lib`. The cryptographic libraries are not included since we need the latest release.
3. (Optional) If you use database other than PostgreSQL, MariaDB and MySQL, you need to
   download the JDBC driver to the folder `${CATALINA_HOME}/lib`.
4. (Optional) If you use database other than MariaDB and MySQL, you need to overwrite the
   configuration templates with those in the corresponding sub folder in `${CONTAINER_ROOT}/xipki/etc/ca/database`.
5. Adapt the database configurations `${CONTAINER_ROOT}/xipki/etc/ca/database/ca-db.properties`.
6. Create new databases configured in Step 6.
7. Initialize the databases configured in Step 6.
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
10. (optional) To accelerate the start process, append the following block to the property
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

```sh
  bin/start.sh
```
