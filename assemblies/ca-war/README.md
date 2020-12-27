Deployment in Tomcat 8 and 9
----
1. Copy the sub-folder `xipki` to the folder `/opt`.
2. Copy the sub-folders `webapps` and `lib ` to the tomcat root folder `${CATALINA_HOME}`.
3. Download the `bcprov-jdk15on-<version>.jar` and `bcpkix-jdk15on-<version>.jar` from
  [BouncyCastle Latest Release](https://www.bouncycastle.org/latest_releases.html) to the folder
  `${CATALINA_HOME}/lib`. The cryptographic libraries are not included since we need the latest release.
4. (Optional) If you use database other than MariaDB and MySQL, you need to overwrite the
   configuration templates with those in the corresponding sub folder in `/opt/xipki/ca/etc/database`,
   and download the JDBC driver to the folder `${CATALINA_HOME}/lib`.
5. Adapt the database configurations `/opt/xipki/ca/etc/database/ca-db.properties`.
6. Create new databases configured in Step 5.
7. Initialize the databases configured in Step 5.
   In dbtool, call `bin/initdb.sh --db-schema /opt/xipki/ca/sql/ca-init.xml --db-conf /opt/xipki/ca/etc/database/ca-db.properties`
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
                truststoreFile="/opt/xipki/ca/keycerts/tlskeys/ca/tls-ca-cert.p12"
                truststorePassword="1234"
                truststoreType="PKCS12">
            <Certificate type="RSA"
                         certificateKeystoreFile="/opt/xipki/ca/keycerts/tlskeys/server/tls-server.p12"
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
                caCertificateFile="/opt/xipki/ca/keycerts/tlskeys/ca/tls-ca-cert.pem">
            <Certificate type="RSA"
                         certificateKeyFile="/opt/xipki/ca/keycerts/tlskeys/server/tls-server-key.pem"
                         certificateFile="/opt/xipki/ca/keycerts/tlskeys/server/tls-server-cert.pem"/>
        </SSLHostConfig>
    </Connector>
```
9. (optional) To accelerate the start process, append the following block to the property
`tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.

```
audit-*.jar,\
bcprov-*.jar,\
bcpkix-*.jar,\
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
