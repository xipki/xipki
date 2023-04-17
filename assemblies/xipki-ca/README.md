Deployment in Tomcat 8 and 9
----
1. Copy the sub-folders `bin`, `webapps`, `xipki` and `lib ` to the tomcat root folder `${CATALINA_HOME}`.
   The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
   `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
2. (Optional) If you use database other than H2, PostgreSQL, MariaDB and MySQL, you need to
   download the JDBC driver to the folder `${CATALINA_HOME}/lib`.
3. (Optional) If you use database other than MariaDB and MySQL, you need to overwrite the
   configuration templates with those in the corresponding sub folder in `${CONTAINER_ROOT}/xipki/etc/ca/database`.
4. Adapt the database configurations `${CONTAINER_ROOT}/xipki/etc/ca/database/ca-db.properties` and 
   `${CONTAINER_ROOT}/xipki/etc/ca/database/caconf-db.properties`.
5. Create new databases configured in Step 4.
6. Initialize the databases configured in Step 4.
   In xipki-mgmt-cli, call `ca:sql --db-conf /path/to/ca-db.properties xipki/sql/ca-init.sql` and
   `ca:sql --db-conf /path/to/caconf-db.properties xipki/sql/caconf-init.sql`
7. Disable the HTTP listener, and configure the TLS listener in the file 
   `${CATALINA_HOME}conf/server.xml` (we use here the port 8444, can be changed to any other port)
   ```sh
    <Connector port="8444" protocol="org.apache.coyote.http11.Http11Nio2Protocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               connectionTimeout="4000">
        <SSLHostConfig
                certificateVerification="required"
                protocols="TLSv1.2+TLSv1.3"
                ciphers="TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_GCM_SHA256,TLS_AES_128_CCM_8_SHA256,TLS_AES_128_CCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
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

8. (optional) To accelerate the start process, append the following block to the property
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
xipki-tomcat-password-*.jar,\
gateway-common-*.jar
```
9. (optional) If you encrypt the passwords in the conf/server.xml with XiPKI solution, replace 
  `org.apache.coyote.http11.Http11Nio2Protocol` by `org.xipki.tomcat.XiHttp11Nio2Protocol`

- Start tomcat

```sh
  bin/start.sh
```
