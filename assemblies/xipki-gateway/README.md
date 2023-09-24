Deployment in Tomcat 8 and 9 (does not work in Tomcat 10+)
----
1. Copy (and overwrite if files already exist) the sub-folders `bin`, `webapps`, `xipki` and `lib `
   to the tomcat root folder `${CATALINA_HOME}`.
   - The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
     `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
   - In `${CATALINA_HOME}/lib`, if an old version of a jar file exists, remove it first.
   - In `${CATALINA_HOME}/webapps`, delete the folder `<some-app>` if the same named `<some-app>.war` file exists.
   - Note if you do not support all protocols CMP, SCEP and RESTful API, please delete the unsupported `war` 
     files and the same named folders
   (cmp.war for CMP, scep.war for SCEP, .well-known.war for EST, acme.war for ACME, and rest.war for RESTful API)
2. If SCEP is supported, you need to have a SCEP server certificate with private key. For the demo you may generate this
   certificate in the `xipki-mgmt-cli` via the command 
   `enroll-cert --ca myca1 --subject "CN=scep responder" --profile scep --key-password 1234 --out output/scep1.der`,
   and then copy the generated file `scep1.p12` to the folder `xipki/keycerts`.
3. If ACME is supported
   1. (Optional) If you use database other than H2, PostgreSQL, MariaDB and MySQL, you need to
      download the JDBC driver to the folder `${CATALINA_HOME}/lib`.
   2. (Optional) If you use database other than MariaDB and MySQL, you need to overwrite the
      `acme-db.properties` with the one in the corresponding sub folder in `${CONTAINER_ROOT}/xipki/etc/acme/database`.
   3. Adapt the database configurations `${CONTAINER_ROOT}/xipki/etc/acme/database/acme-db.properties`.
   4. Create new database configured in previous step.
   5. Initialize the database configured in previous step.  
      In xipki-mgmt-cli, call `ca:sql --db-conf /path/to/acme-db.properties xipki/sql/acme-init.sql`
   6. Adapt the `acme`-block in the `${CONTAINER_ROOT}/xipki/etc/acme-gateway.json`.
   7. The server URL is https://<host>:<HTTPS-port>/acme/ or http://<host>:<HTTP-port>/acme/.
5. Optional, configure the TLS listener in the file
   `${CATALINA_HOME}conf/server.xml` (we use here the port 8082 and 8445, can be changed to any other port)
   ```sh
   <Connector port="8445" protocol="org.apache.coyote.http11.Http11Nio2Protocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               connectionTimeout="4000">
        <SSLHostConfig
                certificateVerification="optional"
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

4. (optional) To accelerate the start process, append the following block to the property
  `tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.

```
animal-sniffer-annotations*.jar,\
bcpkix-*.jar,\
bcprov-*.jar,\
bcutil-*.jar,\
jackson-*.jar,\
log4j-*.jar,\
security-*.jar,\
slf4j-*.jar,\
*pkcs11wrapper-*.jar,\
jose4j-*.jar,\
dnsjava-*.jar,\
util-*.jar,\
xipki-tomcat-password-*.jar,\
gateway-common-*.jar
```

5. (optional) If you encrypt the passwords in the conf/server.xml with XiPKI solution, replace
   `org.apache.coyote.http11.Http11Nio2Protocol` by `org.xipki.tomcat.XiHttp11Nio2Protocol`.

- Start tomcat

```sh
  bin/startup.sh
```
