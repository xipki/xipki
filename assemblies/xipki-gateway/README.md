How to Configure Password
----
In all XiPKI components, you may configure the password in the following methods:
- In plaintext, e.g. `password=CHANGEIT`

- In obfuscated format, e.g. `password=OBF:1izy1htq1fnf1ime1im01fnn1hts1j0w`.
  Use karaf commands `xi:obfuscate` / `xi:deobfuscate`to obfuscate / deobfuscate the password.

- Encrypted with master password, e.g. `password=PBE:AQfQcYk2+tR2nDzR0gCaQXMkmRBgqPIomrt5yfTsJPBqb30sCID5OqHFpH/mEKb3OIIw9Q`.
  Use karaf commands `xi:pbe-enc` / `xi:pbe-dec` to encrypt / decrypt the password with master password.

  You need to configure the master password callback in the block following block of the file `hsmproxy.json`:
   ```
   "password":{
     ...
     "masterPasswordCallback":"FILE file=security/masterpassword.secret"
     ...
   }
   ```
  The following values of masterPasswordCallback are allowed:
   - `FILE file=<path to the masterpassword>`, e.g. `FILE file=security/masterpassword.secret`,
      - The file content is either the password itself or its obfuscated format (starting with `OBF:`).
      - Either absolute path or relative path to the `xipki` folder.
      - `PBE-GUI quorum=<number>,tries=<number>`, e.g. `PBE-GUI quorum=1,tries=3`
      - `GUI quorum=<number>,tries=<number>`, e.g. `GUI quorum=1,tries=3`
      - `OBF OBF:<obfuscated master password>`, e.g. `OBF OBF:1yf01z7o1t331z7e1yf6`.
      - `<class name implements org.xipki.password.PasswordCallback> [<corresponding configuration>]`
        e.g. `org.xipki.password.PassThroughPasswordCallback dummy-password`
        Please refer to https://github.com/xipki/commons/tree/main/password for the source code of
        `org.xipki.password.{PasswordCallback | PassThroughPasswordCallback}`.

- Use you own password resolver, assumed the password protocol is `ABC`, then the password is
  `ABC:<data>`. You need to write a Java class implements `org.xipki.password.SinglePasswordResolver` which
  can resolve password started with `ABC:`.
  You need to configure the master password callback in the block following block of the file `*-gateway.json`:
   ```
   "password":{
     ...
     "singlePasswordResolvers":[
      "<name of class 1 implementing org.xipki.password.SinglePasswordResolver>",
      "<name of class 2 implementing org.xipki.password.SinglePasswordResolver>",
     ],
     ...
   }
   ```
s
Deployment in Tomcat (8, 9 and 10)
----
1. Copy the war-files in `webapps` for tomcat 8/9 or `webapps-tomcat10on` for tomcat 10+,
   to the tomcat folder `${CATALINA_HOME}/webapps`:
   - In `${CATALINA_HOME}/webapps`, delete the folder `<some-app>` if the same named `<some-app>.war` file exists.
   - Note if you do not support all protocols (ACME, CMP, EST, SCEP and RESTful API), please delete the unsupported `war`
     files and the same named folders
     (cmp.war for CMP, scep.war for SCEP, .well-known.war for EST, acme.war for ACME, and rest.war for RESTful API)
2. Copy (and overwrite if files already exist) the sub-folders `bin`, `xipki` and `lib `
   to the tomcat root folder `${CATALINA_HOME}`.
   - The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
     `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
   - In `${CATALINA_HOME}/lib`, if an old version of a jar file exists, remove it first.
3. If SCEP is supported, you need to have a SCEP server certificate with private key. For the demo you may generate this
   certificate in the `xipki-mgmt-cli` via the command 
   `enroll-cert --ca myca1 --subject "CN=scep responder" --profile scep --key-password CHANGEIT --out output/scep1.der`,
   and then copy the generated file `scep1.p12` to the folder `xipki/keycerts`.
4. If ACME is supported
   1. (Optional) If you use database other than PostgreSQL, MariaDB and MySQL, you need to
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
                truststoreFile="${XIPKI_BASE}/keycerts/gateway-client-ca-certstore.p12"
                truststorePassword="CHANGEIT"
                truststoreType="PKCS12">
            <Certificate
                         certificateKeystoreFile="${XIPKI_BASE}/keycerts/gateway-server.p12"
                         certificateKeystorePassword="CHANGEIT"
                         certificateKeystoreType="PKCS12"/>
        </SSLHostConfig>
   </Connector>
   ```

6. (optional) To accelerate the start process, append the following block to the property
  `tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.
   (",\" shall be added to the last line of existing property value).

```
audit-*.jar,\
bcprov-*.jar,\
bcpkix-*.jar,\
bcutil-*.jar,\
ca-sdk-*.jar,\
cmp-core-*.jar,\
datasource-*.jar,\
dnsjava-*.jar,\
*-gateway-*.jar,\
gateway-common-*.jar,\
h2-*.jar \
HikariCP-*.jar,\
*pkcs11wrapper-*.jar,\
jackson-*.jar,\
mariadb-*.jar,\
mysql-*.jar,\
password-*.jar,\
pki-common-*.jar,\
postgresql-*.jar,\
security-*.jar,\
scep-core-*.jar,\
servlet*-common-*.jar,\
xipki-tomcat-password-*.jar,\
util-*.jar
```

7. (optional) If you encrypt the passwords in the conf/server.xml with XiPKI solution, replace
   `org.apache.coyote.http11.Http11Nio2Protocol` by `org.xipki.tomcat.XiHttp11Nio2Protocol`.

8. If you have multiple tomcat instances, change the listing port for SHUTDOWN to be unique.

9. Optional. Configure the Rewrite Rules to forward /.well-known/est/ to /est/, and /.well-known/cmp/ to cmp/.
   Add the Valve org.apache.catalina.valves.rewrite.RewriteValve to the Host element in conf/server.xml
   ```
   <Host name="localhost"  appBase="webapps"
            unpackWARs="true" autoDeploy="true">
     <Valve className="org.apache.catalina.valves.rewrite.RewriteValve"/>
     ...
   </Host>
   ```
   Create a new file in the file conf/Catalina/localhost/rewrite.config with the following content:
   ```
   RewriteRule ^/.well-known/est/(.*) /est/$1
   RewriteRule ^/.well-known/cmp/(.*) /cmp/$1
   ```
