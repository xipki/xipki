How to Configure Password
----
In all XiPKI components, you may configure the password in the following methods:
- In plaintext, e.g. `password=CHANGEIT`

- In obfuscated format, e.g. `password=OBF:1izy1htq1fnf1ime1im01fnn1hts1j0w`.
  Use karaf commands `xi:obfuscate` / `xi:deobfuscate`to obfuscate / deobfuscate the password.

- Encrypted with master password, e.g. `password=PBE:AQfQcYk2+tR2nDzR0gCaQXMkmRBgqPIomrt5yfTsJPBqb30sCID5OqHFpH/mEKb3OIIw9Q`.
  Use karaf commands `xi:pbe-enc` / `xi:pbe-dec` to encrypt / decrypt the password with master password.

  You need to configure the master password callback in the block following block of the file `ocsp.json`:
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
  You need to configure the master password callback in the block following block of the file `ocsp.json`:
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

Prepare
-----
- The `xipki/etc/ocsp/ocsp-responder.json` is for the OCSP store type `xipki-ca-db`. If you use
  other type (namely `xipki-db`, `ejbca-db`, and `crl`), please copy the `ocsp-responder.json` from
  the corresponding sub-folder in `xipki/etc/ocsp/example` to replace it.
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

Deployment in Tomcat (8, 9 and 10)
----
1. Copy the war-files in `webapps` for tomcat 8/9 or `webapps-tomcat10on` for tomcat 10+,
   to the tomcat folder `${CATALINA_HOME}/webapps`:
    - In `${CATALINA_HOME}/webapps`, delete the folder `<some-app>` if the same named `<some-app>.war` file exists.
2. Copy (and overwrite if files already exist) the sub-folders `bin`, `xipki` and `lib `
   to the tomcat root folder `${CATALINA_HOME}`.
    - The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
      `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
    - In `${CATALINA_HOME}/lib`, if an old version of a jar file exists, remove it first.
3. (Optional) If you use database other than PostgreSQL, MariaDB and MySQL, you need to download
   the JDBC driver to the folder `${CATALINA_HOME}/lib`.
4. (Optional) If you use database other than MariaDB and MySQL, you need to overwrite the
   configuration files `ca-db.properties`, `ocsp-db.properties` with those in the corresponding sub
   folder in `${CONTAINER_ROOT}/xipki/etc/ocsp/database`. Adapt the configuration.
5. (Optional, required only when OCSP cache will be activated) 
   To activate the OCSP cache:
   1) Uncomment the `responseCache` block in the configuration file `ocsp-responder.json`;
   2) In xipki-mgmt-cli, call
      `ca:sql --db-conf /path/to/ocsp-cache-db.json xipki/sql/ocsp-cache-init.sql`.
6. (Optional, required only when CRL is used as OCSPSore) 
   1) In xipki-mgmt-cli, call 
      `ca:sql --db-conf /path/to/ocsp-crl-db.json xipki/ocsp-init.sql`.
7. If OCSP over HTTP GET support is activated: Add attribute `encodedSolidusHandling="decode"` to the 
  `Connector`-element in the file `conf/server.xml`
8. (optional) To accelerate the start process, append the following block to the property
`tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.
9. If you have multiple tomcat instances, change the listing port for SHUTDOWN to be unique.

```
audit-*.jar,\
bcpkix-*.jar,\
bcprov-*.jar,\
bcutil-*.jar,\
datasource-*.jar,\
h2-*.jar \
HikariCP-*.jar,\
*pkcs11wrapper-*.jar,\
jackson-*.jar,\
license-*.jar,\
mariadb-*.jar,\
mysql-*.jar,\
ocsp-api-*.jar,\
ocsp-server-*.jar,\
password-*.jar,\
postgresql-*.jar,\
security-*.jar,\
servlet*-common-*.jar,\
util-*.jar,\
xipki-tomcat-password-*.jar
```

After the deployment
-----
You can use the openssl command to check whether the OCSP server answers as expected:
  `openssl ocsp -VAfile <PEM encoded OCSP signer certificate> -issuer <PEM encoded CA certificate> -url <URL> --serial <hex serial number>`
  
e.g.
  `openssl ocsp -VAfile ocsp-signer.pem -issuer ca.pem -url http://localhost:8080/ocsp/ -serial 0x123456789abc`
