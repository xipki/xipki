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
  You need to configure the master password callback in the block following block of the file `hsmproxy.json`:
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
3. Configure the TLS listener in the file
   `${CATALINA_HOME}conf/server.xml` (we use here the port 8446, can be changed to any other port)
   Delete all non-TLS connectors, and add TLS connector as follows:
   ```sh
   <Connector port="8446" protocol="org.apache.coyote.http11.Http11Nio2Protocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               connectionTimeout="4000">
        <SSLHostConfig
                certificateVerification="optional"
                protocols="TLSv1.2+TLSv1.3"
                ciphers="TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_GCM_SHA256,TLS_AES_128_CCM_8_SHA256,TLS_AES_128_CCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                truststoreFile="${XIPKI_BASE}/keycerts/hsmproxy-client-certstore.p12"
                truststorePassword="CHANGEIT"
                truststoreType="PKCS12">
            <Certificate
                         certificateKeystoreFile="${XIPKI_BASE}/keycerts/hsmproxy-server.p12"
                         certificateKeystorePassword="CHANGEIT"
                         certificateKeystoreType="PKCS12"/>
        </SSLHostConfig>
   </Connector>
   ``` 
3. (optional) To accelerate the start process, append the following block to the property
`tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.

```
bcpkix-*.jar,\
bcprov-*.jar,\
bcutil-*.jar,\
*pkcs11wrapper-*.jar,\
hsmproxy-*.jar,\
jackson-*.jar,\
password-*.jar,\
security-*.jar,\
servlet*-common-*.jar,\
util-*.jar,\
xipki-tomcat-password-*.jar
```

4. If you have multiple tomcat instances, change the listing port for SHUTDOW to be unique.