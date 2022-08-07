Migration
----
- From v5.3.0 - v5.3.6 to v5.3.7+
  - Remove the path prefix `xipki/` in all configuration files (`*.json`, `*.properties`, `*.cfg`)
    in the folder `xipki/`.

Deployment in Tomcat 8 and 9
----
1. Copy the sub-folders `bin`, `webapps`, `xipki` and `lib` to the tomcat root folder
  The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
  `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
2. Configure the TLS listener in the file `conf/server.xml`
   - Use NIO connector

   ```sh
   <Connector port="9443" protocol="org.apache.coyote.http11.Http11NioProtocol"
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
   - Use APR connector (fast). See https://tomcat.apache.org/tomcat-8.0-doc/apr.html for more details.

   ```sh
   <Connector port="9443" protocol="org.apache.coyote.http11.Http11AprProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               connectionTimeout="4000">
        <SSLHostConfig
                certificateVerification="optional"
                protocols="TLSv1.2"
                ciphers="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                caCertificateFile="xipki/keycerts/tlskeys/ca/tls-ca-cert.pem">
            <Certificate
                         certificateKeyFile="xipki/keycerts/tlskeys/server/tls-server-key.pem"
                         certificateFile="xipki/keycerts/tlskeys/server/tls-server-cert.pem"/>
        </SSLHostConfig>
    </Connector>
   ```

- (optional) To accelerate the start process, append the following block to the property
`tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.

```
animal-sniffer-annotations*.jar,\
bcpkix-*.jar,\
bcprov-*.jar,\
bcutil-*.jar,\
fastjson-*.jar,\
log4j-*.jar,\
password-*.jar,\
security-*.jar,\
slf4j-*.jar,\
sunpkcs11-wrapper-*.jar,\
tinylog*.jar,\
util-*.jar
```

- Start tomcat

```sh
  bin/start.sh
```
