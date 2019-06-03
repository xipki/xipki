Deployment in Tomcat
----
- Copy the sub-folders `webapps` and `xipki` to the tomcat root folder
- Add the line `org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=true`
   to the file `conf/catalina.properties` if OCSP over HTTP supported is activated.
- (optiona) add `maxKeepAliveRequests="-1"` to the Connector listening on port 8080 in the file `conf/server`.
   This step is only required for the benchmark test.
- Configure the TLS listener in the file `conf/server.xml`
    - Use NIO connector

```sh
    <Connector port="9443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               connectionTimeout="4000" maxKeepAliveRequests="-1">
        <SSLHostConfig
                certificateVerification="optional"
                protocols="TLSv1.2"
                ciphers="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                truststoreFile="xipki/keycerts/tlskeys/ca/tls-ca-cert.p12"
                truststorePassword="1234"
                truststoreType="PKCS12">
            <Certificate type="RSA"
                         certificateKeystoreFile="xipki/keycerts/tlskeys/server/tls-server.p12"
                         certificateKeystorePassword="1234"
                         certificateKeystoreType="PKCS12"/>
        </SSLHostConfig>
    </Connector>
```

     - Use APR connector (fast)

```sh
    <Connector port="9443" protocol="org.apache.coyote.http11.Http11AprProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               connectionTimeout="4000" maxKeepAliveRequests="-1">
        <SSLHostConfig
                certificateVerification="optional"
                protocols="TLSv1.2"
                ciphers="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                caCertificateFile="xipki/keycerts/tlskeys/ca/tls-ca-cert.pem">
            <Certificate type="RSA"
                         certificateKeyFile="xipki/keycerts/tlskeys/server/tls-server-key.pem"
                         certificateFile="xipki/keycerts/tlskeys/server/tls-server-cert.pem"/>
        </SSLHostConfig>
    </Connector>
```

- (optional) To accelerate the start process, append the following block to the property
`tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.

```
bcprov-jdk15on-*.jar,\
bcpkix-jdk15on-*.jar,\
datasource-*.jar,\
fastjson-*.jar,\
HikariCP-*.jar,\
log4j-core-*.jar,\
log4j-api-*.jar,\
log4j-slf4j-impl-*.jar,\
mariadb-java-client-*.jar,\
password-*.jar,\
pkcs11-constants-*.jar,\
postgresql-*.jar,\
security-*.jar,\
sunpkcs11-wrapper-*.jar,\
util-*.jar
```

Deployment in Jetty 9
----
- Copy the sub-folders `webapps` and `xipki` to the jetty root folder, and the files in sub-folder `lib` to the sub-folder `lib/ext` of jetty.
- Configure the TLS listener by adding the following block to the file `start.ini`

```sh
--module=https
jetty.sslContext.keyStorePath=xipki/keycerts/tlskeys/server/tls-server.p12
jetty.sslContext.keyStorePassword=1234
jetty.sslContext.keyStoreType=PKCS12
jetty.sslContext.keyManagerPassword=1234
jetty.sslContext.trustStorePath=xipki/keycerts/tlskeys/ca/tls-ca-cert.p12
jetty.sslContext.trustStorePassword=1234
jetty.sslContext.trustStoreType=PKCS12
jetty.sslContext.needClientAuth=false
jetty.sslContext.wantClientAuth=true
```
