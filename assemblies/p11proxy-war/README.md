Deployment in Tomcat 8 and 9
----
1. Copy the sub-folder `xipki` to the folder `/opt`.
2. Copy the sub-folder `webapps` to the tomcat root folder `${CATALINA_HOME}`.
3. Download the `bcprov-jdk15on-<version>.jar` and `bcpkix-jdk15on-<version>.jar` from
  [BouncyCastle Latest Release](https://www.bouncycastle.org/latest_releases.html) to the folder
  `${CATALINA_HOME}/lib`. The cryptographic libraries are not included since we need the latest release.
4. Configure the TLS listener in the file `conf/server.xml`
    - Use NIO connector

```sh
    <Connector port="9443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               connectionTimeout="4000">
        <SSLHostConfig
                certificateVerification="optional"
                protocols="TLSv1.2"
                ciphers="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                truststoreFile="/opt/xipki/p11proxy/keycerts/tlskeys/ca/tls-ca-cert.p12"
                truststorePassword="1234"
                truststoreType="PKCS12">
            <Certificate type="RSA"
                         certificateKeystoreFile="/opt/xipki/p11proxy/keycerts/tlskeys/server/tls-server.p12"
                         certificateKeystorePassword="1234"
                         certificateKeystoreType="PKCS12"/>
        </SSLHostConfig>
    </Connector>
```

     - Use APR connector (fast)

```sh
    <Connector port="9443" protocol="org.apache.coyote.http11.Http11AprProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               connectionTimeout="4000">
        <SSLHostConfig
                certificateVerification="optional"
                protocols="TLSv1.2"
                ciphers="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                caCertificateFile="/opt/xipki/p11proxy/keycerts/tlskeys/ca/tls-ca-cert.pem">
            <Certificate type="RSA"
                         certificateKeyFile="/opt/xipki/p11proxy/keycerts/tlskeys/server/tls-server-key.pem"
                         certificateFile="/opt/xipki/p11proxy/keycerts/tlskeys/server/tls-server-cert.pem"/>
        </SSLHostConfig>
    </Connector>
```

- (optional) To accelerate the start process, append the following block to the property
`tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.

```
bcprov-*.jar,\
bcpkix-*.jar,\
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
  <span style="color:red">**In the tomcat root folder ${CATALINA_HOME}** (Otherwise the file path
  cannot be interpreted correctly.)</span>

```sh
  bin/start.sh
```

  Note that the start script of tomcat does not set the working directory to the tomcat root
  directory, you have to start tomcat as above so that the XiPKI can retrieve files correctly.