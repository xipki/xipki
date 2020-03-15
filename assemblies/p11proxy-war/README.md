Migration
----
- From v5.3.0 - v5.3.6 to v5.3.7+
  - Remove the path prefix `xipki/` in all configuration files (`*.json`, `*.properties`, `*.cfg`) in the folder `xipki/`.
- For v5.3.7+, the folder `xipki` may be placed anywhere, it must be pointed to by the java property `XIPKI_BASE`.
  It can be configured as follows:
  - Tomcat: in the file `bin\setevn.*`
  - Jetty: in the file `start.ini`.

Deployment in Tomcat 8 and 9
----
- Copy the files `setenv.sh` and `setenv.bat` in the folder `tomcat/bin` to the folder `${CATALINA_HOME}/bin`.
- Copy the sub-folders `webapps` and `xipki` to the tomcat root folder
  The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
  `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
- Configure the TLS listener in the file `conf/server.xml`
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
            <Certificate type="RSA"
                         certificateKeystoreFile="${XIPKI_BASE}/keycerts/tlskeys/server/tls-server.p12"
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
bcprov-*.jar,\
bcpkix-*.jar,\
fastjson-*.jar,\
log4j-*.jar,\
password-*.jar,\
security-*.jar,\
slf4j-*.jar,\
sunpkcs11-wrapper-*.jar,\
util-*.jar
```

- Start tomcat
  <span style="color:red">**In the tomcat root folder ${CATALINA_HOME}** (Otherwise the file path cannot be interpreted correctly.)</span>

```sh
  bin/start.sh
```

  Note that the start script of tomcat does not set the working directory to the tomcat root directory, you have to start tomcat as above so that the XiPKI can retrieve files correctly.

- Shutdown tomcat
   Shutdown tomcat from any folder

```sh
  /path/to/tomcat/bin/shutdown.sh
```

Deployment in Jetty 9
----
- Copy the sub-folder `webapps` to the jetty root folder, and the files in sub-folder `${JETTY_BASE}lib` to the sub-folder `${JETTY_BASE}lib/ext` of jetty.
- Copy the sub-folder `xipki` to any position you wished.
- Configure the TLS listener by adding the following block to the file `start.ini`. Please configure
  XIPKI_BASE correctly.

```sh
--module=https
XIPKI_BASE=<path/to/folder/xipki>
jetty.sslContext.keyStorePath=${XIPKI_BASE}/keycerts/tlskeys/server/tls-server.p12
jetty.sslContext.keyStorePassword=1234
jetty.sslContext.keyStoreType=PKCS12
jetty.sslContext.keyManagerPassword=1234
jetty.sslContext.trustStorePath=${XIPKI_BASE}/keycerts/tlskeys/ca/tls-ca-cert.p12
jetty.sslContext.trustStorePassword=1234
jetty.sslContext.trustStoreType=PKCS12
jetty.sslContext.needClientAuth=false
jetty.sslContext.wantClientAuth=true
```

- For jetty 9.4.15 - 9.4.18
  There is a bug in these versions, you need to remove the `default="HTTPS"` block from the 
  line `EndpointIdentificationAlgorithm` in the file `etc/jetty-ssl-context.xml`, namely from

```
 <Set name="EndpointIdentificationAlgorithm"><Property name="jetty.sslContext.endpointIdentificationAlgorithm" default="HTTPS"/></Set>
```
to

```
 <Set name="EndpointIdentificationAlgorithm"><Property name="jetty.sslContext.endpointIdentificationAlgorithm"/></Set>
```

- Start jetty
   Start jetty from any folder

```sh
  /path/to/jetty/bin/jetty.sh start
```

- Shutdown jetty
   Shutdown jetty from any folder

```sh
  /path/to/jetty/bin/jetty.sh stop
```
