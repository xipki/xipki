Deployment in Tomcat
----
1. Copy the sub-folders `webapps` and `xipki`to the tomcat root folder
2. Configure the TLS listener in the file `conf/server.xml`
    - Use NIO connector

```sh
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               connectionTimeout="4000" maxKeepAliveRequests="-1">
        <SSLHostConfig
                certificateVerification="optional"
                protocols="TLSv1.2"
                ciphers="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                truststoreFile="xipki/keycerts/tlskeys/tls-ca-cert.p12"
                truststorePassword="1234"
                truststoreType="PKCS12">
            <Certificate type="RSA"
                         certificateKeystoreFile="xipki/keycerts/tlskeys/tls-server.p12"
                         certificateKeystorePassword="1234"
                         certificateKeystoreType="PKCS12"/>
        </SSLHostConfig>
    </Connector>
```
  
     - Use APR connector (fast)

```sh
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11AprProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               connectionTimeout="4000" maxKeepAliveRequests="-1">
        <SSLHostConfig
                certificateVerification="optional"
                protocols="TLSv1.2"
                ciphers="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                certificateRevocationListFile="xipki/keycerts/tlskeys/ca/tls-ca-crl.pem"
                caCertificateFile="xipki/keycerts/tlskeys/ca/tls-ca-cert.pem">
            <Certificate type="RSA"
                         certificateKeyFile="xipki/keycerts/tlskeys/tls-server-key.pem"
                         certificateFile="xipki/keycerts/tlskeys/tls-server-cert.pem"/>
        </SSLHostConfig>
    </Connector>
```

Deployment in Jetty 9
----
1. Copy the sub-folders `webapps` and `xipki` to the jetty root folder
2. Configure the TLS listener by adding the following block to the file `start.ini`

```sh
--module=https
jetty.sslContext.keyStorePath=xipki/keycerts/tlskeys/tls-server.p12
jetty.sslContext.keyStorePassword=1234
jetty.sslContext.keyStoreType=PKCS12
jetty.sslContext.keyManagerPassword=1234
jetty.sslContext.trustStorePath=xipki/keycerts/tlskeys/tls-ca-cert.p12
jetty.sslContext.trustStorePassword=1234
jetty.sslContext.trustStoreType=PKCS12
jetty.sslContext.needClientAuth=false
jetty.sslContext.wantClientAuth=true
```
