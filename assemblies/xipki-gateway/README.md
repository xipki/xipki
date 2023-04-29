Deployment in Tomcat 8 and 9
----
1. Copy the sub-folders `bin`, `webapps`, `xipki` and `lib` to the tomcat root folder
   The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
   `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
   Note if you do not support all protocols CMP, SCEP and RESTful API, please delete the unsupported ones
   (cmp.war for CMP, scep.war for SCEP, .well-known.war for EST, and rest.war for RESTful API)
2. If SCEP is supported, you need to have a SCEP server certificate with private key. For the demo you may generate this
   certificate in the `xipki-mgmt-cli` via the command 
   `enroll-cert --ca myca1 --subject "CN=scep responder" --profile scep --key-password 1234 --out output/scep1.der`,
   and then copy the generated file `scep1.p12` to the folder `xipki/keycerts`.
3. Optional, configure the TLS listener in the file
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
gson-*.jar,\
log4j-*.jar,\
security-*.jar,\
slf4j-*.jar,\
*pkcs11wrapper-*.jar,\
util-*.jar,\
xipki-tomcat-password-*.jar,\
gateway-common-*.jar
```

5. (optional) If you encrypt the passwords in the conf/server.xml with XiPKI solution, replace
   `org.apache.coyote.http11.Http11Nio2Protocol` by `org.xipki.tomcat.XiHttp11Nio2Protocol`.

- Start tomcat

```sh
  bin/start.sh
```
