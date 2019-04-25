Deployment in Tomcat
----
- Copy the sub-folders `webapps`, `xipki` and `lib ` to the tomcat root folder
- Add the line `org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=true`
   to the file `conf/catalina.properties` if OCSP over HTTP supported is activated.
- (optiona) add `maxKeepAliveRequests="-1"` to the HTTP Connector in the file `conf/server`.
   This step is only required for the benchmark test.
- (optional) To accelerate the start process, append the following block to the property
`tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.

```
audit-*.jar,\
bcprov-jdk15on-*.jar,\
bcpkix-jdk15on-*.jar,\
ca-*.jar,\
certprofile-xijson-*.jar,\
datasource-*.jar,\
fastjson-*.jar,\
HikariCP-*.jar,\
logback-core-*.jar,\
logback-classic-*.jar,\
mariadb-java-client-*.jar,\
ocsp-api-*.jar,\
ocsp-server-*.jar,\
password-*.jar,\
pkcs11-constants-*.jar,\
postgresql-*.jar,\
scep-common-*.jar,\
security-*.jar,\
sunpkcs11-wrapper-*.jar,\
syslog-java-client-*.jar,\
util-*.jar
```
- Start tomcat
  In the tomcat root folder

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
- Copy the sub-folders `webapps` and `xipki` to the jetty root folder, and the files in sub-folder `lib` to the sub-folder `lib/ext` of jetty.
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

