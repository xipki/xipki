Deployment in Tomcat
----
1. Copy (and overwrite if files already exist) the sub-folders `webapps`, `xipki` and `lib `
   to the tomcat root folder `${CATALINA_HOME}`.
    - In `${CATALINA_HOME}/lib`, if an old version of a jar file exists, remove it first.
2. Add the line `org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=true`
   to the file `conf/catalina.properties` if OCSP over HTTP supported is activated.
3. Start tomcat
  In the tomcat root folder

```sh
  bin/start.sh
```

  Note that the start script of tomcat does not set the working directory to the tomcat root directory, you have to start tomcat as above so that the XiPKI can retrieve files correctly.

4. Shutdown tomcat
   Shutdown tomcat from any folder
```sh
  /path/to/tomcat/bin/shutdown.sh
```

Deployment in Jetty 9
----
1. Copy the sub-folders `webapps` and `xipki` to the jetty root folder, and the files in sub-folder `lib` to the sub-folder `lib/ext` of jetty.
2. Start jetty
   Start jetty from any folder
```sh
  /path/to/jetty/bin/jetty.sh start
```

3. Shutdown jetty
   Shutdown jetty from any folder
```sh
  /path/to/jetty/bin/jetty.sh stop
```

