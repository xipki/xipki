# Prepare

## In QA Folder
- Set the XIPKI_DIR in `xipki/qa/setenv.script`.
- Copy the file `xipki/etc/ca/ca.json` to `<tomcat/jetty_root>/xipki/etc/ca/ca.json`.

## In Tomcat/Jetty Folder
- Copy the file `dummy-ctlog-server-5.2.0-SNAPSHOT.war` from project folder to `webapps/ctlog.war`.
- Comment-in the remoteMgmt block in `xipki/etc/ocsp/ocsp.json`.
- Copy the database files `xipki/etc/ca/database/mariadb/*.properties` to `xipki/etc/ca/database/`.
- Copy the database files `xipki/etc/ocsp/database/mariadb/*.properties` to `xipki/etc/ocsp/database/`.

## In Tomcat conf/server.xml
- Add `maxKeepAliveRequests="-1"` to the Connectors listening on port 8080 and 8443.