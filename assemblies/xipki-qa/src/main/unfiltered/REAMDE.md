# Prepare

- Set the XIPKI_DIR in `xipki/qa/setenv.script`.
- Uncomment the line `#datasource.ocsp` in `xipki/etc/ca/ca.properties`
- Copy the database files `xipki/etc/ca/database/<db-type>/*.properties` to `xipki/etc/ca/database/`
- Copy the database files `xipki/etc/ocsp/database/<db-type>/*.properties` to `xipki/etc/ocsp/database/`
- Deploy both ocsp.war and ca.war to the same servlet container.
- Enable the remote management of OCSP explicitly by setting `remote.mgmt.enabled = true`
  in the file `xipki/etc/org.xipki.ocsp.server.cfg`.
- Databases used by this QA must be one of MySQL, MariaDB, PostgreSQL, Oracle and DB2.
  In tomcat, you can just add the jar file to the folder `webapps/ca/WEB-INF/lib`. 
