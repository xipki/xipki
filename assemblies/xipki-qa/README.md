# Prepare

- Set the XIPKI_DIR in `xipki/qa/setenv.script`.
- Deploy both ocsp.war and ca.war to the same servlet container.
- Enable the remote management of OCSP explicitly by setting `remote.mgmt.enabled = true`
  in the file `xipki/etc/org.xipki.ocsp.server.cfg`.
- Databases used by this QA must be one of MySQL, MariaDB, PostgreSQL, Oracle and DB2.
- Add `example/certprofile-example/target/certprofile-example-<version>.jar` to
  `webapps/ca.war`.  
  In tomcat, you can just add the jar file to the folder `webapps/ca/WEB-INF/lib`. 
- Append the following line to `xipki/etc/ca/ca.properties` of the CA server:
  `Additional.CertprofileFactories=org.xipki.ca.certprofile.demo.CertprofileFactoryImpl`
  