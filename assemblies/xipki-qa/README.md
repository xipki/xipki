# Prepare

- Set the XIPKI_DIR in `xipki/qa/setenv.script`.
- Databases used by this QA must be one of MySQL, MariaDB, PostgreSQL, Oracle and DB2.
- Add `example/certprofile-example/target/certprofile-example-<version>.jar` to
  `webapps/ca.war`.  
  In tomcat, you can just add the jar file to the folder `webapps/ca/WEB-INF/lib`. 
- Append the following line to `xipki/etc/ca/ca.properties` of the CA server:
  `Additional.CertprofileFactories=org.xipki.ca.certprofile.demo.CertprofileFactoryImpl`
  