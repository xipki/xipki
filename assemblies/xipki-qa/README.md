# Prepare

- Make sure that the databases (`ca-db.properties` and `ocsp-db.properties`)
used by the CA server and this console-qa are of the same.
- Copy the following line to `xipki/etc/ca/ca.properties` of the CA server:
  `Additional.CertprofileFactories=org.xipki.ca.certprofile.demo.CertprofileFactoryImpl`  