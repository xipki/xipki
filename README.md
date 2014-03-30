XiPKI
=====

Enterprise PKI containing Certificate Authority and OCSP responder


0.Prepare 
    ./install.sh to install the iaikPkcs11Wrapper.jar to the local maven repository

1. Build the project

1.1. In project folder
   mvn clean install 

1.2. In folder dist
   mvn clean install


2. Prepare the CA and OCSP responder

2.1. Login mysql and executing the SQL queries in 
   datasource/sql/mysql-ca.sql and datasource/sql/mysql-ocsp.sql

2.2. Untar the distribution file created in step 1.2
   tar xvf xipki-<version>.tar.gz
  
   and switch to the folder xipki-<version>
 
2.3 Configure the database data
      ca-config/ca-db.properties and ca-demo/ocsp-db.properties

2.4 Start the ca/ocsp responder
     bin/karaf

2.5 In the karaf console
     source ca-demo/demo.script
    
    to configure CA and OCSP responder and test them
  
