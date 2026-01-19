Deployment in Tomcat (10 and 11)
----
1. (Optional) If you use database other than H2, PostgreSQL, MariaDB and MySQL:
   Download the JDBC driver to the folder `tomcat/lib`.
2. (Optional) If you use database other than MariaDB and MySQL:  
   Overwrite the configuration files `*-db.properties` in the folder `tomcat/xipki/etc/ca/database`
   with those in the corresponding sub folder.
3. Adapt the database configurations `*-db.properties` in the folder `tomcat/xipki/etc/ca/database`.
4. Create new databases configured in Step 3.
5. Execute the command  
   `./install.sh -t <tomcat dir of CA server>`
