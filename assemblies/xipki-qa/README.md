# Prepare

## In /opt/xipki

- Change the owner of the sub folders `ca` and `ocsp` to the current user:
  `sudo chown -R <user> ca ocsp`.

## In QA Folder 

- Execute `xipki/prepare.sh`.
- Copy the folder `xipki/webapps` to `${CATALINA_HOME}`.

## In Tomcat conf/server.xml
- Add `maxKeepAliveRequests="-1"` to the Connectors listening on port 8080 and 8443.