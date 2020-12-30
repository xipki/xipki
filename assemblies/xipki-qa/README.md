# Prepare

## In QA Folder
- Adapt the `XIPKI_DIR` and `WEBAPPS_DIR` in `xipki/prepare.sh`.
- Execute `xipki/prepare.sh`.

## In Tomcat conf/server.xml
- Add `maxKeepAliveRequests="-1"` to the Connectors listening on port 8080 and 8443.

## Misc
  For SSH: you may use "-o StrictHostKeyChecking=no" to skip the host key check.
