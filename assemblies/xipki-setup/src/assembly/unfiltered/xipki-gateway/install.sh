#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"
. "$SCRIPT_DIR/../setup/install-common.sh"

TOMCAT_DIR=
parse_tomcat_target "$@"
require_no_conflicting_wars \
  ca "CA is running in $TOMCAT_DIR, please use other tomcat instance." \
  ocsp "OCSP responder is running in $TOMCAT_DIR, please use other tomcat instance."
require_no_conflicting_paths \
  xipki/etc/ca "CA is running in $TOMCAT_DIR, please use other tomcat instance." \
  xipki/etc/ocsp "OCSP responder is running in $TOMCAT_DIR, please use other tomcat instance."

TOMCAT_MAJOR="$(resolve_tomcat_major)"
if [ "$TOMCAT_MAJOR" -lt 10 ]; then
  echo "Unsupported tomcat major version $TOMCAT_MAJOR"
  exit 1
fi

create_backup_layout
backup_common_tomcat_files

# WAR files of former versions
for war_name in gw acme cmp est rest scep; do
  if [ -f "$TOMCAT_DIR/webapps/$war_name.war" ]; then
    mv "$TOMCAT_DIR/webapps/$war_name.war" "$BACKUP_DIR/webapps"
  fi
  rm -rf "$TOMCAT_DIR/webapps/$war_name"
done

# The gateway is the root web application. Back up the current one, e.g. Tomcat's default
# web application in webapps/ROOT.
if [ -f "$TOMCAT_DIR/webapps/ROOT.war" ]; then
  mv "$TOMCAT_DIR/webapps/ROOT.war" "$BACKUP_DIR/webapps"
fi
if [ -d "$TOMCAT_DIR/webapps/ROOT" ]; then
  mv "$TOMCAT_DIR/webapps/ROOT" "$BACKUP_DIR/webapps"
fi

# The rewrite rules of former versions (RewriteValve), no longer needed.
rewrite_config="$TOMCAT_DIR/conf/Catalina/localhost/rewrite.config"
if [ -f "$rewrite_config" ]; then
  mv "$rewrite_config" "$BACKUP_DIR/conf"
fi

# copies also webapps/ROOT.war
copy_tomcat_tree
