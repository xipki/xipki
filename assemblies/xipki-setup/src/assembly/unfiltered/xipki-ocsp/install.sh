#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"
. "$SCRIPT_DIR/../setup/install-common.sh"

TOMCAT_DIR=
parse_tomcat_target "$@"
require_no_conflicting_wars \
  ca "CA is running in $TOMCAT_DIR, please use other tomcat instance." \
  gw "Protocol gateway is running in $TOMCAT_DIR, please use other tomcat instance."

TOMCAT_MAJOR="$(resolve_tomcat_major)"
if [ "$TOMCAT_MAJOR" -lt 10 ]; then
  echo "Unsupported tomcat major version $TOMCAT_MAJOR"
  exit 1
fi

create_backup_layout
backup_common_tomcat_files

if [ -f "$TOMCAT_DIR/webapps/ocsp.war" ]; then
  mv "$TOMCAT_DIR/webapps/ocsp.war" "$BACKUP_DIR/webapps"
fi
rm -rf "$TOMCAT_DIR/webapps/ocsp"

copy_tomcat_tree
