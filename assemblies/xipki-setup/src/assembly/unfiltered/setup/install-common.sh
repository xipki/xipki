#!/usr/bin/env bash

usage_tomcat_target() {
  echo
  echo "Usage: $0 -t <dir of destination tomcat>"
  exit 1
}

parse_tomcat_target() {
  local opt
  while getopts 't:' opt; do
    case "$opt" in
      t) TOMCAT_DIR="$OPTARG" ;;
      *) usage_tomcat_target ;;
    esac
  done
  [ -n "${TOMCAT_DIR:-}" ] || usage_tomcat_target
}

require_no_conflicting_wars() {
  local war_name message
  while [ "$#" -gt 0 ]; do
    war_name="$1"
    message="$2"
    shift 2
    if [ -f "$TOMCAT_DIR/webapps/${war_name}.war" ]; then
      echo "$message"
      exit 1
    fi
  done
}

resolve_tomcat_major() {
  local version_line
  version_line="$($TOMCAT_DIR/bin/version.sh | grep 'Server number')"
  echo "Tomcat $version_line" >&2
  printf '%s\n' "$version_line" | cut -d ':' -f 2- | cut -d '.' -f 1 | awk '{$1=$1};1'
}

move_matches() {
  local target_dir="$1"
  shift
  local pattern file
  for pattern in "$@"; do
    for file in $pattern; do
      [ -e "$file" ] || continue
      mv "$file" "$target_dir"
    done
  done
}

create_backup_layout() {
  BACKUP_DIR="$TOMCAT_DIR/backup-$(date '+%Y%m%dT%H%M%S')"
  mkdir -p "$BACKUP_DIR/bin" "$BACKUP_DIR/lib" "$BACKUP_DIR/conf" "$BACKUP_DIR/webapps"
  echo "backup dir: $BACKUP_DIR"
}

backup_common_tomcat_files() {
  [ -d "$TOMCAT_DIR/xipki" ] && cp -r "$TOMCAT_DIR/xipki" "$BACKUP_DIR"
  [ -f "$TOMCAT_DIR/conf/catalina.properties" ] && mv "$TOMCAT_DIR/conf/catalina.properties" "$BACKUP_DIR/conf"
  [ -f "$TOMCAT_DIR/conf/server.xml" ] && mv "$TOMCAT_DIR/conf/server.xml" "$BACKUP_DIR/conf"

  move_matches "$BACKUP_DIR/bin" \
    "$TOMCAT_DIR"/bin/setenv.*

  move_matches "$BACKUP_DIR/lib" \
    "$TOMCAT_DIR"/lib/password-*.jar \
    "$TOMCAT_DIR"/lib/passwords-*.jar \
    "$TOMCAT_DIR"/lib/xipki-tomcat-password-*.jar \
    "$TOMCAT_DIR"/lib/*pkcs11*.jar \
    "$TOMCAT_DIR"/lib/bc*-jdk*.jar \
    "$TOMCAT_DIR"/lib/bc*-lts*.jar \
    "$TOMCAT_DIR"/lib/h2-*.jar \
    "$TOMCAT_DIR"/lib/mariadb-java-*.jar
}

copy_tomcat_tree() {
  cp -r "$SCRIPT_DIR/tomcat/"* "$TOMCAT_DIR"
}
