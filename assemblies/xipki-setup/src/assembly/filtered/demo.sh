#!/usr/bin/env bash

set -e

DATABASE_TYPE=h2
DEMO_DIR=~/demo_xipki
TOMCAT_MAJOR_VERSION=10

script_dir="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"
lib_dir="$script_dir/xipki-mgmt-cli/lib"
classpath="$lib_dir/*"
java_exec="${JAVA_HOME:+$JAVA_HOME/bin/}java"

error() {
  echo "ERROR: $*" >&2
  exit 1
}

find_tomcat_version() {
  local search_dir="$1"
  local major="$2"
  local local_tar

  if ls "$search_dir"/apache-tomcat-"$major"*.tar.gz >/dev/null 2>&1; then
    local_tar="$(ls "$search_dir"/apache-tomcat-"$major".*.tar.gz | tail -n 1)"
    basename "$local_tar" | cut -d '-' -f 3 | cut -d '.' -f 1-3
  else
    curl --silent "https://dlcdn.apache.org/tomcat/tomcat-${major}/" \
      | grep "v${major}" \
      | tail -n 1 \
      | awk '{split($5,c,">v"); split(c[2],d,"/"); print d[1]}'
  fi
}

# Sends shutdown to all given tomcats, then waits until all of them are stopped, since
# shutdown.sh returns before tomcat is stopped and its folder will be removed afterwards.
shutdown_tomcats() {
  local name tomcat_dir running=()
  for name in "$@"; do
    tomcat_dir="$DEMO_DIR/$name"
    pgrep -f -- "-Dcatalina.base=$tomcat_dir " >/dev/null 2>&1 || continue
    echo "Stop $name"
    sh "$tomcat_dir/bin/shutdown.sh" >/dev/null 2>&1 || true
    running+=("$tomcat_dir")
  done

  local seconds=0
  for tomcat_dir in "${running[@]}"; do
    while pgrep -f -- "-Dcatalina.base=$tomcat_dir " >/dev/null 2>&1; do
      seconds=$((seconds + 1))
      [ "$seconds" -le 60 ] || error "tomcat $tomcat_dir is not stopped after 60 seconds"
      sleep 1
    done
  done
  [ "${#running[@]}" -eq 0 ] || echo "Stopped ${#running[@]} tomcat(s) in ${seconds}s"
}

install_component() {
  local installer="$1"
  local target="$2"
  "$script_dir/$installer" -t "$target"
}

cd "$script_dir"
"$java_exec" -cp "$classpath" -Ddemo.dir="$DEMO_DIR" \
  org.xipki.util.misc.BatchReplace setup/demo-conf.json

bash "$script_dir/prepare.sh"

mkdir -p "$DEMO_DIR"

tomcat_version="$(find_tomcat_version "$DEMO_DIR" "$TOMCAT_MAJOR_VERSION")"
echo "Tomcat ${tomcat_version}"

tomcat_dir="apache-tomcat-${tomcat_version}"
tomcat_binary="${tomcat_dir}.tar.gz"

echo "working dir: ${script_dir}"
cd "$DEMO_DIR"
echo "change to folder: $(pwd)"

if [ -f "$tomcat_binary" ]; then
  echo "Use local ${tomcat_binary}"
else
  echo "Download ${tomcat_binary}"
  tomcat_url="https://dlcdn.apache.org/tomcat/tomcat-${TOMCAT_MAJOR_VERSION}"
  curl --fail --location --remote-name "${tomcat_url}/v${tomcat_version}/bin/${tomcat_binary}"
fi

shutdown_tomcats ca-tomcat ocsp-tomcat gateway-tomcat

rm -rf ca-tomcat ocsp-tomcat gateway-tomcat "$tomcat_dir"
tar xf "$tomcat_binary"
rm -rf "$tomcat_dir/webapps"/*
cp -r "$tomcat_dir" ca-tomcat
cp -r "$tomcat_dir" ocsp-tomcat
mv "$tomcat_dir" gateway-tomcat

cd "$script_dir"
echo "change to folder: $(pwd)"

install_component xipki-ca/install.sh "$DEMO_DIR/ca-tomcat"
install_component xipki-ocsp/install.sh "$DEMO_DIR/ocsp-tomcat"
install_component xipki-gateway/install.sh "$DEMO_DIR/gateway-tomcat"

dbconf_dir="$script_dir/xipki-ca/tomcat/xipki/etc/ca/database/${DATABASE_TYPE}"
dbconf_ca="$dbconf_dir/ca-db.properties"
dbconf_caconf="$dbconf_dir/caconf-db.properties"
dbconf_ocsp="$dbconf_dir/ocsp-db.properties"

if [ "$DATABASE_TYPE" = "h2" ]; then
  rm -rf ~/.xipki/db/h2/
fi

cp "$dbconf_ca" "$dbconf_caconf" "$dbconf_ocsp" \
  "$DEMO_DIR/ca-tomcat/xipki/etc/ca/database/"
cp "$dbconf_ca" "$dbconf_ocsp" \
  "$DEMO_DIR/ocsp-tomcat/xipki/etc/ocsp/database/"

cd "$script_dir/xipki-mgmt-cli"
echo "change to folder: $(pwd)"

bin/xipki
