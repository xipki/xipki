#!/usr/bin/env bash

set -e

BOUNCYCASTLE_MODE_CLIENT=LTS
BOUNCYCASTLE_MODE_SERVER=LTS
TBDIR=~/test/xipki
DATABASE_TYPE=h2
TOMCAT_MAJOR_VERSION=10

script_dir="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"
java_exec="${JAVA_HOME:+$JAVA_HOME/bin/}java"

find_tomcat_version() {
  local base_dir="$1"
  local major="$2"
  if ls "$base_dir"/apache-tomcat-"$major"*.tar.gz >/dev/null 2>&1; then
    local file
    file="$(ls "$base_dir"/apache-tomcat-"$major".*.tar.gz | tail -n 1)"
    basename "$file" | cut -d '-' -f 3 | cut -d '.' -f 1-3
  else
    curl --silent "http://dlcdn.apache.org/tomcat/tomcat-${major}/" \
      | grep "v${major}" | tail -n 1 \
      | awk '{split($5,c,">v"); split(c[2],d,"/"); print d[1]}'
  fi
}

shutdown_tomcat() {
  local name="$1"
  sh "$TBDIR/$name/bin/shutdown.sh" >/dev/null 2>&1 || true
}

copy_tree_contents() {
  local src_dir="$1"
  local dest_dir="$2"
  mkdir -p "$dest_dir"
  cp -r "$src_dir"/* "$dest_dir"/
}

if [ "$TOMCAT_MAJOR_VERSION" -lt 10 ]; then
  echo "Unsupported tomcat major version ${TOMCAT_MAJOR_VERSION}"
  exit 1
fi

mkdir -p "$TBDIR"
tomcat_version="$(find_tomcat_version "$TBDIR" "$TOMCAT_MAJOR_VERSION")"
echo "Tomcat ${tomcat_version}"

tomcat_dir="apache-tomcat-${tomcat_version}"
tomcat_binary="${tomcat_dir}.tar.gz"

echo "working dir: ${script_dir}"

if [ -d "$TBDIR/jdk-tomcat" ]; then
  tomcat_java_home="--env JAVA_HOME=${TBDIR}/jdk-tomcat"
else
  tomcat_java_home=""
fi

cd "$TBDIR"
echo "change to folder: $(pwd)"

if [ -f "$tomcat_binary" ]; then
  echo "Use local ${tomcat_binary}"
else
  echo "Download ${tomcat_binary}"
  wget --no-check-certificate "https://dlcdn.apache.org/tomcat/tomcat-${TOMCAT_MAJOR_VERSION}/v${tomcat_version}/bin/${tomcat_binary}"
fi

shutdown_tomcat ca-tomcat
shutdown_tomcat ocsp-tomcat
shutdown_tomcat gateway-tomcat
shutdown_tomcat dummy-tomcat

rm -rf ca-tomcat ocsp-tomcat gateway-tomcat dummy-tomcat "$tomcat_dir"
tar xf "$tomcat_binary"
rm -rf "$tomcat_dir/webapps"/*
cp -r "$tomcat_dir" ca-tomcat
cp -r "$tomcat_dir" ocsp-tomcat
cp -r "$tomcat_dir" gateway-tomcat
mv "$tomcat_dir" dummy-tomcat

cd "$script_dir"
echo "change to folder: $(pwd)"

rm -f xipki-qa-cli/lib/bc*-lts*.jar xipki-qa-cli/lib/bc*-fips-*.jar

mkdir -p xipki-ca/tomcat/lib xipki-ocsp/tomcat/lib xipki-gateway/tomcat/lib xipki-dummy/tomcat/lib
rm -f xipki-ca/tomcat/lib/bc*-lts*.jar xipki-ca/tomcat/lib/bc*-fips-*.jar
rm -f xipki-ocsp/tomcat/lib/bc*-lts*.jar xipki-ocsp/tomcat/lib/bc*-fips-*.jar
rm -f xipki-gateway/tomcat/lib/bc*-lts*.jar xipki-gateway/tomcat/lib/bc*-fips-*.jar
rm -f xipki-dummy/tomcat/lib/bc*-lts*.jar xipki-dummy/tomcat/lib/bc*-fips-*.jar

echo "Copy JDBC jars"
jars_dir=setup/jars

cp $jars_dir/jdbc/*.jar xipki-qa-cli/lib/
cp $jars_dir/jdbc/*.jar xipki-ca/tomcat/lib/
cp $jars_dir/jdbc/*.jar xipki-ocsp/tomcat/lib/
cp $jars_dir/jdbc/*.jar xipki-gateway/tomcat/lib/
cp $jars_dir/jdbc/*.jar xipki-dummy/tomcat/lib/

if [ "$BOUNCYCASTLE_MODE_CLIENT" = "LTS" ]; then
  echo "Client: copy BouncyCastle LTS jars"
  cp $jars_dir/bclts/* xipki-qa-cli/lib/
  cp $jars_dir/xipki/bcbridge-lts* xipki-qa-cli/lib/
else
  echo "Client: copy BouncyCastle FIPS jars to xipki-qa-cli"
  cp $jars_dir/bcfips/* xipki-qa-cli/lib/
  cp $jars_dir/xipki/bcbridge-fips* xipki-qa-cli/lib/
fi

if [ "$BOUNCYCASTLE_MODE_SERVER" = "LTS" ]; then
  echo "Server: copy BouncyCastle LTS jars to xipki-ca"
  cp $jars_dir/bclts/* xipki-ca/tomcat/lib/
  cp $jars_dir/xipki/bcbridge-lts* xipki-ca/tomcat/lib/
else
  echo "Server: copy BouncyCastle FIPS jars to xipki-ca"
  cp $jars_dir/bcfips/* xipki-ca/tomcat/lib/
  cp $jars_dir/xipki/bcbridge-fips* xipki-ca/tomcat/lib/
fi

echo "Copy JDBC & BouncyCastle jars to xipki-ocsp, xipki-gateway, and xipki-dummy"
copy_tree_contents xipki-ca/tomcat/lib xipki-ocsp/tomcat/lib
copy_tree_contents xipki-ca/tomcat/lib xipki-gateway/tomcat/lib
copy_tree_contents xipki-ca/tomcat/lib xipki-dummy/tomcat/lib

rm -rf "$script_dir/war-common"
mkdir -p "$script_dir/war-common/WEB-INF/lib"
cp xipki-qa-cli/lib/HikariCP-${hikaricp.version}.jar \
   xipki-qa-cli/lib/codec-${project.version}.jar \
   xipki-qa-cli/lib/pkcs11-${project.version}.jar \
   xipki-qa-cli/lib/security-${project.version}.jar \
   xipki-qa-cli/lib/util-${project.version}.jar \
   xipki-qa-cli/lib/util-extra-${project.version}.jar \
   xipki-qa-cli/lib/xihsm-${project.version}.jar \
   xipki-qa-cli/lib/slf4j-api-*.jar \
   xipki-qa-cli/lib/slf4j-jdk14-*.jar \
   "$script_dir/war-common/WEB-INF/lib"

classpath="xipki-qa-cli/lib/*"
"$java_exec" -cp "$classpath" \
  -Ddatabase.type="$DATABASE_TYPE" -Dtest.basedir="$TBDIR" \
  -Dtomcat.java.home="$tomcat_java_home" \
  org.xipki.util.extra.misc.BatchReplace setup/conf.json
"$java_exec" -cp "$classpath" org.xipki.security.util.GenerateCerts setup/keycerts.json setup/keycerts

cd "$script_dir/war-common"
zip -r "$script_dir/xipki-ocsp/tomcat/webapps/ocsp.war" .
zip -r "$script_dir/xipki-gateway/tomcat/webapps/gw.war" .
zip -r "$script_dir/xipki-dummy/tomcat/webapps/dummy.war" .
cp "$script_dir"/xipki-qa-cli/lib/ca-api-*.jar \
   "$script_dir"/xipki-qa-cli/lib/certprofile-*.jar \
   "$script_dir/war-common/WEB-INF/lib"
zip -r "$script_dir/xipki-ca/tomcat/webapps/ca.war" .
rm -rf "$script_dir/war-common"

kc_dir="$script_dir/setup/keycerts"
ks_dir="$kc_dir/certstore"

mkdir -p "$script_dir/xipki-ca/tomcat/xipki/keycerts"
cp "$kc_dir"/ca-server/* \
   "$kc_dir"/ca-mgmt-client/ca-mgmt-client-cert.pem \
   "$kc_dir"/dummy-server/dummy-server-cert.pem \
   "$ks_dir"/ca-client-certstore.p12 \
   "$script_dir/xipki-ca/tomcat/xipki/keycerts"

mkdir -p "$script_dir/xipki-ocsp/tomcat/xipki/keycerts"

mkdir -p "$script_dir/xipki-gateway/tomcat/xipki/keycerts"
cp "$kc_dir"/gateway-server/* \
   "$kc_dir"/ra-sdk-client/* \
   "$kc_dir"/ca-server/ca-server-cert.pem \
   "$ks_dir"/gateway-client-ca-certstore.p12 \
   "$kc_dir"/dh-pop/dh-pop.p12 \
   "$kc_dir"/cmp-client/cmp-client-cert.pem \
   "$kc_dir"/est-client/est-client-cert.pem \
   "$kc_dir"/rest-client/rest-client-cert.pem \
   "$kc_dir"/secretkeys/kem-pop.jceks \
   "$script_dir/xipki-gateway/tomcat/xipki/keycerts"

mkdir -p "$script_dir/xipki-dummy/tomcat/xipki/keycerts"
cp "$kc_dir"/dummy-server/* \
   "$script_dir/xipki-dummy/tomcat/xipki/keycerts"

mkdir -p "$script_dir/xipki-qa-cli/xipki/keycerts"
cp "$kc_dir"/ca-mgmt-client/* \
   "$kc_dir"/cmp-client/* \
   "$kc_dir"/est-client/* \
   "$kc_dir"/rest-client/* \
   "$kc_dir"/ocsp-client/* \
   "$kc_dir"/ca-server/* \
   "$kc_dir"/gateway-server/* \
   "$kc_dir"/dh-pop/dh-pop-certs.pem \
   "$kc_dir"/ra-sdk-client/ra-sdk-client.p12 \
   "$kc_dir"/ra-sdk-client/ra-sdk-client-cert.pem \
   "$kc_dir"/secretkeys/kem-pop.jceks \
   "$script_dir/xipki-qa-cli/xipki/keycerts"

pki_ui_dir="$TBDIR/pki-ui"

mkdir -p "$pki_ui_dir/keycerts"
cp "$kc_dir"/ca-server/ca-server-cert.pem \
   "$kc_dir"/ca-mgmt-client/ca-mgmt-client.p12 \
   "$pki_ui_dir/keycerts"

tomcat_dir_ca="$TBDIR/ca-tomcat"
tomcat_dir_ocsp="$TBDIR/ocsp-tomcat"
tomcat_dir_gateway="$TBDIR/gateway-tomcat"
tomcat_dir_dummy="$TBDIR/dummy-tomcat"

for tomcat_dir in "$tomcat_dir_ca" "$tomcat_dir_ocsp" "$tomcat_dir_gateway" "$tomcat_dir_dummy"; do
  echo "tomcat dir: ${tomcat_dir}"
  rm -rf "$tomcat_dir/webapps" "$tomcat_dir/logs/"* "$tomcat_dir/xipki"
  rm -rf "$tomcat_dir"/lib/bc*.jar \
         "$tomcat_dir"/lib/mariadb-java-client-*.jar \
         "$tomcat_dir"/lib/postgresql-*.jar \
         "$tomcat_dir"/lib/h2-*.jar
done

cp -r "$script_dir/xipki-ca/tomcat/"* "$tomcat_dir_ca/"
cp -r "$script_dir/xipki-ocsp/tomcat/"* "$tomcat_dir_ocsp/"
cp -r "$script_dir/xipki-gateway/tomcat/"* "$tomcat_dir_gateway/"
cp -r "$script_dir/xipki-dummy/tomcat/"* "$tomcat_dir_dummy/"

rm -rf ~/.xipki/db/h2/

cp "$script_dir"/xipki-ca/tomcat/xipki/etc/ca/database/"$DATABASE_TYPE"/* \
   "$tomcat_dir_ca/xipki/etc/ca/database/"

mkdir -p "$tomcat_dir_dummy/xipki/etc/ca/database/"
cp "$script_dir"/xipki-ca/tomcat/xipki/etc/ca/database/"$DATABASE_TYPE"/ca-db.properties \
   "$tomcat_dir_dummy/xipki/etc/ca/database/"

cp "$script_dir"/xipki-ocsp/tomcat/xipki/etc/ocsp/database/"$DATABASE_TYPE"/* \
   "$tomcat_dir_ocsp/xipki/etc/ocsp/database/"
cp "$tomcat_dir_ocsp"/xipki/etc/ocsp/database/h2/ocsp-cache-db.properties \
   "$tomcat_dir_ocsp/xipki/etc/ocsp/database/"

cp "$script_dir"/xipki-gateway/tomcat/xipki/etc/acme/database/"$DATABASE_TYPE"/* \
   "$tomcat_dir_gateway/xipki/etc/acme/database/"

cd "$script_dir/xipki-qa-cli"
echo "change to folder: $(pwd)"

bin/xipki