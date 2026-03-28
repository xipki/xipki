#!/usr/bin/env bash

set -e

error() {
  echo "ERROR: $*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"

jars_jdbc_dir="setup/jars/jdbc"
jars_bc_dir="setup/jars/bouncycastle"
jars_xipki_dir="setup/jars/xipki"

shopt -s nullglob
jdbc_jars=("$jars_jdbc_dir"/*.jar)
bc_jars=("$jars_bc_dir"/*.jar)
bcutil_lts_jars=("$jars_bc_dir"/bcutil-lts8on-*.jar)
bcutil_fips_jars=("$jars_bc_dir"/bcutil-fips-*.jar)
bcutil_std_jars=("$jars_bc_dir"/bcutil-jdk8on-*.jar)
shopt -u nullglob

[ ${#jdbc_jars[@]} -gt 0 ] || error "no jar file found in $jars_jdbc_dir"
[ ${#bc_jars[@]} -gt 0 ] || error "no jar file found in $jars_bc_dir"

cd "$script_dir"
echo "change to folder: $(pwd)"

if [ ${#bcutil_lts_jars[@]} -gt 0 ]; then
  bcbridge_jar="$jars_xipki_dir"/bcbridge-lts*.jar;
elif [ ${#bcutil_fips_jars[@]} -gt 0 ]; then
  bcbridge_jar="$jars_xipki_dir"/bcbridge-fips*.jar;
elif [ ${#bcutil_std_jars[@]} -gt 0 ]; then
  bcbridge_jar="$jars_xipki_dir"/bcbridge-lts*.jar;
else
  error "none of bcutil-{lts8on|fips|jdk8on}-*.jar found in $jars_bc_dir"
fi

script_dir="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"
java_exec="${JAVA_HOME:+$JAVA_HOME/bin/}java"
classpath="xipki-mgmt-cli/lib/*"

copy_tree_contents() {
  local src_dir="$1"
  local dest_dir="$2"
  mkdir -p "$dest_dir"
  cp -r "$src_dir"/* "$dest_dir"/
}

copy_key_material() {
  local source_dir="$1"
  local target_dir="$2"
  shift 2
  mkdir -p "$target_dir"
  cp "$@" "$target_dir"
}

cd "$script_dir"
echo "change to folder: $(pwd)"

echo "Copy xipki-mgmt-cli's folders lib to xipki-cli"
copy_tree_contents xipki-mgmt-cli/lib xipki-cli/lib
rm -f xipki-cli/lib/ca-api*.jar \
      xipki-cli/lib/ca-mgmt*.jar \
      xipki-cli/lib/certprofile*.jar \
      xipki-cli/lib/ca-mgmt-shell*.jar \
      xipki-cli/lib/xipki-mgmt-cli*.jar \
      xipki-cli/lib/demo-shell*.jar

echo "Prepare tomcat"
mkdir -p xipki-ca/tomcat/lib xipki-ocsp/tomcat/lib xipki-gateway/tomcat/lib

echo "Copy bcbridge jar"
cp $bcbridge_jar xipki-mgmt-cli/lib/
cp $bcbridge_jar xipki-cli/lib/
cp $bcbridge_jar xipki-ca/tomcat/lib/
cp $bcbridge_jar xipki-ocsp/tomcat/lib/
cp $bcbridge_jar xipki-gateway/tomcat/lib/

echo "Copy bouncycastle jars"
cp "$jars_bc_dir"/*.jar xipki-mgmt-cli/lib/
cp "$jars_bc_dir"/*.jar xipki-cli/lib/
cp "$jars_bc_dir"/*.jar xipki-ca/tomcat/lib/
cp "$jars_bc_dir"/*.jar xipki-ocsp/tomcat/lib/
cp "$jars_bc_dir"/*.jar xipki-gateway/tomcat/lib/

echo "Copy JDBC driver jars"
cp "$jars_jdbc_dir"/*.jar xipki-mgmt-cli/lib/
cp "$jars_jdbc_dir"/*.jar xipki-ca/tomcat/lib/
cp "$jars_jdbc_dir"/*.jar xipki-ocsp/tomcat/lib/
cp "$jars_jdbc_dir"/*.jar xipki-gateway/tomcat/lib/

echo "Copy $script_dir/war-common/ to war files (ca.war, ocsp.war, gw.war)"
rm -rf "$script_dir/war-common"
mkdir -p "$script_dir/war-common/WEB-INF/lib"
cp xipki-mgmt-cli/lib/HikariCP-${hikaricp.version}.jar \
   xipki-mgmt-cli/lib/codec-${project.version}.jar \
   xipki-mgmt-cli/lib/pkcs11-${project.version}.jar \
   xipki-mgmt-cli/lib/security-${project.version}.jar \
   xipki-mgmt-cli/lib/util-${project.version}.jar \
   xipki-mgmt-cli/lib/util-extra-${project.version}.jar \
   xipki-mgmt-cli/lib/xihsm-${project.version}.jar \
   xipki-mgmt-cli/lib/slf4j-api-*.jar \
   xipki-mgmt-cli/lib/slf4j-jdk14-*.jar \
   "$script_dir/war-common/WEB-INF/lib"

cd "$script_dir/war-common"
zip -r "$script_dir/xipki-ocsp/tomcat/webapps/ocsp.war" .
zip -r "$script_dir/xipki-gateway/tomcat/webapps/gw.war" .
cp "$script_dir"/xipki-mgmt-cli/lib/ca-api-*.jar \
   "$script_dir"/xipki-mgmt-cli/lib/certprofile-*.jar \
   "$script_dir/war-common/WEB-INF/lib"
zip -r "$script_dir/xipki-ca/tomcat/webapps/ca.war" .
rm -rf "$script_dir/war-common"

cd "$script_dir"
"$java_exec" -cp "$classpath" org.xipki.util.extra.misc.BatchReplace setup/conf.json

kc_dir="setup/keycerts"
"$java_exec" -cp "$classpath" org.xipki.security.util.GenerateCerts setup/keycerts.json "$kc_dir"

ks_dir="$kc_dir/certstore"

echo "Copying generated keys to the XiPKI component xipki-ca"
copy_key_material "$kc_dir" "$script_dir/xipki-ca/tomcat/xipki/keycerts" \
  "$kc_dir"/ca-server/* \
  "$kc_dir"/ca-mgmt-client/*-cert.pem \
  "$ks_dir"/ca-client-certstore.p12

echo "Copying generated keys to the XiPKI component xipki-gateway"
copy_key_material "$kc_dir" "$script_dir/xipki-gateway/tomcat/xipki/keycerts" \
  "$kc_dir"/gateway-server/* \
  "$kc_dir"/ra-sdk-client/* \
  "$kc_dir"/cmp-client/*-cert.pem \
  "$kc_dir"/est-client/*-cert.pem \
  "$kc_dir"/rest-client/*-cert.pem \
  "$kc_dir"/ca-server/ca-server-cert.pem \
  "$ks_dir"/gateway-client-ca-certstore.p12 \
  "$kc_dir"/dh-pop/dh-pop.p12 \
  "$kc_dir"/secretkeys/kem-pop.jceks

echo "Copying generated keys to the XiPKI component xipki-cli"
copy_key_material "$kc_dir" "$script_dir/xipki-cli/xipki/keycerts" \
  "$kc_dir"/cmp-client/* \
  "$kc_dir"/est-client/* \
  "$kc_dir"/rest-client/* \
  "$kc_dir"/gateway-server/gateway-server-cert.pem \
  "$kc_dir"/dh-pop/dh-pop-certs.pem \
  "$kc_dir"/secretkeys/kem-pop.jceks

echo "Copying generated keys to the XiPKI component xipki-mgmt-cli"
copy_key_material "$kc_dir" "$script_dir/xipki-mgmt-cli/xipki/keycerts" \
  "$kc_dir"/cmp-client/* \
  "$kc_dir"/est-client/* \
  "$kc_dir"/rest-client/* \
  "$kc_dir"/gateway-server/gateway-server-cert.pem \
  "$kc_dir"/dh-pop/dh-pop-certs.pem \
  "$kc_dir"/secretkeys/kem-pop.jceks \
  "$kc_dir"/ra-sdk-client/ra-sdk-client-cert.pem \
  "$kc_dir"/ca-mgmt-client/*.p12 \
  "$kc_dir"/ca-mgmt-client/*-cert.pem \
  "$kc_dir"/ca-server/ca-server-cert.pem
