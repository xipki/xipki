#!/usr/bin/env bash

set -e

error() {
  echo "ERROR: $*" >&2
  exit 1
}

copy_key_material() {
  local source_dir="$1"
  local target_dir="$2"
  shift 2
  mkdir -p "$target_dir"
  cp "$@" "$target_dir"
}

script_dir="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"
jars_dir="$script_dir"/setup/jars

cd "$script_dir"
echo "change to folder: $(pwd)"

cd "$script_dir"
echo "change to folder: $(pwd)"

echo "Copy jars to xipki-qa"

cp "$jars_dir"/jdbc/*.jar \
   "$jars_dir"/crypto/*   \
   xipki-mgmt-cli/lib/

echo "Replace Configuration and generate Key & Certificates"

java_exec="${JAVA_HOME:+$JAVA_HOME/bin/}java"
classpath="xipki-mgmt-cli/lib/*"

cd "$script_dir"
"$java_exec" -cp "$classpath" org.xipki.util.misc.BatchReplace setup/conf.json

kc_dir="$script_dir"/setup/keycerts
"$java_exec" -cp "$classpath" org.xipki.pkix.util.GenerateCerts setup/keycerts.json "$kc_dir"

echo "Copy xipki-mgmt-cli's folders lib to xipki-cli"
cp xipki-mgmt-cli/lib/* xipki-cli/lib

rm -f xipki-cli/lib/org.xipki.pki.ca-*-*.jar \
      xipki-cli/lib/org.xipki.pki.xipki-mgmt-cli-*.jar \
      xipki-cli/lib/org.xipki.pki.shell.ca-mgmt-shell-*.jar \
      xipki-cli/lib/org.xipki.pki.shell.demo-shell-*.jar

echo "Prepare tomcat"

echo "Prepare tomcat instances"

rm -rf "$script_dir"/war-common
mkdir -p "$script_dir"/war-common/WEB-INF/lib
cd "$script_dir"/war-common

echo "1. Prepare xipki-ocsp"

mkdir -p "$script_dir"/xipki-ocsp/tomcat/lib

cp "$jars_dir"/jdbc/*.jar "$script_dir"/xipki-ocsp/tomcat/lib/

cp "$jars_dir"/crypto/org.bouncycastle.*.jar \
   "$script_dir"/xipki-ocsp/tomcat/lib/ 2>/dev/null || true

cp $jars_dir/crypto/*.jar \
   "$script_dir"/xipki-mgmt-cli/lib/com.zaxxer.HikariCP-*.jar \
   "$script_dir"/xipki-mgmt-cli/lib/org.slf4j.*.jar \
   "$script_dir"/xipki-mgmt-cli/lib/org.xipki.crypto.*.jar \
   "$script_dir"/xipki-mgmt-cli/lib/org.xipki.pkix.*.jar \
   "$script_dir"/xipki-mgmt-cli/lib/org.xipki.pki.util-*.jar \
   "$jars_dir"/misc/org.xipki.pki.servlet.servlet-common-*.jar \
   "$script_dir"/war-common/WEB-INF/lib

# bouncycastle already in the tomcat's lib dir
rm -f "$script_dir"/war-common/WEB-INF/lib/org.bouncycastle.*.jar

zip -r "$script_dir"/xipki-ocsp/tomcat/webapps/ocsp.war .

echo "2. Prepare xipki-gateway"

mkdir -p "$script_dir"/xipki-gateway/tomcat/lib

cp "$jars_dir"/jdbc/*.jar "$script_dir"/xipki-gateway/tomcat/lib/

cp "$jars_dir"/crypto/org.bouncycastle.*.jar \
   "$script_dir"/xipki-gateway/tomcat/lib/ 2>/dev/null || true

cp "$jars_dir"/misc/org.xipki.pki.ca-sdk-*.jar \
   "$script_dir"/war-common/WEB-INF/lib

zip -r "$script_dir/xipki-gateway/tomcat/webapps/gw.war" .

echo "3. Prepare xipki-ca"

mkdir -p "$script_dir"/xipki-ca/tomcat/lib

cp "$jars_dir"/jdbc/*.jar "$script_dir"/xipki-ca/tomcat/lib/

cp "$jars_dir"/crypto/org.bouncycastle.*.jar \
   "$script_dir"/xipki-ca/tomcat/lib/ 2>/dev/null || true

cp "$script_dir"/xipki-mgmt-cli/lib/org.xipki.pki.ca-api-*.jar \
   "$script_dir"/war-common/WEB-INF/lib

zip -r "$script_dir"/xipki-ca/tomcat/webapps/ca.war .

rm -rf "$script_dir"/war-common

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
