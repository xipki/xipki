#!/usr/bin/env sh
set -eu

echo "[1/4] Compile"
mvn -B -ntp -DskipTests compile

echo "[2/4] Java indentation lint"
sh tools/check-java-indent.sh

echo "[3/4] Targeted unit tests"
mvn -B -ntp -DskipTests -pl gateway,security -am test

echo "[4/4] Dependency CVE scan (fail on CVSS >= 8)"
DC_EXTRA=""
if [ -n "${NVD_API_KEY:-}" ]; then
  DC_EXTRA="-DnvdApiKey=${NVD_API_KEY}"
else
  echo "INFO: NVD_API_KEY not set. Dependency-Check may run much slower."
fi

mvn -B -ntp -DskipTests org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=8 ${DC_EXTRA}

echo "Release gate passed."
