# syntax=docker/dockerfile:1.7

ARG TOMCAT_IMAGE=tomcat:10.1.48-jre25-temurin-noble
ARG BUILD_IMAGE=eclipse-temurin:25-jdk-noble
ARG JRE_IMAGE=eclipse-temurin:25-jre-noble
ARG XIPKI_SETUP_ARCHIVE=assemblies/xipki-setup/target/xipki-setup-7.0.0.tar.gz
ARG XIPKI_CONSOLE_JAR=console-server/target/xipki-console-server-7.0.0.jar

FROM ${BUILD_IMAGE} AS release

ARG XIPKI_SETUP_ARCHIVE

COPY ${XIPKI_SETUP_ARCHIVE} /tmp/xipki-setup.tar.gz
COPY --chmod=0755 deploy/docker/common/assemble-runtime.sh /usr/local/bin/assemble-runtime

RUN install -d /opt/xipki \
    && tar -xzf /tmp/xipki-setup.tar.gz --strip-components=1 -C /opt/xipki \
    && rm /tmp/xipki-setup.tar.gz \
    && assemble-runtime /opt/xipki

FROM ${TOMCAT_IMAGE} AS runtime-base

ARG XIPKI_UID=10001
ARG XIPKI_GID=10001

ENV XIPKI_BASE=/var/lib/xipki \
    XIPKI_RUNTIME_ROOT=/opt/xipki-runtime \
    XIPKI_REQUIRE_INITIALIZED=true \
    XIPKI_HEALTH_HOST=127.0.0.1 \
    XIPKI_HEALTH_MODE=tcp

USER root

# Tomcat keeps its examples and documentation in webapps.dist. XiPKI never deploys them, so omit
# the dormant applications from every public HTTP role as well as clearing the active webapps dir.
RUN rm -rf "${CATALINA_HOME}/webapps"/* "${CATALINA_HOME}/webapps.dist" \
    && groupadd --gid "${XIPKI_GID}" xipki \
    && useradd --uid "${XIPKI_UID}" --gid "${XIPKI_GID}" \
      --home-dir "${XIPKI_BASE}" --no-create-home --shell /usr/sbin/nologin xipki \
    && install -d -o xipki -g xipki -m 0750 \
      "${XIPKI_BASE}" \
      "${CATALINA_HOME}/logs" \
      "${CATALINA_HOME}/temp" \
      "${CATALINA_HOME}/webapps" \
      "${CATALINA_HOME}/work" \
      /opt/xipki-runtime/roles \
      /opt/xipki-runtime/console

COPY --chmod=0755 deploy/docker/common/entrypoint.sh /usr/local/bin/xipki-entrypoint
COPY --chmod=0755 deploy/docker/common/healthcheck.sh /usr/local/bin/xipki-healthcheck
COPY --chmod=0755 deploy/docker/common/role-init.sh /usr/local/bin/xipki-role-init

# Compile the database preflight helper separately so the short-lived Bootstrap runtime does not
# carry javac, jshell, or other JDK development tools into production.
FROM ${BUILD_IMAGE} AS bootstrap-compiler

COPY deploy/docker/bootstrap/ExternalDatabaseCheck.java /tmp/ExternalDatabaseCheck.java

RUN install -d /opt/xipki-bootstrap \
    && javac -d /opt/xipki-bootstrap /tmp/ExternalDatabaseCheck.java

FROM ${JRE_IMAGE} AS bootstrap

ARG XIPKI_UID=10001
ARG XIPKI_GID=10001

COPY --from=release --chown=${XIPKI_UID}:${XIPKI_GID} /opt/xipki/ /opt/xipki/
COPY --from=bootstrap-compiler --chown=${XIPKI_UID}:${XIPKI_GID} \
    /opt/xipki-bootstrap/ /opt/xipki-bootstrap/
COPY --chown=${XIPKI_UID}:${XIPKI_GID} deploy/docker/bootstrap/container-conf.json /opt/xipki/setup/container-conf.json
COPY --chmod=0755 deploy/docker/bootstrap/bootstrap.sh /usr/local/bin/xipki-bootstrap

RUN groupadd --gid "${XIPKI_GID}" xipki \
    && useradd --uid "${XIPKI_UID}" --gid "${XIPKI_GID}" \
      --home-dir /var/lib/xipki-bootstrap --no-create-home --shell /usr/sbin/nologin xipki \
    && install -d -o xipki -g xipki -m 0700 \
      /var/lib/xipki-bootstrap /state/admin /state/ca /state/console /state/gateway /state/ocsp

USER xipki:xipki
ENTRYPOINT ["xipki-bootstrap"]

FROM runtime-base AS xipki

ARG XIPKI_CONSOLE_JAR

USER root

# Each Tomcat role gets an isolated CATALINA_BASE. The common Tomcat installation stays in
# CATALINA_HOME, while role-specific configuration, libraries, and WARs remain selectable at
# runtime without exposing the other applications to Tomcat's auto-deployer.
RUN for role in ca gateway ocsp; do \
      role_base="${XIPKI_RUNTIME_ROOT}/roles/${role}"; \
      install -d "${role_base}/conf" "${role_base}/logs" "${role_base}/temp" \
        "${role_base}/webapps" "${role_base}/work"; \
      cp -a "${CATALINA_HOME}/conf/." "${role_base}/conf/"; \
    done

COPY --from=release --chown=xipki:xipki /opt/xipki/xipki-ca/tomcat/ /opt/xipki-runtime/roles/ca/
COPY --from=release --chown=xipki:xipki /opt/xipki/xipki-gateway/tomcat/ /opt/xipki-runtime/roles/gateway/
COPY --from=release --chown=xipki:xipki /opt/xipki/xipki-ocsp/tomcat/ /opt/xipki-runtime/roles/ocsp/

COPY --chown=xipki:xipki ${XIPKI_CONSOLE_JAR} /opt/xipki-runtime/console/console.jar
COPY --chown=xipki:xipki console-server/target/lib/ /opt/xipki-runtime/console/lib/

RUN for role in ca gateway ocsp; do \
      role_base="${XIPKI_RUNTIME_ROOT}/roles/${role}"; \
      rm -rf "${role_base}/xipki" "${role_base}/conf/server.xml"; \
      ln -s "${XIPKI_BASE}/xipki" "${role_base}/xipki"; \
      ln -s "${XIPKI_BASE}/conf/server.xml" "${role_base}/conf/server.xml"; \
      chown -R xipki:xipki "${role_base}"; \
    done \
    && chown -R xipki:xipki "${XIPKI_RUNTIME_ROOT}/console"

USER xipki:xipki
WORKDIR /opt/xipki-runtime

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=12 \
  CMD ["xipki-healthcheck"]

STOPSIGNAL SIGTERM
ENTRYPOINT ["xipki-entrypoint"]
