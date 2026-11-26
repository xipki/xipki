# syntax=docker/dockerfile:1.7

ARG MARIADB_IMAGE=mariadb:11.4.12-noble

FROM ${MARIADB_IMAGE}

COPY --chmod=0755 deploy/compose/mariadb/init-databases.sh \
  /docker-entrypoint-initdb.d/10-xipki-databases.sh
COPY assemblies/xipki-setup/src/assembly/unfiltered/xipki-mgmt-cli/xipki/sql/mysql/ \
  /opt/xipki/sql/
