# syntax=docker/dockerfile:1.7

ARG POSTGRES_IMAGE=postgres:17.6-alpine3.22

FROM ${POSTGRES_IMAGE}

COPY --chmod=0755 deploy/compose/postgres/init-databases.sh \
  /docker-entrypoint-initdb.d/10-xipki.sh
COPY assemblies/xipki-setup/src/assembly/unfiltered/xipki-mgmt-cli/xipki/sql/postgresql/ \
  /opt/xipki/sql/
