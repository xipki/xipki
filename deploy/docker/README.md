# XiPKI container images

This directory builds one XiPKI application image from the normal `xipki-setup` release archive and the Console server JAR, so container packaging cannot drift away from the supported distribution. The image is published as `docker.io/xipki/xipki:<version>`.

## Runtime contract

- Processes run as the fixed `xipki` user (`10001:10001` by default).
- Mutable state lives under `/var/lib/xipki`; application binaries remain in the image.
- A role starts only after bootstrap has atomically created `/var/lib/xipki/.initialized`.
- `XIPKI_ROLE=ca|gateway|ocsp|console` is the complete role-selection interface. Compose runs four separate containers from the same image; it does not run multiple XiPKI processes in one container.
- CA, Gateway, and OCSP use isolated `CATALINA_BASE` directories, so Tomcat only discovers the WAR and configuration for the selected role. Console remains a standalone Java process selected by the same entrypoint.
- Passwords, private keys, and generated certificates are supplied through the deployment state volume. They are never Docker build arguments or image environment defaults.
- Bootstrap supports a managed database container or a DBA-prepared external MariaDB/PostgreSQL service. External mode uses only the four application identities, verifies every required database and schema over JDBC, and never accepts a database administrator credential.
- The common health check supports TCP during the first container milestone and HTTP readiness endpoints as roles gain `/health/ready`.

Do not run the internal base stage directly or omit `XIPKI_ROLE`. The final `xipki` stage contains all four role runtimes, while its entrypoint selects exactly one and rejects unknown roles. The separate [`mariadb/Dockerfile`](mariadb/Dockerfile) and [`postgres/Dockerfile`](postgres/Dockerfile) package XiPKI's database initialization without requiring source files at deployment time. MariaDB is the deployment default; PostgreSQL remains optional. For the supported development workflow, use [`../compose/container.sh`](../compose/container.sh).
