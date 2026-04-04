---
marp: true
theme: default
paginate: true
size: 16:9
title: XiPKI Technical Deep Dive
description: Technical deep dive for PKI engineers
---

# XiPKI Technical Deep Dive

PKI engineering view  

Dr. Lijun Liao

---

# What XiPKI Is

- Open-source PKI platform for CA, RA/gateway, and OCSP
- Designed for critical infrastructure and automation-heavy environments
- Focuses on performance, modularity, and operational control
- Supports PQC-ready and HSM-backed deployments

---

# Why PKI Engineers Care

- Broad protocol support in one platform
- Strong PKCS#11 and HSM integration
- Flexible CA and OCSP deployment models
- Scriptable setup and operations
- Support for modern and PQC algorithms

---

# High-Level System View

- CA service for issuance and revocation
- OCSP service for certificate status
- Gateway service for enrollment protocols
- Management CLI and APIs for administration

---

# Gateway-Centric Architecture

```text
           ACME
           CMP
Client <-- EST  --> Gateway <-- CBOR Messages --> CA
           REST
           SCEP
```

- Clients integrate through standard enrollment protocols
- Gateway normalizes external protocol traffic
- Gateway and CA communicate via compact CBOR messages optimized for high performance and low resource usage
- This keeps client-facing protocol handling separate from CA core logic

---

# XiPKI Repository Structure

- Base modules: `codec`, `util`, `util-extra`
- Security modules: `security`, `pkcs11`, `xihsm`, `bcbridge-lts8on`, `bcbridge-fips`
- PKI services: `ca-api`, `ca-server`, `ca-mgmt`, `ocsp-api`, `ocsp-server`, `gateway`
- Operations: `shells`, `servlets`, `assemblies`
- QA: `qa`

---

# Packaging Model

- `xipki-setup-6.7.0-bclts.tar.gz`: about 17 MB, including Bouncy Castle LTS jars
- `xipki-setup-6.7.0-bcfips.tar.gz`: about 19 MB, including Bouncy Castle FIPS jars
- `xipki-setup-6.7.0-thin.tar.gz`: about 6 MB, without JDBC or Bouncy Castle jars

---

# Runtime Topology

- CA can run in multiple parallel active instances
- OCSP can run in multiple parallel active instances
- Gateway can run in multiple parallel active instances
- CLI distributions handle admin, setup, and QA workflows
- Database stores CA config, CA data, and OCSP data

---

# Core Roles in the Platform

- CA: issue certs, revoke certs, generate CRLs
- OCSP: provide certificate status at scale
- Gateway: expose enrollment and management protocols
- CLI: automate provisioning and operations
- QA: validate end-to-end behaviors and scenarios

---

# CA Responsibilities

- X.509 certificate issuance
- CRL generation
- Policy and certificate profile enforcement
- Publisher integration
- Multi-CA operation in one software instance
- Clustered and active-active deployment support

---

# OCSP Responsibilities

- RFC 6960 and RFC 5019 support
- Multiple certificate status backends
- Supports XiPKI CA DB, published OCSP DB, CRLs, and EJBCA DB
- Additional certificate status sources can be integrated via plugins
- Signed and unsigned request support
- High-volume and active-active deployment orientation

---

# OCSP Efficiency

- OCSP response cache reduces repeated response generation
- Minimal conversion between byte streams and Java objects
- Reduced parsing and object creation overhead
- Optimized for high-volume responder workloads

---

# OCSP Memory Profile

- Stream-based CRL parsing
- Useful for very large CRLs, for example 100 MB
- Avoids loading oversized CRLs fully into memory
- Practical for large revocation datasets and constrained deployments

---

# Gateway Responsibilities

- EST support, including XiPKI-specific `u` commands that complement standard EST with simpler raw and PEM responses
- SCEP support
- CMP support
- ACME support
- XiPKI REST API support
- Protocol front end between clients, RAs, and the CA
- Can be horizontally extended with multiple active instances

---

# XiPKI EST `u` Commands vs Standard EST

| Standard EST | XiPKI `u` | Main difference |
| --- | --- | --- |
| `cacerts` | `ucacerts` | CA certificates as PEM instead of PKCS#7 |
| N/A | `ucacert` | A single CA certificate as raw `application/pkix-cert` |
| N/A | `ucrl` | Current CRL as raw `application/pkix-crl` |
| `simpleenroll` | `usimpleenroll` | Raw issued certificate instead of PKCS#7 certs-only |
| `simplereenroll` | `usimplereenroll` | Raw issued certificate instead of PKCS#7 certs-only |
| `serverkeygen` | `userverkeygen` | PEM private key plus certificate instead of multipart EST packaging |

---

# Management Plane

- CA management API
- Management client
- Shell-based administration
- Script-driven setup and lifecycle changes
- Strong fit for reproducible operations and automation

---

# One-Step Scripted Configuration

- XiPKI can be configured via script files in one step
- End-to-end setup can run without man-in-loop interaction
- This is useful for reproducible lab setup, CI pipelines, and automated provisioning
- It reduces manual console work and helps keep PKI environments consistent

---

# CLI Model

- `xipki-cli` for general PKI operations
- `xipki-mgmt-cli` for CA management
- `xipki-qa-cli` for validation and testing
- Interactive commands plus script execution
- Useful for repeatable setup and operational runbooks

---

# Demo Experience

- `demo.sh` prepares a working XiPKI environment
- Local demo stands up CA, OCSP, and gateway instances
- H2-backed setup is convenient for evaluation
- Useful for onboarding engineers and testing workflows

---

# Supported Platforms

- Java 11+
- Linux, Windows, macOS
- Tomcat, Jetty, and in principle any HTTP server
- DB2, MariaDB, MySQL, Oracle, PostgreSQL, H2, HSQLDB
- Broad deployment flexibility for enterprise PKI

---

# HSM and PKCS#11 Integration

- Native PKCS#11 support is a core capability
- Designed for hardware-backed key generation and signing
- Supports many HSM vendors through PKCS#11
- Useful for CA keys, responder keys, and key lifecycle control

---

# PKCS#11 Architecture

```text
Application <--> XiPKI-PKCS11 +-- PKCS#11 -- HSM Device
                              |
                              +-- XiHSM (XiPKI HSM Simulator)
                              |
                              +-- Plugin, e.g. HSM Proxy
```

- XiPKI uses its own PKCS#11 integration layer between the application and token backends
- The same architecture can target real HSM devices, the XiHSM simulator, or plugin-based integrations
- This keeps token access consistent while allowing backend-specific extensions where needed

---

# HSM Support Approach

- XiPKI does not rely on the JCE PKCS#11 provider due to limitations:
  - Available only in some JREs
  - Limited algorithm support, with no practical support for current PQC algorithms
  - Very limited flexibility for fine-grained control of PKCS#11 keys and objects
- XiPKI instead uses its own precise PKCS#11 wrapper:
  - Support for PKCS#11 v3.2
  - Support for vendor-specific HSM functions
  - Fine-grained control, for example wrapper templates and key usage
  - Extensible toward nearly all PKCS#11 features needed by the platform

---

# Classical Algorithm Support

- RSA
- EC / ECDSA
- Ed25519 and Ed448
- X25519 and X448
- SM2 / SM3
- SHA-1, SHA-2, SHA-3, and SHAKE where applicable

---

# Post-Quantum Cryptography Support

- ML-DSA
- ML-KEM
- Composite ML-DSA
- Composite ML-KEM
- PQC support is one of XiPKI's strongest differentiators
- Useful for lab, migration, and transition planning

---

# Certificate Profile: Fine-Grained Control

- JSON-based certificate profile support
- No hardcoding in most scenarios
- Maximal certificate size
- Certificate level: root CA, cross CA, sub CA, end entity
- Certificate validity: duration or undefined (`99991231235959Z`)
- `notBefore`: current time or midnight
- Allowed signature algorithms
- Allowed public key algorithms and key sizes or curves
- Subject control: RDN order, occurrences of each RDN, and validation rules
- Extensions: native support for most extensions, others configurable via a generic method

---

# Certificate Profile Validation

- XiPKI provides code to verify that generated certificates conform to the configured certificate profiles
- This helps engineers validate profile behavior beyond issuance success alone
- Useful for regression testing, QA automation, and profile evolution
- Strengthens confidence that issued certificates match policy intent

---

# X.509 and Policy Breadth

- RFC 5280 support
- eIDAS-related standards support
- CT-related support
- Standard and custom extensions
- Suitable for enterprise and regulated PKI scenarios

---

# Configuration Model

- Most CA configuration lives in the database
- Database acts as operational source of truth
- Useful for clustering and repeatable provisioning
- Reduces dependence on hand-edited local files
- Supports management through API and CLI

---

# Password Configuration Options

- Passwords can be configured in plain text, obfuscated form, or encrypted form
- Plain-text configuration is supported but not recommended
- Obfuscated and encrypted forms help reduce direct secret exposure in configuration
- This is useful for scripted deployment and operational hardening

---

# Performance Orientation

- XiPKI is designed as a high-performance PKI platform
- OCSP is explicitly optimized for high-volume scenarios
- Compact modular architecture reduces unnecessary runtime overhead
- Services can be deployed separately and scaled independently
- Built for performance-sensitive PKI deployments

---

# Low Resource Consumption

- Compact codebase: about 120 KLOC
- Small install footprint: about 18 MB for the setup package
- Thin distribution is under 6 MB without bundled JDBC and Bouncy Castle jars
- Compact design and minimal dependencies reduce the operational footprint
- Useful for constrained environments and lean deployments

---

# Minimal Dependencies

- XiPKI keeps its third-party dependency set intentionally small
- Core external dependencies are mainly: SLF4J, dnsjava, HikariCP, Bouncy Castle, JLine, and Picocli
- No database ORM or Hibernate-style dependency layer
- No external JSON or CBOR third-party libraries
- No third-party PKCS#11 wrapper libraries
- Smaller dependency surface helps reduce startup overhead, packaging size, and upgrade complexity
- This also makes the system easier to inspect, operate, and troubleshoot

---

# High Availability and Scale

- Multiple instances can serve the same CA in active mode
- Multiple OCSP responders can run active-active
- Gateway tier can scale independently with multiple active nodes
- DB-backed coordination enables clustered designs
- Suitable for segmented and redundant deployments

---

# Engineering Strengths

- Open source and inspectable
- Strong automation model
- Broad protocol support
- Modern crypto support including PQC
- High-performance design with small footprint and minimal dependencies
- Practical for engineers who want control

---

# Best-Fit Deployment Scenarios

- Enterprise private PKI
- Critical infrastructure PKI
- HSM-backed issuance environments
- High-scale OCSP
- Protocol gateway consolidation
- PQC experimentation and transition planning

---

# Key Takeaways

- XiPKI is a modular PKI platform, not just a CA
- It is strongest where automation, protocols, and HSMs matter
- It stands out for PQC and composite-algorithm support
- It fits PKI engineering teams that value operational control and extensibility

---

# Q&A
