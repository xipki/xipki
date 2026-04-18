# XiPKI Copilot Instructions

## Quick Reference

**Project**: XiPKI - Extensible simple Public Key Infrastructure (CA, OCSP, Gateway)  
**Language**: Java 11+  
**Build System**: Maven with multi-module structure (40 modules)  
**Key Frameworks**: Bouncy Castle (LTS/FIPS variants), PKCS#11, Jakarta Servlet 5.0

## Build and Test Commands

### Build the entire project
```bash
./install.sh
# or
mvn clean install -DskipTests
```

### Run tests for a specific module
```bash
mvn test -pl :<module-name>
# Example:
mvn test -pl :security
```

### Run all tests
```bash
mvn test
# Note: This runs all tests in modules that have src/test/java/
```

### Run a specific test class
```bash
mvn test -Dtest=TestClassName -pl :<module-name>
# Example:
mvn test -Dtest=GetInfoTest -pl :pkcs11test
```

### Compile without running tests (CI build)
```bash
mvn -DskipTests clean install
```

### Build individual modules
```bash
mvn clean install -pl :<module-name>
# Example: Build only ca-server
mvn clean install -pl :ca-server
```

## Architecture Overview

### High-Level System Design

XiPKI follows a **gateway-centric architecture** where external protocol traffic is normalized by the gateway before reaching the core CA:

```
        ACME, CMP, EST
Client <-- REST, SCEP --> Gateway <-- CBOR Messages --> CA
                          (Protocols)   (High Performance)
```

The gateway handles multiple enrollment protocols (ACME, CMP, EST, SCEP, REST) and communicates with the CA using compact CBOR messages for efficiency.

### Module Categories

**Base & Utilities** (foundation layer)
- `codec` - CBOR encoding/decoding and protocol utilities
- `util`, `util-extra` - General utilities and extensions
- `pkcs11` - PKCS#11 wrapper for HSM access
- `xihsm` - XiPKI HSM abstraction layer
- `pkcs11test` - PKCS#11 integration tests

**Cryptography & Security**
- `security` - Cryptographic operations and certificate handling
- `bcbridge-lts8on`, `bcbridge-fips` - Bouncy Castle LTS and FIPS bridge modules
  - Allows switching between LTS and FIPS variants
  - LTS: `bcbridge-lts8on`, FIPS: `bcbridge-fips`

**Core PKI Services**
- `ca-api` - CA API interfaces and data models
- `ca-server` - CA implementation (issuance, revocation, CRL generation)
- `ca-sdk` - CA client SDK
- `ca-mgmt` - CA management functionality
- `ocsp-api` - OCSP API interfaces
- `ocsp-server` - OCSP responder implementation
- `gateway` - Protocol gateway (ACME, CMP, EST, SCEP, REST)

**Operations & CLI**
- `shells` - Management CLI shells and commands
- `pki-client` - End-user PKI client for certificate enrollment/revocation
- `certprofile` - Certificate profile configuration
- `servlets` - HTTP servlet implementations
- `qa` - Quality assurance and integration tests

**Distribution**
- `assemblies` - Builds distribution packages:
  - `xipki-setup-<version>-bclts.tar.gz` (~17 MB with BC LTS)
  - `xipki-setup-<version>-bcfips.tar.gz` (~19 MB with BC FIPS)
  - `xipki-setup-<version>-thin.tar.gz` (~6 MB without JDBC/BC, user provides)

### Module Dependencies

Key dependency layers (modules lower in list depend on modules above):
1. Base: `codec`, `util`, `pkcs11`, `xihsm`
2. Crypto: `security`, `bcbridge-*`
3. API: `ca-api`, `ocsp-api`
4. SDK/Implementation: `ca-sdk`, `ca-server`, `ocsp-server`
5. Integration: `gateway`, `ca-mgmt`, `shells`, `pki-client`
6. Distribution: `assemblies`

## Key Conventions

### Package Structure
- All packages use `org.xipki.*` prefix
- Submodule classes follow pattern: `org.xipki.<module>.<subpackage>`
- Example: `org.xipki.ca.server.servlet.CaHttpMgmtServlet` (ca-server module)

### Testing Patterns
- Test classes use suffix `Test` (e.g., `GetInfoTest`, `DeleteObjectTest`)
- Only some modules have test suites: `util`, `security`, `ocsp-server`, `pkcs11test`, `shells`
- Many modules (ca-server, gateway, etc.) are primarily tested via integration tests in `qa`
- Run tests with `mvn test -pl :<module-name>` for module-specific testing

### Build Customization
- Java source/target: **Java 11** (set in parent `pom.xml` as `<release>11</release>`)
- Surefire plugin version: 3.5.5 for test execution
- Assembly plugin: 3.8.0 for building distributions
- Source encoding: UTF-8

### Bouncy Castle Variants
- Two bridge modules: `bcbridge-lts8on` (LTS) and `bcbridge-fips` (FIPS)
- Versions in parent pom:
  - `bc-lts.version`: 2.73.10
  - `bc-fips.version`: 2.1.2
- Only one should be included in final builds (set via profile or classifier)
- Thin distribution allows users to provide their own Bouncy Castle variant

### Database Support
- Supported: DB2, MariaDB, MySQL, Oracle, PostgreSQL, H2, HSQLDB
- JDBC drivers versions in properties:
  - H2: 2.4.240
  - MariaDB: 3.5.8
  - PostgreSQL: 42.7.10

### Runtime Topology
- **CA, OCSP, Gateway** can each run in multiple parallel active instances
- All instances share the same database
- Configuration stored in database (not config files)
- Enables horizontal scaling without session affinity

## Important Notes

### When Modifying Core Modules
- Changes to `codec`, `util`, `security`, or `bcbridge-*` affect all dependent services
- Always run `mvn test` on changed modules
- Test integration with CA and OCSP in `qa` module if making cryptographic changes

### For Protocol/Gateway Work
- Gateway normalizes multiple enrollment protocols into CBOR messages
- Changes should maintain backward compatibility with CA protocol expectations
- See `gateway` module for protocol handler implementations

### Performance Considerations
- CBOR encoding is used for gateway-CA communication (compact, fast)
- OCSP responder designed for high volume
- Review `doc/database/Perf-MySQL.md` for database optimization

### HSM Integration
- Primary interface: PKCS#11 via `pkcs11` and `xihsm` modules
- Supported HSMs: AWS CloudHSM, Nitrokey, nCipher, Sansec, Softhsm, TASS, Thales, Utimaco
- HSM support verified in `pkcs11test` module

## References

- Technical architecture: `doc/xipki-tech.md`
- Development environment: `doc/dev-env/README.md`
- Git workflow: `doc/git/git-commands.md`
- CI/CD: `.github/workflows/quick-ci.yml` (tests on PR/push to master)
