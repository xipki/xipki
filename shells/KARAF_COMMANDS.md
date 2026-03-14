# Karaf Commands in `shells/`

Generated from Java sources under `shells/**/src/main/java`.
Commands are discovered via `@Command`, options via `@Option`, arguments via `@Argument`.
Default value is taken from the field assignment (for example `private int n = 5;`).

Total commands: **192**

## Command Index

| Command | Module | Class | Description |
|---|---|---|---|
| `ca:ca-add` | `ca-mgmt-shell` | `CaAdd` | add CA |
| `ca:ca-info` | `ca-mgmt-shell` | `CaInfo` | show information of CA |
| `ca:ca-revoke` | `ca-mgmt-shell` | `CaRevoke` | revoke CA |
| `ca:ca-rm` | `ca-mgmt-shell` | `CaRm` | remove CA |
| `ca:ca-token-info-p11` | `ca-mgmt-shell` | `CaTokenInfoP11` | list objects in PKCS#11 device of the CA |
| `ca:ca-unrevoke` | `ca-mgmt-shell` | `CaUnrevoke` | unrevoke CA |
| `ca:ca-up` | `ca-mgmt-shell` | `CaUp` | update CA |
| `ca:caalias-add` | `ca-mgmt-shell` | `CaaliasAdd` | add CA alias |
| `ca:caalias-info` | `ca-mgmt-shell` | `CaaliasInfo` | show information of CA alias |
| `ca:caalias-rm` | `ca-mgmt-shell` | `CaaliasRm` | remove CA alias |
| `ca:cacert` | `ca-mgmt-shell` | `CaCert` | get CA's certificate |
| `ca:cacerts` | `ca-mgmt-shell` | `CaCerts` | get CA's certificate chain |
| `ca:caprofile-add` | `ca-mgmt-shell` | `CaprofileAdd` | add certificate profile to CA |
| `ca:caprofile-info` | `ca-mgmt-shell` | `CaprofileInfo` | show information of certificate profile in given CA |
| `ca:caprofile-rm` | `ca-mgmt-shell` | `CaprofileRm` | remove certificate profile from CA |
| `ca:capub-add` | `ca-mgmt-shell` | `CapubAdd` | add publisher to CA |
| `ca:capub-info` | `ca-mgmt-shell` | `CapubInfo` | show information of publisher in given CA |
| `ca:capub-rm` | `ca-mgmt-shell` | `CapubRm` | remove publisher from CA |
| `ca:careq-add` | `ca-mgmt-shell` | `CareqAdd` | add requestor to CA |
| `ca:careq-info` | `ca-mgmt-shell` | `CareqInfo` | show information of requestor in CA |
| `ca:careq-rm` | `ca-mgmt-shell` | `CareqRm` | remove requestor from CA |
| `ca:cert-status` | `ca-mgmt-shell` | `CertStatus` | show certificate status and save the certificate |
| `ca:convert-profile` | `ca-mgmt-shell` | `ConvertProfile` | Convert the profile file to the up-to-date format |
| `ca:dbschema-add` | `ca-mgmt-shell` | `AddDbSchema` | add DBSchema entry |
| `ca:dbschema-info` | `ca-mgmt-shell` | `ListDbSchemas` | list DBSchema entries |
| `ca:dbschema-rm` | `ca-mgmt-shell` | `RemoveDbSchema` | remove DBSchema entry |
| `ca:dbschema-up` | `ca-mgmt-shell` | `ChangeDbSchema` | change DBSchema entry |
| `ca:diff-digest` | `ca-mgmt-shell` | `DiffDigest` | diff digest XiPKI database |
| `ca:enroll-cert` | `ca-mgmt-shell` | `EnrollCert` | enroll certificate |
| `ca:enroll-cross-cert` | `ca-mgmt-shell` | `EnrollCrossCert` | enroll cross certificate |
| `ca:export-ca` | `ca-mgmt-shell` | `ExportCa` | export CA database |
| `ca:export-ca-certstore` | `ca-mgmt-shell` | `ExportCaCertStore` | export CA cerstore database (without the CA configuration) |
| `ca:export-conf` | `ca-mgmt-shell` | `ExportConf` | export configuration to zip file |
| `ca:export-ocsp` | `ca-mgmt-shell` | `ExportOcsp` | export OCSP database |
| `ca:gen-crl` | `ca-mgmt-shell` | `GenCrl` | generate CRL |
| `ca:gen-rootca` | `ca-mgmt-shell` | `GenRootca` | generate selfsigned CA |
| `ca:get-cert` | `ca-mgmt-shell` | `GetCert` | get certificate |
| `ca:get-crl` | `ca-mgmt-shell` | `GetCrl` | download CRL |
| `ca:import-ca` | `ca-mgmt-shell` | `ImportCa` | import CA database |
| `ca:import-ca-certstore` | `ca-mgmt-shell` | `ImportCaCertStore` | import CA certstore database only (without the CA configuration) |
| `ca:import-ocsp` | `ca-mgmt-shell` | `ImportOcsp` | import OCSP database |
| `ca:import-ocspfromca` | `ca-mgmt-shell` | `ImportOcspfromCa` | import OCSP database from CA data |
| `ca:keypairgen-add` | `ca-mgmt-shell` | `KeypairGenAdd` | add keypair generation |
| `ca:keypairgen-info` | `ca-mgmt-shell` | `KeypairGenInfo` | show information of keypair generation |
| `ca:keypairgen-rm` | `ca-mgmt-shell` | `KeypairGenRm` | remove keypair generation |
| `ca:keypairgen-up` | `ca-mgmt-shell` | `KeypairGenUp` | update keypair generation |
| `ca:list-cert` | `ca-mgmt-shell` | `ListCert` | show a list of certificates |
| `ca:load-conf` | `ca-mgmt-shell` | `LoadConf` | load configuration |
| `ca:notify-change` | `ca-mgmt-shell` | `NotifyChange` | notify the change of CA system |
| `ca:profile-add` | `ca-mgmt-shell` | `ProfileAdd` | add certificate profile |
| `ca:profile-export` | `ca-mgmt-shell` | `ProfileExport` | export certificate profile configuration |
| `ca:profile-info` | `ca-mgmt-shell` | `ProfileInfo` | show information of certificate profile |
| `ca:profile-rm` | `ca-mgmt-shell` | `ProfileRm` | remove certificate profile |
| `ca:profile-up` | `ca-mgmt-shell` | `ProfileUp` | update certificate profile |
| `ca:publisher-add` | `ca-mgmt-shell` | `PublisherAdd` | add publisher |
| `ca:publisher-export` | `ca-mgmt-shell` | `PublisherExport` | export publisher configuration |
| `ca:publisher-info` | `ca-mgmt-shell` | `PublisherInfo` | show information of publisher |
| `ca:publisher-rm` | `ca-mgmt-shell` | `PublisherRm` | remove publisher |
| `ca:publisher-up` | `ca-mgmt-shell` | `PublisherUp` | update publisher |
| `ca:republish` | `ca-mgmt-shell` | `Republish` | republish certificates |
| `ca:requestor-add` | `ca-mgmt-shell` | `RequestorAdd` | add requestor |
| `ca:requestor-info` | `ca-mgmt-shell` | `RequestorInfo` | show information of requestor |
| `ca:requestor-rm` | `ca-mgmt-shell` | `RequestorRm` | remove requestor |
| `ca:requestor-up` | `ca-mgmt-shell` | `RequestorUp` | update requestor |
| `ca:restart` | `ca-mgmt-shell` | `Restart` | restart CA system |
| `ca:restart-ca` | `ca-mgmt-shell` | `RestartCa` | restart CA |
| `ca:revoke-cert` | `ca-mgmt-shell` | `RevokeCert` | revoke certificate |
| `ca:rm-cert` | `ca-mgmt-shell` | `RmCert` | remove certificate |
| `ca:signer-add` | `ca-mgmt-shell` | `SignerAdd` | add signer |
| `ca:signer-info` | `ca-mgmt-shell` | `SignerInfo` | show information of signer |
| `ca:signer-rm` | `ca-mgmt-shell` | `SignerRm` | remove signer |
| `ca:signer-up` | `ca-mgmt-shell` | `SignerUp` | update signer |
| `ca:sql` | `ca-mgmt-shell` | `Sql` | Run SQL script |
| `ca:system-status` | `ca-mgmt-shell` | `SystemStatus` | show CA system status |
| `ca:unlock` | `ca-mgmt-shell` | `Unlock` | unlock CA system |
| `ca:unsuspend-cert` | `ca-mgmt-shell` | `UnsuspendCert` | unsuspend certificate |
| `caqa:ca-check` | `qa-shell` | `CaCheck` | check information of CAs (QA) |
| `caqa:caalias-check` | `qa-shell` | `CaAliasCheck` | check CA aliases (QA) |
| `caqa:caprofile-check` | `qa-shell` | `CaprofileCheck` | check information of certificate profiles in given CA (QA) |
| `caqa:capub-check` | `qa-shell` | `CapubCheck` | check information of publishers in given CA (QA) |
| `caqa:careq-check` | `qa-shell` | `CaReqCheck` | check information of requestors in CA (QA) |
| `caqa:check-cert` | `qa-shell` | `CheckCert` | check the certificate |
| `caqa:init` | `qa-shell` | `Init` | initialize the CA QA manager |
| `caqa:neg-ca-add` | `qa-shell` | `NegCaAdd` | add CA (negative, QA) |
| `caqa:neg-ca-revoke` | `qa-shell` | `NegCaRevoke` | revoke CA (negative, QA) |
| `caqa:neg-ca-rm` | `qa-shell` | `NegCaRm` | remove CA (negative, QA) |
| `caqa:neg-ca-unrevoke` | `qa-shell` | `NegCaUnrevoke` | unrevoke CA (negative, QA) |
| `caqa:neg-ca-up` | `qa-shell` | `NegCaUp` | update CA (negative, QA) |
| `caqa:neg-caalias-add` | `qa-shell` | `NegCaaliasAdd` | add CA alias (negative, QA) |
| `caqa:neg-caalias-rm` | `qa-shell` | `NegCaaliasRm` | remove CA alias (negative, QA) |
| `caqa:neg-caprofile-add` | `qa-shell` | `NegCaprofileAdd` | add certificate profiles to CA (negative, QA) |
| `caqa:neg-caprofile-rm` | `qa-shell` | `NegCaprofileRm` | remove certificate profile from CA (negative, QA) |
| `caqa:neg-capub-add` | `qa-shell` | `NegCaPubAdd` | add publishers to CA (negative, QA) |
| `caqa:neg-capub-rm` | `qa-shell` | `NegCapubRm` | remove publisher from CA (negative, QA) |
| `caqa:neg-careq-add` | `qa-shell` | `NegCaReqAdd` | add requestor to CA (negative, QA) |
| `caqa:neg-careq-rm` | `qa-shell` | `NegCareqRm` | remove requestor in CA (negative, QA) |
| `caqa:neg-enroll-cert` | `qa-shell` | `NegEnrollCert` | enroll certificate (negative, QA) |
| `caqa:neg-gen-rootca` | `qa-shell` | `NegGenRootCa` | generate selfsigned CA (negative, QA) |
| `caqa:neg-profile-add` | `qa-shell` | `NegProfileAdd` | add certificate profile (negative, QA) |
| `caqa:neg-profile-rm` | `qa-shell` | `NegProfileRm` | remove Profile (negative, QA) |
| `caqa:neg-profile-up` | `qa-shell` | `NegProfileUp` | update certificate profile (negative, QA) |
| `caqa:neg-publisher-add` | `qa-shell` | `NegPublisherAdd` | add publisher (negative, QA) |
| `caqa:neg-publisher-rm` | `qa-shell` | `NegPublisherRm` | remove publisher (negative, QA) |
| `caqa:neg-publisher-up` | `qa-shell` | `NegPublisherUp` | update publisher (negative, QA) |
| `caqa:neg-republish` | `qa-shell` | `NegRepublish` | republish certificates (negative, QA) |
| `caqa:neg-requestor-add` | `qa-shell` | `NegRequestorAdd` | add requestor (negative, QA) |
| `caqa:neg-requestor-rm` | `qa-shell` | `NegRequestorRm` | remove requestor (negative, QA) |
| `caqa:neg-requestor-up` | `qa-shell` | `NegRequestorUp` | update requestor (negative, QA) |
| `caqa:neg-revoke-cert` | `qa-shell` | `NegRevokeCert` | revoke certificate (negative, QA) |
| `caqa:neg-rm-cert` | `qa-shell` | `NegRmCert` | remove certificate (negative, QA) |
| `caqa:neg-signer-add` | `qa-shell` | `NegSignerAdd` | add signer (negative, QA) |
| `caqa:neg-signer-rm` | `qa-shell` | `NegSignerRm` | remove signer (negative, QA) |
| `caqa:neg-signer-up` | `qa-shell` | `NegSignerUp` | update signer (negative, QA) |
| `caqa:neg-unrevoke-cert` | `qa-shell` | `NegUnrevokeCert` | unrevoke certificate (negative, QA) |
| `caqa:profile-check` | `qa-shell` | `ProfileCheck` | check information of profiles (QA) |
| `caqa:publisher-check` | `qa-shell` | `PublisherCheck` | check information of publishers (QA) |
| `caqa:requestor-check` | `qa-shell` | `RequestorCheck` | check information of requestors (QA) |
| `caqa:signer-check` | `qa-shell` | `SignerCheck` | check information of signer (QA) |
| `demo:shutdown-h2-server` | `demo-shell` | `ShutdownH2Server` | Shutdown H2 server |
| `demo:start-h2-server` | `demo-shell` | `StartH2Server` | Start H2 server |
| `qa:fill-keypool` | `qa-shell` | `QaFillKeypoolAction` | Fill the keypool |
| `xi:base64` | `shell-base` | `Base64EnDecode` | Base64 encode / decode |
| `xi:cert-info` | `security-shell` | `CertInfo` | print certificate information |
| `xi:cmp-cacert` | `pki-client-shell` | `CmpCacert` | get CA certificate |
| `xi:cmp-cacerts` | `pki-client-shell` | `CmpCacertchain` | get CA certificate chain |
| `xi:cmp-csr-enroll` | `pki-client-shell` | `CmpCsrEnroll` | enroll certificate via CSR |
| `xi:cmp-enroll-p11` | `pki-client-shell` | `CmpEnrollP11` | enroll certificate (PKCS#11 token) |
| `xi:cmp-enroll-p12` | `pki-client-shell` | `CmpEnrollP12` | enroll certificate (PKCS#12 keystore) |
| `xi:cmp-enroll-serverkeygen` | `pki-client-shell` | `CmpEnrollCagenkey` | enroll certificate (keypair will be generated by the CA) |
| `xi:cmp-get-crl` | `pki-client-shell` | `CmpGetCrl` | download CRL |
| `xi:cmp-revoke` | `pki-client-shell` | `CmpRevoke` | revoke certificate |
| `xi:cmp-unsuspend` | `pki-client-shell` | `CmpUnsuspend` | unsuspend certificate |
| `xi:cmp-update-p11` | `pki-client-shell` | `CmpUpdateP11` | update certificate (PKCS#11 token) |
| `xi:cmp-update-p12` | `pki-client-shell` | `CmpUpdateP12` | update certificate (PKCS#12 keystore) |
| `xi:cmp-update-serverkeygen` | `pki-client-shell` | `CmpUpdateCagenkey` | update certificate (keypair will be generated by the CA) |
| `xi:confirm` | `shell-base` | `Confirm` | confirm an action |
| `xi:convert-keystore` | `security-shell` | `ConvertKeystore` | Convert keystore |
| `xi:copy-dir` | `shell-base` | `CopyDir` | copy content of the directory to destination |
| `xi:copy-file` | `shell-base` | `CopyFile` | copy file |
| `xi:crl-info` | `security-shell` | `CrlInfo` | print CRL information |
| `xi:csr-jce` | `security-shell` | `CsrJceAction` | generate CSR request with JCE device |
| `xi:csr-p11` | `security-shell` | `CsrP11Action` | generate CSR request with PKCS#11 device |
| `xi:csr-p12` | `security-shell` | `CsrP12Action` | generate CSR with PKCS#12 keystore |
| `xi:curl` | `shell-base` | `Curl` | transfer a URL |
| `xi:datetime` | `shell-base` | `DateTime` | get current date-time |
| `xi:delete-all-objects-p11` | `security-shell` | `DeleteAllObjectsP11` | delete all objects in PKCS#11 device |
| `xi:delete-key-p11` | `security-shell` | `DeleteKeyP11` | delete key in PKCS#11 device |
| `xi:delete-objects-p11` | `security-shell` | `DeleteObjectsP11` | delete objects in PKCS#11 device |
| `xi:deobfuscate` | `security-shell` | `Deobfuscate` | deobfuscate password |
| `xi:exec` | `shell-base` | `ExecTerminalCommand` | execute terminal |
| `xi:export-cert-p12` | `security-shell` | `ExportCertP12` | export certificate from PKCS#12 keystore |
| `xi:export-cert-p7m` | `security-shell` | `ExportCertP7m` | export (the first) certificate from CMS signed data |
| `xi:export-keycert-est` | `security-shell` | `ExportKeyCertEst` | export key and certificate from the response of EST's serverkeygen |
| `xi:export-keycert-pem` | `security-shell` | `ExportKeyCertPem` | export key and certificate from the PEM file |
| `xi:file-exists` | `shell-base` | `FileExists` | test whether file or folder exists |
| `xi:import-cert` | `security-shell` | `ImportCert` | import certificates to a keystore |
| `xi:import-secretkey-p11` | `security-shell` | `ImportSecretkeyP11` | import secret key with given value in PKCS#11 device |
| `xi:keypair-p11` | `security-shell` | `KeypairP11` | generate keypair in PKCS#11 device |
| `xi:keypair-p12` | `security-shell` | `KeypairP12` | generate keypair in PKCS#12 keystore |
| `xi:lowercase` | `shell-base` | `Lowercase` | convert to lowercase string |
| `xi:mkdir` | `shell-base` | `Mkdir` | make directories |
| `xi:move-dir` | `shell-base` | `MoveDir` | move content of the directory to destination |
| `xi:move-file` | `shell-base` | `MoveFile` | move file |
| `xi:obfuscate` | `security-shell` | `Obfuscate` | obfuscate password |
| `xi:object-exists-p11` | `security-shell` | `ObjectExistsP11` | return whether objects exist in PKCS#11 device |
| `xi:ocsp-status` | `pki-client-shell` | `OcspStatus` | request certificate status |
| `xi:osinfo` | `shell-base` | `OsInfo` | get info of operation system |
| `xi:pbe-dec` | `security-shell` | `PbeDec` | decrypt password with master password |
| `xi:pbe-enc` | `security-shell` | `PbeEnc` | encrypt password with master password |
| `xi:pkcs12` | `security-shell` | `Pkcs12` | export PKCS#12 key store, like the 'openssl pkcs12' command |
| `xi:replace` | `shell-base` | `Replace` | replace text in file |
| `xi:rm` | `shell-base` | `Rm` | remove file or directory |
| `xi:scep-cacert` | `pki-client-shell` | `ScepCacert` | get CA certificate |
| `xi:scep-certpoll` | `pki-client-shell` | `ScepCertpoll` | poll certificate |
| `xi:scep-enroll` | `pki-client-shell` | `ScepEnroll` | enroll certificate |
| `xi:scep-get-cert` | `pki-client-shell` | `ScepGetCert` | download certificate |
| `xi:scep-get-crl` | `pki-client-shell` | `ScepGetCrl` | download CRL |
| `xi:secretkey-p11` | `security-shell` | `SecretkeyP11` | generate secret key in PKCS#11 device |
| `xi:secretkey-p12` | `security-shell` | `SecretkeyP12` | generate secret key in JCEKS (not PKCS#12) keystore |
| `xi:speed-keypair-p11` | `security-shell` | `SpeedKeypairGenP11` | performance test of PKCS#11 key generation |
| `xi:speed-keypair-p12` | `security-shell` | `SpeedKeypairGenP12` | performance test of PKCS#12 keypair key generation |
| `xi:speed-sign-p11` | `security-shell` | `SpeedSignP11` | performance test of PKCS#11 signature creation |
| `xi:speed-sign-p12` | `security-shell` | `SpeedSignP12` | performance test of PKCS#12 signature creation |
| `xi:token-info-p11` | `security-shell` | `TokenInfoP11` | list objects in PKCS#11 device |
| `xi:update-cert-p12` | `security-shell` | `UpdateCertP12` | update certificate in PKCS#12 keystore |
| `xi:uppercase` | `shell-base` | `Uppercase` | convert to uppercase string |
| `xi:validate-csr` | `security-shell` | `ValidateCsrAction` | validate CSR |
| `xiqa:batch-ocsp-status` | `qa-shell` | `BatchOcspQaStatusAction` | batch request status of certificates (QA) |
| `xiqa:benchmark-enroll` | `qa-shell` | `BenchmarkEnroll` | Enroll certificate (benchmark) |
| `xiqa:benchmark-enroll-serverkeygen` | `qa-shell` | `BenchmarkCaGenEnroll` | Enroll certificate (CA generates keypairs, benchmark) |
| `xiqa:benchmark-ocsp-status` | `qa-shell` | `BenchmarkOcspStatusAction` | OCSP benchmark |
| `xiqa:qa-ocsp-status` | `qa-shell` | `OcspQaStatusAction` | request certificate status (QA) |

## Command Details

### `ca:ca-add`

- Module: `ca-mgmt-shell`
- Class: `CaAdd`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CaActions.java`
- Description: add CA

Options:
- None

Arguments:
- None

### `ca:ca-info`

- Module: `ca-mgmt-shell`
- Class: `CaInfo`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CaActions.java`
- Description: show information of CA

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--verbose` | `Boolean` | `verbose` | `false` | `Boolean.FALSE` | show CA information verbosely |

Arguments:
- None

### `ca:ca-revoke`

- Module: `ca-mgmt-shell`
- Class: `CaRevoke`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CaActions.java`
- Description: revoke CA

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--inv-date` | `String` | `invalidityDateS` | `false` | `` | invalidity date, UTC time of format yyyyMMddHHmmss |
| `--rev-date` | `String` | `revocationDateS` | `false` | `` | revocation date, UTC time of format yyyyMMddHHmmss |

Arguments:
- None

### `ca:ca-rm`

- Module: `ca-mgmt-shell`
- Class: `CaRm`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CaActions.java`
- Description: remove CA

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | without prompt |

Arguments:
- None

### `ca:ca-token-info-p11`

- Module: `ca-mgmt-shell`
- Class: `CaTokenInfoP11`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/MiscActions.java`
- Description: list objects in PKCS#11 device of the CA

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--module` | `String` | `moduleName` | `false` | `"default"` | name of the PKCS#11 module. |
| `--slot` | `Integer` | `slotIndex` | `false` | `` | slot index |
| `--verbose` | `Boolean` | `verbose` | `false` | `Boolean.FALSE` | show object information verbosely |

Arguments:
- None

### `ca:ca-unrevoke`

- Module: `ca-mgmt-shell`
- Class: `CaUnrevoke`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CaActions.java`
- Description: unrevoke CA

Options:
- None

Arguments:
- None

### `ca:ca-up`

- Module: `ca-mgmt-shell`
- Class: `CaUp`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CaActions.java`
- Description: update CA

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--ca-cert-uri` | `List<String>` | `caCertUris` | `false` | `` | CA certificate URI |
| `--crl-control` | `String` | `crlControl` | `false` | `` | CRL control or 'null' |
| `--crl-uri` | `List<String>` | `crlUris` | `false` | `` | CRL distribution point URI or 'null' |
| `--ctlog-control` | `String` | `ctlogControl` | `false` | `` | CT log control |
| `--deltacrl-uri` | `List<String>` | `deltaCrlUris` | `false` | `` | delta CRL distribution point URI or 'null' |
| `--expiration-period` | `Integer` | `expirationPeriod` | `false` | `` | days before expiration time of CA to issue certificates |
| `--extra-control` | `String` | `extraControl` | `false` | `` | extra control |
| `--keep-expired-certs` | `Integer` | `keepExpiredCertDays` | `false` | `` | days to keep expired certificates |
| `--max-validity` | `String` | `maxValidity` | `false` | `` | maximal validity |
| `--num-crls` | `Integer` | `numCrls` | `false` | `` | number of CRLs to be kept in database |
| `--ocsp-uri` | `List<String>` | `ocspUris` | `false` | `` | OCSP URI or 'null' |
| `--revoke-suspended-control` | `String` | `revokeSuspendedControl` | `false` | `` | Revoke suspended certificates control |
| `--signer-conf` | `String` | `signerConf` | `false` | `` | CA signer configuration or 'null' |
| `--sn-len` | `Integer` | `snLen` | `false` | `` | number of octets of the serial number, between |

Arguments:
- None

### `ca:caalias-add`

- Module: `ca-mgmt-shell`
- Class: `CaaliasAdd`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CaActions.java`
- Description: add CA alias

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--alias` | `String` | `caAlias` | `true` | `` | CA alias |

Arguments:
- None

### `ca:caalias-info`

- Module: `ca-mgmt-shell`
- Class: `CaaliasInfo`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CaActions.java`
- Description: show information of CA alias

Options:
- None

Arguments:
- None

### `ca:caalias-rm`

- Module: `ca-mgmt-shell`
- Class: `CaaliasRm`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CaActions.java`
- Description: remove CA alias

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | without prompt |

Arguments:
- None

### `ca:cacert`

- Module: `ca-mgmt-shell`
- Class: `CaCert`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CaActions.java`
- Description: get CA's certificate

Options:
- None

Arguments:
- None

### `ca:cacerts`

- Module: `ca-mgmt-shell`
- Class: `CaCerts`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CaActions.java`
- Description: get CA's certificate chain

Options:
- None

Arguments:
- None

### `ca:caprofile-add`

- Module: `ca-mgmt-shell`
- Class: `CaprofileAdd`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/ProfileActions.java`
- Description: add certificate profile to CA

Options:
- None

Arguments:
- None

### `ca:caprofile-info`

- Module: `ca-mgmt-shell`
- Class: `CaprofileInfo`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/ProfileActions.java`
- Description: show information of certificate profile in given CA

Options:
- None

Arguments:
- None

### `ca:caprofile-rm`

- Module: `ca-mgmt-shell`
- Class: `CaprofileRm`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/ProfileActions.java`
- Description: remove certificate profile from CA

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | without prompt |

Arguments:
- None

### `ca:capub-add`

- Module: `ca-mgmt-shell`
- Class: `CapubAdd`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/PublisherActions.java`
- Description: add publisher to CA

Options:
- None

Arguments:
- None

### `ca:capub-info`

- Module: `ca-mgmt-shell`
- Class: `CapubInfo`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/PublisherActions.java`
- Description: show information of publisher in given CA

Options:
- None

Arguments:
- None

### `ca:capub-rm`

- Module: `ca-mgmt-shell`
- Class: `CapubRm`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/PublisherActions.java`
- Description: remove publisher from CA

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | without prompt |

Arguments:
- None

### `ca:careq-add`

- Module: `ca-mgmt-shell`
- Class: `CareqAdd`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/RequestorActions.java`
- Description: add requestor to CA

Options:
- None

Arguments:
- None

### `ca:careq-info`

- Module: `ca-mgmt-shell`
- Class: `CareqInfo`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/RequestorActions.java`
- Description: show information of requestor in CA

Options:
- None

Arguments:
- None

### `ca:careq-rm`

- Module: `ca-mgmt-shell`
- Class: `CareqRm`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/RequestorActions.java`
- Description: remove requestor from CA

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | without prompt |

Arguments:
- None

### `ca:cert-status`

- Module: `ca-mgmt-shell`
- Class: `CertStatus`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CertActions.java`
- Description: show certificate status and save the certificate

Options:
- None

Arguments:
- None

### `ca:convert-profile`

- Module: `ca-mgmt-shell`
- Class: `ConvertProfile`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/ProfileActions.java`
- Description: Convert the profile file to the up-to-date format

Options:
- None

Arguments:
- None

### `ca:dbschema-add`

- Module: `ca-mgmt-shell`
- Class: `AddDbSchema`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/DbSchemaActions.java`
- Description: add DBSchema entry

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--name` | `String` | `name` | `true` | `` | DBSchema entry name |
| `--value` | `String` | `value` | `true` | `` | DBSchema entry value |

Arguments:
- None

### `ca:dbschema-info`

- Module: `ca-mgmt-shell`
- Class: `ListDbSchemas`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/DbSchemaActions.java`
- Description: list DBSchema entries

Options:
- None

Arguments:
- None

### `ca:dbschema-rm`

- Module: `ca-mgmt-shell`
- Class: `RemoveDbSchema`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/DbSchemaActions.java`
- Description: remove DBSchema entry

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--name` | `String` | `name` | `true` | `` | DBSchema entry name |

Arguments:
- None

### `ca:dbschema-up`

- Module: `ca-mgmt-shell`
- Class: `ChangeDbSchema`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/DbSchemaActions.java`
- Description: change DBSchema entry

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--name` | `String` | `name` | `true` | `` | DBSchema entry name |
| `--value` | `String` | `value` | `true` | `` | DBSchema entry value |

Arguments:
- None

### `ca:diff-digest`

- Module: `ca-mgmt-shell`
- Class: `DiffDigest`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/DbActions.java`
- Description: diff digest XiPKI database

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--revoked-only` | `Boolean` | `revokedOnly` | `false` | `Boolean.FALSE` | considers only the revoked certificates |
| `--target-threads` | `Integer` | `numTargetThreads` | `false` | `40` | number of threads to query the target database |
| `-k` | `Integer` | `numCertsPerSelect` | `false` | `1000` | number of certificates per SELECT |

Arguments:
- None

### `ca:enroll-cert`

- Module: `ca-mgmt-shell`
- Class: `EnrollCert`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CertActions.java`
- Description: enroll certificate

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--key-outform` | `String` | `keyOutform` | `false` | `"p12"` | output format of the private key (pem or p12) |
| `--key-password` | `String` | `keyPasswordHint` | `false` | `` | Password to protect the private key, as plaintext or PBE-encrypted.\n |
| `--not-after` | `String` | `notAfterS` | `false` | `` | notAfter, UTC time of format yyyyMMddHHmmss |
| `--not-before` | `String` | `notBeforeS` | `false` | `` | notBefore, UTC time of format yyyyMMddHHmmss |
| `--subject` | `String` | `subject` | `false` | `` | Subject of the certificate.\n |

Arguments:
- None

### `ca:enroll-cross-cert`

- Module: `ca-mgmt-shell`
- Class: `EnrollCrossCert`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CertActions.java`
- Description: enroll cross certificate

Options:
- None

Arguments:
- None

### `ca:export-ca`

- Module: `ca-mgmt-shell`
- Class: `ExportCa`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/DbActions.java`
- Description: export CA database

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--resume` | `Boolean` | `resume` | `false` | `Boolean.FALSE` | resume from the last successful point |
| `-k` | `Integer` | `numCertsPerCommit` | `false` | `100` | number of certificates per SELECT |
| `-n` | `Integer` | `numCertsInBundle` | `false` | `10000` | number of certificates in one zip file |

Arguments:
- None

### `ca:export-ca-certstore`

- Module: `ca-mgmt-shell`
- Class: `ExportCaCertStore`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/DbActions.java`
- Description: export CA cerstore database (without the CA configuration)

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--resume` | `Boolean` | `resume` | `false` | `Boolean.FALSE` | resume from the last successful point |
| `-k` | `Integer` | `numCertsPerCommit` | `false` | `100` | number of certificates per SELECT |
| `-n` | `Integer` | `numCertsInBundle` | `false` | `10000` | number of certificates in one zip file |

Arguments:
- None

### `ca:export-conf`

- Module: `ca-mgmt-shell`
- Class: `ExportConf`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/MiscActions.java`
- Description: export configuration to zip file

Options:
- None

Arguments:
- None

### `ca:export-ocsp`

- Module: `ca-mgmt-shell`
- Class: `ExportOcsp`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/DbActions.java`
- Description: export OCSP database

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--resume` | `Boolean` | `resume` | `false` | `Boolean.FALSE` | resume from the last successful point |
| `-k` | `Integer` | `numCertsPerSelect` | `false` | `100` | number of certificates per SELECT |
| `-n` | `Integer` | `numCertsInBundle` | `false` | `10000` | number of certificates in one zip file |

Arguments:
- None

### `ca:gen-crl`

- Module: `ca-mgmt-shell`
- Class: `GenCrl`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CertActions.java`
- Description: generate CRL

Options:
- None

Arguments:
- None

### `ca:gen-rootca`

- Module: `ca-mgmt-shell`
- Class: `GenRootca`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CaActions.java`
- Description: generate selfsigned CA

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--not-after` | `String` | `notAfterS` | `false` | `` | notAfter, UTC time of format yyyyMMddHHmmss |
| `--not-before` | `String` | `notBeforeS` | `false` | `` | notBefore, UTC time of format yyyyMMddHHmmss |
| `--profile` | `String` | `rootcaProfile` | `true` | `` | profile of the Root CA |
| `--serial` | `String` | `serialS` | `false` | `` | serial number of the Root CA |
| `--subject` | `String` | `subject` | `true` | `` | subject of the Root CA |

Arguments:
- None

### `ca:get-cert`

- Module: `ca-mgmt-shell`
- Class: `GetCert`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CertActions.java`
- Description: get certificate

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--serial` | `String` | `serialNumberS` | `true` | `` | serial number |

Arguments:
- None

### `ca:get-crl`

- Module: `ca-mgmt-shell`
- Class: `GetCrl`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CertActions.java`
- Description: download CRL

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--with-basecrl` | `Boolean` | `withBaseCrl` | `false` | `Boolean.FALSE` | whether to retrieve the baseCRL if the current CRL is a delta CRL |

Arguments:
- None

### `ca:import-ca`

- Module: `ca-mgmt-shell`
- Class: `ImportCa`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/DbActions.java`
- Description: import CA database

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--resume` | `Boolean` | `resume` | `false` | `Boolean.FALSE` | resume from the last successful point |
| `-k` | `Integer` | `numCertsPerCommit` | `false` | `100` | number of certificates per commit |

Arguments:
- None

### `ca:import-ca-certstore`

- Module: `ca-mgmt-shell`
- Class: `ImportCaCertStore`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/DbActions.java`
- Description: import CA certstore database only (without the CA configuration)

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--resume` | `Boolean` | `resume` | `false` | `Boolean.FALSE` | resume from the last successful point |
| `-k` | `Integer` | `numCertsPerCommit` | `false` | `100` | number of certificates per commit |

Arguments:
- None

### `ca:import-ocsp`

- Module: `ca-mgmt-shell`
- Class: `ImportOcsp`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/DbActions.java`
- Description: import OCSP database

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--resume` | `Boolean` | `resume` | `false` | `Boolean.FALSE` | resume from the last successful point |
| `-k` | `Integer` | `numCertsPerCommit` | `false` | `100` | number of certificates per commit |

Arguments:
- None

### `ca:import-ocspfromca`

- Module: `ca-mgmt-shell`
- Class: `ImportOcspfromCa`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/DbActions.java`
- Description: import OCSP database from CA data

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--publisher` | `String` | `publisherName` | `false` | `DFLT_PUBLISHER` | publisher name |
| `--resume` | `Boolean` | `resume` | `false` | `Boolean.FALSE` | resume from the last successful point |
| `-k` | `Integer` | `numCertsPerCommit` | `false` | `100` | number of certificates per commit |

Arguments:
- None

### `ca:keypairgen-add`

- Module: `ca-mgmt-shell`
- Class: `KeypairGenAdd`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/KeypairGenActions.java`
- Description: add keypair generation

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--conf` | `String` | `conf` | `false` | `` | keypair generation configuration |

Arguments:
- None

### `ca:keypairgen-info`

- Module: `ca-mgmt-shell`
- Class: `KeypairGenInfo`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/KeypairGenActions.java`
- Description: show information of keypair generation

Options:
- None

Arguments:
- None

### `ca:keypairgen-rm`

- Module: `ca-mgmt-shell`
- Class: `KeypairGenRm`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/KeypairGenActions.java`
- Description: remove keypair generation

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | without prompt |

Arguments:
- None

### `ca:keypairgen-up`

- Module: `ca-mgmt-shell`
- Class: `KeypairGenUp`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/KeypairGenActions.java`
- Description: update keypair generation

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--conf` | `String` | `conf` | `false` | `` | keypair generation configuration or 'null' |

Arguments:
- None

### `ca:list-cert`

- Module: `ca-mgmt-shell`
- Class: `ListCert`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CertActions.java`
- Description: show a list of certificates

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--subject` | `String` | `subjectPatternS` | `false` | `` | the subject pattern, * is allowed. |
| `--valid-from` | `String` | `validFromS` | `false` | `` | start UTC time when the certificate is still valid, |
| `--valid-to` | `String` | `validToS` | `false` | `` | end UTC time when the certificate is still valid, in |
| `-n` | `int` | `num` | `false` | `1000` | maximal number of entries (between 1 and 1000) |

Arguments:
- None

### `ca:load-conf`

- Module: `ca-mgmt-shell`
- Class: `LoadConf`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/MiscActions.java`
- Description: load configuration

Options:
- None

Arguments:
- None

### `ca:notify-change`

- Module: `ca-mgmt-shell`
- Class: `NotifyChange`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/MiscActions.java`
- Description: notify the change of CA system

Options:
- None

Arguments:
- None

### `ca:profile-add`

- Module: `ca-mgmt-shell`
- Class: `ProfileAdd`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/ProfileActions.java`
- Description: add certificate profile

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--conf` | `String` | `conf` | `false` | `` | certificate profile configuration |
| `--name` | `String` | `name` | `true` | `` | profile name |

Arguments:
- None

### `ca:profile-export`

- Module: `ca-mgmt-shell`
- Class: `ProfileExport`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/ProfileActions.java`
- Description: export certificate profile configuration

Options:
- None

Arguments:
- None

### `ca:profile-info`

- Module: `ca-mgmt-shell`
- Class: `ProfileInfo`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/ProfileActions.java`
- Description: show information of certificate profile

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--verbose` | `Boolean` | `verbose` | `false` | `Boolean.FALSE` | show certificate profile information verbosely |

Arguments:
- None

### `ca:profile-rm`

- Module: `ca-mgmt-shell`
- Class: `ProfileRm`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/ProfileActions.java`
- Description: remove certificate profile

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | without prompt |

Arguments:
- None

### `ca:profile-up`

- Module: `ca-mgmt-shell`
- Class: `ProfileUp`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/ProfileActions.java`
- Description: update certificate profile

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--conf` | `String` | `conf` | `false` | `` | certificate profile configuration or 'null' |

Arguments:
- None

### `ca:publisher-add`

- Module: `ca-mgmt-shell`
- Class: `PublisherAdd`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/PublisherActions.java`
- Description: add publisher

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--conf` | `String` | `conf` | `false` | `` | publisher configuration |
| `--name` | `String` | `name` | `true` | `` | publisher Name |

Arguments:
- None

### `ca:publisher-export`

- Module: `ca-mgmt-shell`
- Class: `PublisherExport`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/PublisherActions.java`
- Description: export publisher configuration

Options:
- None

Arguments:
- None

### `ca:publisher-info`

- Module: `ca-mgmt-shell`
- Class: `PublisherInfo`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/PublisherActions.java`
- Description: show information of publisher

Options:
- None

Arguments:
- None

### `ca:publisher-rm`

- Module: `ca-mgmt-shell`
- Class: `PublisherRm`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/PublisherActions.java`
- Description: remove publisher

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | without prompt |

Arguments:
- None

### `ca:publisher-up`

- Module: `ca-mgmt-shell`
- Class: `PublisherUp`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/PublisherActions.java`
- Description: update publisher

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--conf` | `String` | `conf` | `false` | `` | publisher configuration or 'null' |

Arguments:
- None

### `ca:republish`

- Module: `ca-mgmt-shell`
- Class: `Republish`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/MiscActions.java`
- Description: republish certificates

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--thread` | `Integer` | `numThreads` | `false` | `5` | number of threads |

Arguments:
- None

### `ca:requestor-add`

- Module: `ca-mgmt-shell`
- Class: `RequestorAdd`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/RequestorActions.java`
- Description: add requestor

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--name` | `String` | `name` | `true` | `` | requestor name |

Arguments:
- None

### `ca:requestor-info`

- Module: `ca-mgmt-shell`
- Class: `RequestorInfo`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/RequestorActions.java`
- Description: show information of requestor

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--verbose` | `Boolean` | `verbose` | `false` | `Boolean.FALSE` | show requestor information verbosely |

Arguments:
- None

### `ca:requestor-rm`

- Module: `ca-mgmt-shell`
- Class: `RequestorRm`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/RequestorActions.java`
- Description: remove requestor

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | without prompt |

Arguments:
- None

### `ca:requestor-up`

- Module: `ca-mgmt-shell`
- Class: `RequestorUp`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/RequestorActions.java`
- Description: update requestor

Options:
- None

Arguments:
- None

### `ca:restart`

- Module: `ca-mgmt-shell`
- Class: `Restart`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/MiscActions.java`
- Description: restart CA system

Options:
- None

Arguments:
- None

### `ca:restart-ca`

- Module: `ca-mgmt-shell`
- Class: `RestartCa`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/MiscActions.java`
- Description: restart CA

Options:
- None

Arguments:
- None

### `ca:revoke-cert`

- Module: `ca-mgmt-shell`
- Class: `RevokeCert`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CertActions.java`
- Description: revoke certificate

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--inv-date` | `String` | `invalidityDateS` | `false` | `` | invalidity date, UTC time of format yyyyMMddHHmmss |

Arguments:
- None

### `ca:rm-cert`

- Module: `ca-mgmt-shell`
- Class: `RmCert`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CertActions.java`
- Description: remove certificate

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | without prompt |

Arguments:
- None

### `ca:signer-add`

- Module: `ca-mgmt-shell`
- Class: `SignerAdd`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/SignerActions.java`
- Description: add signer

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--conf` | `String` | `conf` | `true` | `` | conf of the signer |
| `--name` | `String` | `name` | `true` | `` | signer name |

Arguments:
- None

### `ca:signer-info`

- Module: `ca-mgmt-shell`
- Class: `SignerInfo`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/SignerActions.java`
- Description: show information of signer

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--verbose` | `Boolean` | `verbose` | `false` | `Boolean.FALSE` | show signer information verbosely |

Arguments:
- None

### `ca:signer-rm`

- Module: `ca-mgmt-shell`
- Class: `SignerRm`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/SignerActions.java`
- Description: remove signer

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | without prompt |

Arguments:
- None

### `ca:signer-up`

- Module: `ca-mgmt-shell`
- Class: `SignerUp`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/SignerActions.java`
- Description: update signer

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--conf` | `String` | `conf` | `false` | `` | conf of the signer or 'null' |

Arguments:
- None

### `ca:sql`

- Module: `ca-mgmt-shell`
- Class: `Sql`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/DbActions.java`
- Description: Run SQL script

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | without prompt |

Arguments:
- None

### `ca:system-status`

- Module: `ca-mgmt-shell`
- Class: `SystemStatus`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/MiscActions.java`
- Description: show CA system status

Options:
- None

Arguments:
- None

### `ca:unlock`

- Module: `ca-mgmt-shell`
- Class: `Unlock`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/MiscActions.java`
- Description: unlock CA system

Options:
- None

Arguments:
- None

### `ca:unsuspend-cert`

- Module: `ca-mgmt-shell`
- Class: `UnsuspendCert`
- Source: `shells/ca-mgmt-shell/src/main/java/org/xipki/ca/mgmt/shell/CertActions.java`
- Description: unsuspend certificate

Options:
- None

Arguments:
- None

### `caqa:ca-check`

- Module: `qa-shell`
- Class: `CaCheck`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaActions.java`
- Description: check information of CAs (QA)

Options:
- None

Arguments:
- None

### `caqa:caalias-check`

- Module: `qa-shell`
- Class: `CaAliasCheck`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaActions.java`
- Description: check CA aliases (QA)

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--alias` | `String` | `aliasName` | `true` | `` | alias name |

Arguments:
- None

### `caqa:caprofile-check`

- Module: `qa-shell`
- Class: `CaprofileCheck`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaActions.java`
- Description: check information of certificate profiles in given CA (QA)

Options:
- None

Arguments:
- None

### `caqa:capub-check`

- Module: `qa-shell`
- Class: `CapubCheck`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaActions.java`
- Description: check information of publishers in given CA (QA)

Options:
- None

Arguments:
- None

### `caqa:careq-check`

- Module: `qa-shell`
- Class: `CaReqCheck`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaActions.java`
- Description: check information of requestors in CA (QA)

Options:
- None

Arguments:
- None

### `caqa:check-cert`

- Module: `qa-shell`
- Class: `CheckCert`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaActions.java`
- Description: check the certificate

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--verbose` | `Boolean` | `verbose` | `false` | `Boolean.FALSE` | show status verbosely |

Arguments:
- None

### `caqa:init`

- Module: `qa-shell`
- Class: `Init`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaActions.java`
- Description: initialize the CA QA manager

Options:
- None

Arguments:
- None

### `caqa:neg-ca-add`

- Module: `qa-shell`
- Class: `NegCaAdd`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: add CA (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-ca-revoke`

- Module: `qa-shell`
- Class: `NegCaRevoke`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: revoke CA (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-ca-rm`

- Module: `qa-shell`
- Class: `NegCaRm`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: remove CA (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-ca-unrevoke`

- Module: `qa-shell`
- Class: `NegCaUnrevoke`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: unrevoke CA (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-ca-up`

- Module: `qa-shell`
- Class: `NegCaUp`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: update CA (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-caalias-add`

- Module: `qa-shell`
- Class: `NegCaaliasAdd`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: add CA alias (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-caalias-rm`

- Module: `qa-shell`
- Class: `NegCaaliasRm`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: remove CA alias (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-caprofile-add`

- Module: `qa-shell`
- Class: `NegCaprofileAdd`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: add certificate profiles to CA (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-caprofile-rm`

- Module: `qa-shell`
- Class: `NegCaprofileRm`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: remove certificate profile from CA (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-capub-add`

- Module: `qa-shell`
- Class: `NegCaPubAdd`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: add publishers to CA (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-capub-rm`

- Module: `qa-shell`
- Class: `NegCapubRm`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: remove publisher from CA (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-careq-add`

- Module: `qa-shell`
- Class: `NegCaReqAdd`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: add requestor to CA (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-careq-rm`

- Module: `qa-shell`
- Class: `NegCareqRm`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: remove requestor in CA (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-enroll-cert`

- Module: `qa-shell`
- Class: `NegEnrollCert`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: enroll certificate (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-gen-rootca`

- Module: `qa-shell`
- Class: `NegGenRootCa`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: generate selfsigned CA (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-profile-add`

- Module: `qa-shell`
- Class: `NegProfileAdd`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: add certificate profile (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-profile-rm`

- Module: `qa-shell`
- Class: `NegProfileRm`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: remove Profile (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-profile-up`

- Module: `qa-shell`
- Class: `NegProfileUp`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: update certificate profile (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-publisher-add`

- Module: `qa-shell`
- Class: `NegPublisherAdd`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: add publisher (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-publisher-rm`

- Module: `qa-shell`
- Class: `NegPublisherRm`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: remove publisher (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-publisher-up`

- Module: `qa-shell`
- Class: `NegPublisherUp`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: update publisher (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-republish`

- Module: `qa-shell`
- Class: `NegRepublish`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: republish certificates (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-requestor-add`

- Module: `qa-shell`
- Class: `NegRequestorAdd`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: add requestor (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-requestor-rm`

- Module: `qa-shell`
- Class: `NegRequestorRm`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: remove requestor (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-requestor-up`

- Module: `qa-shell`
- Class: `NegRequestorUp`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: update requestor (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-revoke-cert`

- Module: `qa-shell`
- Class: `NegRevokeCert`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: revoke certificate (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-rm-cert`

- Module: `qa-shell`
- Class: `NegRmCert`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: remove certificate (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-signer-add`

- Module: `qa-shell`
- Class: `NegSignerAdd`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: add signer (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-signer-rm`

- Module: `qa-shell`
- Class: `NegSignerRm`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: remove signer (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-signer-up`

- Module: `qa-shell`
- Class: `NegSignerUp`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: update signer (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:neg-unrevoke-cert`

- Module: `qa-shell`
- Class: `NegUnrevokeCert`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaNegActions.java`
- Description: unrevoke certificate (negative, QA)

Options:
- None

Arguments:
- None

### `caqa:profile-check`

- Module: `qa-shell`
- Class: `ProfileCheck`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaActions.java`
- Description: check information of profiles (QA)

Options:
- None

Arguments:
- None

### `caqa:publisher-check`

- Module: `qa-shell`
- Class: `PublisherCheck`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaActions.java`
- Description: check information of publishers (QA)

Options:
- None

Arguments:
- None

### `caqa:requestor-check`

- Module: `qa-shell`
- Class: `RequestorCheck`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaActions.java`
- Description: check information of requestors (QA)

Options:
- None

Arguments:
- None

### `caqa:signer-check`

- Module: `qa-shell`
- Class: `SignerCheck`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaActions.java`
- Description: check information of signer (QA)

Options:
- None

Arguments:
- None

### `demo:shutdown-h2-server`

- Module: `demo-shell`
- Class: `ShutdownH2Server`
- Source: `shells/demo-shell/src/main/java/org/xipki/qa/shell/H2DatabaseActions.java`
- Description: Shutdown H2 server

Options:
- None

Arguments:
- None

### `demo:start-h2-server`

- Module: `demo-shell`
- Class: `StartH2Server`
- Source: `shells/demo-shell/src/main/java/org/xipki/qa/shell/H2DatabaseActions.java`
- Description: Start H2 server

Options:
- None

Arguments:
- None

### `qa:fill-keypool`

- Module: `qa-shell`
- Class: `QaFillKeypoolAction`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaFillKeypoolAction.java`
- Description: Fill the keypool

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--enc-algo` | `String` | `encAlg` | `false` | `"AES128/GCM"` | algorithm to encrypt the generated keypair. Valid values are |
| `--num` | `int` | `num` | `false` | `10` | number of keypairs for each keyspec |
| `--password` | `String` | `passwordHint` | `false` | `` | password to encrypt the generated keypair, as plaintext or PBE-encrypted. |

Arguments:
- None

### `xi:base64`

- Module: `shell-base`
- Class: `Base64EnDecode`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: Base64 encode / decode

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--decode` | `boolean` | `decode` | `false` | `false` | Decode |

Arguments:
- None

### `xi:cert-info`

- Module: `security-shell`
- Class: `CertInfo`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/SecurityActions.java`
- Description: print certificate information

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--der` | `Boolean` | `der` | `false` | `Boolean.FALSE` | print DER-encoded issuer and subject in hex format |
| `--fingerprint` | `Boolean` | `fingerprint` | `false` | `` | print fingerprint in hex |
| `--hex` | `Boolean` | `hex` | `false` | `Boolean.FALSE` | print (serial) number in hex format |
| `--issuer` | `Boolean` | `issuer` | `false` | `` | print issuer |
| `--not-after` | `Boolean` | `notAfter` | `false` | `` | print notAfter |
| `--not-before` | `Boolean` | `notBefore` | `false` | `` | print notBefore |
| `--serial` | `Boolean` | `serial` | `false` | `` | print serial number |
| `--subject` | `Boolean` | `subject` | `false` | `` | print subject |
| `--text` | `Boolean` | `text` | `false` | `` | print text (as openssl x509 -text) |

Arguments:
- None

### `xi:cmp-cacert`

- Module: `pki-client-shell`
- Class: `CmpCacert`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/cmp/client/shell/CmpActions.java`
- Description: get CA certificate

Options:
- None

Arguments:
- None

### `xi:cmp-cacerts`

- Module: `pki-client-shell`
- Class: `CmpCacertchain`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/cmp/client/shell/CmpActions.java`
- Description: get CA certificate chain

Options:
- None

Arguments:
- None

### `xi:cmp-csr-enroll`

- Module: `pki-client-shell`
- Class: `CmpCsrEnroll`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/cmp/client/shell/EnrollCertActions.java`
- Description: enroll certificate via CSR

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--not-after` | `String` | `notAfterS` | `false` | `` | notAfter, UTC time of format yyyyMMddHHmmss |
| `--not-before` | `String` | `notBeforeS` | `false` | `` | notBefore, UTC time of format yyyyMMddHHmmss |
| `--profile` | `String` | `profile` | `true` | `` | certificate profile |

Arguments:
- None

### `xi:cmp-enroll-p11`

- Module: `pki-client-shell`
- Class: `CmpEnrollP11`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/cmp/client/shell/EnrollCertActions.java`
- Description: enroll certificate (PKCS#11 token)

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--key-id` | `String` | `keyId` | `false` | `` | id of the private key in the PKCS#11 device\n |
| `--key-label` | `String` | `keyLabel` | `false` | `` | label of the private key in the PKCS#11 device\n |
| `--module` | `String` | `moduleName` | `false` | `"default"` | name of the PKCS#11 module |
| `--slot` | `String` | `slotIndex` | `true` | `"0"` | slot index |

Arguments:
- None

### `xi:cmp-enroll-p12`

- Module: `pki-client-shell`
- Class: `CmpEnrollP12`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/cmp/client/shell/EnrollCertActions.java`
- Description: enroll certificate (PKCS#12 keystore)

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--password` | `String` | `passwordHint` | `false` | `` | password of the PKCS#12 keystore file, as plaintext or PBE-encrypted. |

Arguments:
- None

### `xi:cmp-enroll-serverkeygen`

- Module: `pki-client-shell`
- Class: `CmpEnrollCagenkey`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/cmp/client/shell/EnrollCertActions.java`
- Description: enroll certificate (keypair will be generated by the CA)

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--password` | `String` | `passwordHint` | `false` | `` | password of the PKCS#12 file, as plaintext or PBE-encrypted. |

Arguments:
- None

### `xi:cmp-get-crl`

- Module: `pki-client-shell`
- Class: `CmpGetCrl`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/cmp/client/shell/CrlActions.java`
- Description: download CRL

Options:
- None

Arguments:
- None

### `xi:cmp-revoke`

- Module: `pki-client-shell`
- Class: `CmpRevoke`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/cmp/client/shell/UnRevokeCertActions.java`
- Description: revoke certificate

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--inv-date` | `String` | `invalidityDateS` | `false` | `` | invalidity date, UTC time of format yyyyMMddHHmmss |

Arguments:
- None

### `xi:cmp-unsuspend`

- Module: `pki-client-shell`
- Class: `CmpUnsuspend`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/cmp/client/shell/UnRevokeCertActions.java`
- Description: unsuspend certificate

Options:
- None

Arguments:
- None

### `xi:cmp-update-p11`

- Module: `pki-client-shell`
- Class: `CmpUpdateP11`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/cmp/client/shell/UpdateCertActions.java`
- Description: update certificate (PKCS#11 token)

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--key-id` | `String` | `keyId` | `false` | `` | id of the private key in the PKCS#11 device\n |
| `--key-label` | `String` | `keyLabel` | `false` | `` | label of the private key in the PKCS#11 device\n |
| `--module` | `String` | `moduleName` | `false` | `"default"` | name of the PKCS#11 module |
| `--slot` | `String` | `slotIndex` | `true` | `"0"` | slot index |

Arguments:
- None

### `xi:cmp-update-p12`

- Module: `pki-client-shell`
- Class: `CmpUpdateP12`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/cmp/client/shell/UpdateCertActions.java`
- Description: update certificate (PKCS#12 keystore)

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--password` | `String` | `passwordHint` | `false` | `` | password of the PKCS#12 keystore file, as plaintext or PBE-encrypted. |

Arguments:
- None

### `xi:cmp-update-serverkeygen`

- Module: `pki-client-shell`
- Class: `CmpUpdateCagenkey`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/cmp/client/shell/UpdateCertActions.java`
- Description: update certificate (keypair will be generated by the CA)

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--password` | `String` | `passwordHint` | `false` | `` | password of the PKCS#12 file, as plaintext or PBE-encrypted. |

Arguments:
- None

### `xi:confirm`

- Module: `shell-base`
- Class: `Confirm`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: confirm an action

Options:
- None

Arguments:
| Index | Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|---|
| `` | `message` | `String` | `prompt` | `true` | `` | prompt message |

### `xi:convert-keystore`

- Module: `security-shell`
- Class: `ConvertKeystore`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/SecurityActions.java`
- Description: Convert keystore

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--inpwd` | `String` | `inPwdHint` | `false` | `` | password of the source keystore, as plaintext or PBE-encrypted. |
| `--outpwd` | `String` | `outPwdHint` | `false` | `` | password of the destination keystore, as plaintext or PBE-encrypted.\n |

Arguments:
- None

### `xi:copy-dir`

- Module: `shell-base`
- Class: `CopyDir`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: copy content of the directory to destination

Options:
- None

Arguments:
- None

### `xi:copy-file`

- Module: `shell-base`
- Class: `CopyFile`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: copy file

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | override existing file, never prompt |

Arguments:
- None

### `xi:crl-info`

- Module: `security-shell`
- Class: `CrlInfo`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/SecurityActions.java`
- Description: print CRL information

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--crlnumber` | `Boolean` | `crlNumber` | `false` | `` | print CRL number |
| `--hex` | `Boolean` | `hex` | `false` | `Boolean.FALSE` | print hex number |
| `--issuer` | `Boolean` | `issuer` | `false` | `` | print issuer |
| `--next-update` | `Boolean` | `nextUpdate` | `false` | `` | print nextUpdate |
| `--this-update` | `Boolean` | `thisUpdate` | `false` | `` | print thisUpdate |

Arguments:
- None

### `xi:csr-jce`

- Module: `security-shell`
- Class: `CsrJceAction`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/CsrActions.java`
- Description: generate CSR request with JCE device

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--alias` | `String` | `alias` | `true` | `` | alias of the key in the JCE device |
| `--type` | `String` | `type` | `true` | `` | JCE signer type |

Arguments:
- None

### `xi:csr-p11`

- Module: `security-shell`
- Class: `CsrP11Action`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/CsrActions.java`
- Description: generate CSR request with PKCS#11 device

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--id` | `String` | `id` | `false` | `` | id (hex) of the private key in the PKCS#11 device\n |
| `--label` | `String` | `label` | `false` | `` | label of the private key in the PKCS#11 device\n |
| `--rsa-pss` | `Boolean` | `rsaPss` | `false` | `Boolean.FALSE` | whether to use the RSAPSS for the POP computation\n |
| `--slot` | `String` | `slotIndex` | `false` | `"0"` | slot index |

Arguments:
- None

### `xi:csr-p12`

- Module: `security-shell`
- Class: `CsrP12Action`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/CsrActions.java`
- Description: generate CSR with PKCS#12 keystore

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--password` | `String` | `passwordHint` | `false` | `` | password of the PKCS#12 keystore file, as plaintext or PBE-encrypted. |
| `--rsa-pss` | `Boolean` | `rsaPss` | `false` | `Boolean.FALSE` | whether to use the RSAPSS for the POP computation\n |

Arguments:
- None

### `xi:curl`

- Module: `shell-base`
- Class: `Curl`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: transfer a URL

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--base64` | `boolean` | `base64` | `false` | `` | Base64-encode the content |
| `--data` | `String` | `postData` | `false` | `` | data to be sent in a POST request |
| `--data-charset` | `String` | `postDataCharSet` | `false` | `"UTF-8"` | charset of data |
| `--header` | `List<String>` | `headers` | `false` | `` | header in request |
| `--post` | `Boolean` | `usePost` | `false` | `Boolean.FALSE` | send the request via HTTP POST |
| `--user` | `String` | `userPassword` | `false` | `` | User and password of the form user:password |
| `--verbose` | `Boolean` | `verbose` | `false` | `Boolean.FALSE` | show request and response verbosely |

Arguments:
| Index | Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|---|
| `` | `url` | `String` | `url` | `true` | `` | URL |

### `xi:datetime`

- Module: `shell-base`
- Class: `DateTime`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: get current date-time

Options:
- None

Arguments:
- None

### `xi:delete-all-objects-p11`

- Module: `security-shell`
- Class: `DeleteAllObjectsP11`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/P11Actions.java`
- Description: delete all objects in PKCS#11 device

Options:
- None

Arguments:
- None

### `xi:delete-key-p11`

- Module: `security-shell`
- Class: `DeleteKeyP11`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/P11Actions.java`
- Description: delete key in PKCS#11 device

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | remove identifies without prompt |
| `--id` | `String` | `id` | `false` | `` | id (hex) of the private key in the PKCS#11 device, \n |
| `--label` | `String` | `label` | `false` | `` | label of the private key in the PKCS#11 device\n |

Arguments:
- None

### `xi:delete-objects-p11`

- Module: `security-shell`
- Class: `DeleteObjectsP11`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/P11Actions.java`
- Description: delete objects in PKCS#11 device

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | remove identifies without prompt |
| `--handle` | `long[]` | `handles` | `false` | `` | Object handle, if specified, id and label must not be set |
| `--id` | `String` | `id` | `false` | `` | id (hex) of the objects in the PKCS#11 device\n |
| `--label` | `String` | `label` | `false` | `` | label of the objects in the PKCS#11 device\n |

Arguments:
- None

### `xi:deobfuscate`

- Module: `security-shell`
- Class: `Deobfuscate`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/PasswordActions.java`
- Description: deobfuscate password

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--password` | `String` | `passwordHint` | `false` | `` | obfuscated password, starts with |

Arguments:
- None

### `xi:exec`

- Module: `shell-base`
- Class: `ExecTerminalCommand`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: execute terminal

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--ignore-error` | `Boolean` | `ignoreError` | `false` | `` | whether ignores error |

Arguments:
- None

### `xi:export-cert-p12`

- Module: `security-shell`
- Class: `ExportCertP12`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/P12Actions.java`
- Description: export certificate from PKCS#12 keystore

Options:
- None

Arguments:
- None

### `xi:export-cert-p7m`

- Module: `security-shell`
- Class: `ExportCertP7m`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/SecurityActions.java`
- Description: export (the first) certificate from CMS signed data

Options:
- None

Arguments:
- None

### `xi:export-keycert-est`

- Module: `security-shell`
- Class: `ExportKeyCertEst`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/SecurityActions.java`
- Description: export key and certificate from the response of EST's serverkeygen

Options:
- None

Arguments:
- None

### `xi:export-keycert-pem`

- Module: `security-shell`
- Class: `ExportKeyCertPem`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/SecurityActions.java`
- Description: export key and certificate from the PEM file

Options:
- None

Arguments:
- None

### `xi:file-exists`

- Module: `shell-base`
- Class: `FileExists`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: test whether file or folder exists

Options:
- None

Arguments:
- None

### `xi:import-cert`

- Module: `security-shell`
- Class: `ImportCert`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/SecurityActions.java`
- Description: import certificates to a keystore

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--password` | `String` | `ksPwdHint` | `false` | `` | password of the keystore, as plaintext or PBE-encrypted. |

Arguments:
- None

### `xi:import-secretkey-p11`

- Module: `security-shell`
- Class: `ImportSecretkeyP11`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/P11Actions.java`
- Description: import secret key with given value in PKCS#11 device

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--password` | `String` | `passwordHint` | `false` | `` | password of the keystore file, as plaintext or PBE-encrypted. |

Arguments:
- None

### `xi:keypair-p11`

- Module: `security-shell`
- Class: `KeypairP11`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/P11Actions.java`
- Description: generate keypair in PKCS#11 device

Options:
- None

Arguments:
- None

### `xi:keypair-p12`

- Module: `security-shell`
- Class: `KeypairP12`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/P12Actions.java`
- Description: generate keypair in PKCS#12 keystore

Options:
- None

Arguments:
- None

### `xi:lowercase`

- Module: `shell-base`
- Class: `Lowercase`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: convert to lowercase string

Options:
- None

Arguments:
| Index | Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|---|
| `` | `text` | `String` | `text` | `true` | `` | text to be converted |

### `xi:mkdir`

- Module: `shell-base`
- Class: `Mkdir`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: make directories

Options:
- None

Arguments:
- None

### `xi:move-dir`

- Module: `shell-base`
- Class: `MoveDir`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: move content of the directory to destination

Options:
- None

Arguments:
- None

### `xi:move-file`

- Module: `shell-base`
- Class: `MoveFile`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: move file

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | override existing file, never prompt |

Arguments:
- None

### `xi:obfuscate`

- Module: `security-shell`
- Class: `Obfuscate`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/PasswordActions.java`
- Description: obfuscate password

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `-k` | `Integer` | `quorum` | `false` | `1` | quorum of the password parts |

Arguments:
- None

### `xi:object-exists-p11`

- Module: `security-shell`
- Class: `ObjectExistsP11`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/P11Actions.java`
- Description: return whether objects exist in PKCS#11 device

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--id` | `String` | `id` | `false` | `` | id (hex) of the object in the PKCS#11 device\n |
| `--label` | `String` | `label` | `false` | `` | label of the object key in the PKCS#11 device\n |

Arguments:
- None

### `xi:ocsp-status`

- Module: `pki-client-shell`
- Class: `OcspStatus`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/ocsp/client/shell/OcspActions.java`
- Description: request certificate status

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--quiet` | `Boolean` | `quiet` | `false` | `Boolean.FALSE` | Do not throw error if OCSP status is not 'OK' |

Arguments:
- None

### `xi:osinfo`

- Module: `shell-base`
- Class: `OsInfo`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: get info of operation system

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--arch` | `Boolean` | `printArch` | `false` | `` | output OS arch |
| `--name` | `Boolean` | `printName` | `false` | `` | output OS name |

Arguments:
- None

### `xi:pbe-dec`

- Module: `security-shell`
- Class: `PbeDec`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/PasswordActions.java`
- Description: decrypt password with master password

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--password` | `String` | `passwordHint` | `false` | `` | encrypted password, starts with PBE:\n |

Arguments:
- None

### `xi:pbe-enc`

- Module: `security-shell`
- Class: `PbeEnc`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/PasswordActions.java`
- Description: encrypt password with master password

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `-k` | `Integer` | `quorum` | `false` | `1` | quorum of the password parts |

Arguments:
- None

### `xi:pkcs12`

- Module: `security-shell`
- Class: `Pkcs12`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/P12Actions.java`
- Description: export PKCS#12 key store, like the 'openssl pkcs12' command

Options:
- None

Arguments:
- None

### `xi:replace`

- Module: `shell-base`
- Class: `Replace`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: replace text in file

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--new` | `List<String>` | `newTexts` | `true` | `` | new text |
| `--old` | `List<String>` | `oldTexts` | `true` | `` | text to be replaced |

Arguments:
- None

### `xi:rm`

- Module: `shell-base`
- Class: `Rm`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: remove file or directory

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--force` | `Boolean` | `force` | `false` | `Boolean.FALSE` | remove files without prompt |
| `--recursive` | `Boolean` | `recursive` | `false` | `Boolean.FALSE` | remove directories and their contents recursively |

Arguments:
- None

### `xi:scep-cacert`

- Module: `pki-client-shell`
- Class: `ScepCacert`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/scep/client/shell/ScepActions.java`
- Description: get CA certificate

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--ca-id` | `String` | `caId` | `false` | `` | CA identifier |
| `--url` | `String` | `url` | `true` | `` | URL of the SCEP server |

Arguments:
- None

### `xi:scep-certpoll`

- Module: `pki-client-shell`
- Class: `ScepCertpoll`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/scep/client/shell/ScepActions.java`
- Description: poll certificate

Options:
- None

Arguments:
- None

### `xi:scep-enroll`

- Module: `pki-client-shell`
- Class: `ScepEnroll`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/scep/client/shell/ScepActions.java`
- Description: enroll certificate

Options:
- None

Arguments:
- None

### `xi:scep-get-cert`

- Module: `pki-client-shell`
- Class: `ScepGetCert`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/scep/client/shell/ScepActions.java`
- Description: download certificate

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--serial` | `String` | `serialNumber` | `true` | `` | serial number |

Arguments:
- None

### `xi:scep-get-crl`

- Module: `pki-client-shell`
- Class: `ScepGetCrl`
- Source: `shells/pki-client-shell/src/main/java/org/xipki/scep/client/shell/ScepActions.java`
- Description: download CRL

Options:
- None

Arguments:
- None

### `xi:secretkey-p11`

- Module: `security-shell`
- Class: `SecretkeyP11`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/P11Actions.java`
- Description: generate secret key in PKCS#11 device

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--extern-if-gen-unsupported` | `Boolean` | `createExternIfGenUnsupported` | `false` | `Boolean.FALSE` | If set, if the generation mechanism is not supported by the PKCS#11 |
| `--key-size` | `Integer` | `keysize` | `false` | `` | keysize in bit |

Arguments:
- None

### `xi:secretkey-p12`

- Module: `security-shell`
- Class: `SecretkeyP12`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/P12Actions.java`
- Description: generate secret key in JCEKS (not PKCS#12) keystore

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--key-size` | `Integer` | `keysize` | `false` | `` | keysize in bit |

Arguments:
- None

### `xi:speed-keypair-p11`

- Module: `security-shell`
- Class: `SpeedKeypairGenP11`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/QaSecurityActions.java`
- Description: performance test of PKCS#11 key generation

Options:
- None

Arguments:
- None

### `xi:speed-keypair-p12`

- Module: `security-shell`
- Class: `SpeedKeypairGenP12`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/QaSecurityActions.java`
- Description: performance test of PKCS#12 keypair key generation

Options:
- None

Arguments:
- None

### `xi:speed-sign-p11`

- Module: `security-shell`
- Class: `SpeedSignP11`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/QaSecurityActions.java`
- Description: performance test of PKCS#11 signature creation

Options:
- None

Arguments:
- None

### `xi:speed-sign-p12`

- Module: `security-shell`
- Class: `SpeedSignP12`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/QaSecurityActions.java`
- Description: performance test of PKCS#12 signature creation

Options:
- None

Arguments:
- None

### `xi:token-info-p11`

- Module: `security-shell`
- Class: `TokenInfoP11`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/P11Actions.java`
- Description: list objects in PKCS#11 device

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--object` | `Long` | `objectHandle` | `false` | `` | object handle |
| `--slot` | `Integer` | `slotIndex` | `false` | `` | slot index |
| `--verbose` | `Boolean` | `verbose` | `false` | `Boolean.FALSE` | show object information verbosely |

Arguments:
- None

### `xi:update-cert-p12`

- Module: `security-shell`
- Class: `UpdateCertP12`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/P12Actions.java`
- Description: update certificate in PKCS#12 keystore

Options:
- None

Arguments:
- None

### `xi:uppercase`

- Module: `shell-base`
- Class: `Uppercase`
- Source: `shells/shell-base/src/main/java/org/xipki/shell/Actions.java`
- Description: convert to uppercase string

Options:
- None

Arguments:
| Index | Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|---|
| `` | `text` | `String` | `text` | `true` | `` | text to be converted |

### `xi:validate-csr`

- Module: `security-shell`
- Class: `ValidateCsrAction`
- Source: `shells/security-shell/src/main/java/org/xipki/security/shell/CsrActions.java`
- Description: validate CSR

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--keystore-password` | `String` | `keystorePasswordHint` | `false` | `` | password of the keystore, as plaintext or PBE-encrypted. |

Arguments:
- None

### `xiqa:batch-ocsp-status`

- Module: `qa-shell`
- Class: `BatchOcspQaStatusAction`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaOcspActions.java`
- Description: batch request status of certificates (QA)

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--hex` | `Boolean` | `hex` | `false` | `Boolean.FALSE` | serial number without prefix is hex number |
| `--no-sig-verify` | `Boolean` | `noSigVerify` | `false` | `Boolean.FALSE` | where to verify the signature |
| `--save-req` | `Boolean` | `saveReq` | `false` | `Boolean.FALSE` | whether to save the request |
| `--save-resp` | `Boolean` | `saveResp` | `false` | `Boolean.FALSE` | whether to save the request |
| `--url` | `String` | `serverUrlStr` | `true` | `` | OCSP responder URL |

Arguments:
- None

### `xiqa:benchmark-enroll`

- Module: `qa-shell`
- Class: `BenchmarkEnroll`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaActions.java`
- Description: Enroll certificate (benchmark)

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--new-key` | `boolean` | `newKey` | `false` | `false` | Generate different keypair for each certificate |

Arguments:
- None

### `xiqa:benchmark-enroll-serverkeygen`

- Module: `qa-shell`
- Class: `BenchmarkCaGenEnroll`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaCaActions.java`
- Description: Enroll certificate (CA generates keypairs, benchmark)

Options:
- None

Arguments:
- None

### `xiqa:benchmark-ocsp-status`

- Module: `qa-shell`
- Class: `BenchmarkOcspStatusAction`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaOcspActions.java`
- Description: OCSP benchmark

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--duration` | `String` | `duration` | `false` | `"30s"` | duration |
| `--hex` | `Boolean` | `hex` | `false` | `Boolean.FALSE` | serial number without prefix is hex number |
| `--max-num` | `Integer` | `maxRequests` | `false` | `0` | maximal number of OCSP queries\n0 for unlimited |
| `--serial` | `String` | `serialNumberList` | `false` | `` | comma-separated serial numbers or ranges (like 1,3,6-10)\n |
| `--thread` | `Integer` | `numThreads` | `false` | `5` | number of threads |
| `--url` | `String` | `serverUrl` | `true` | `` | OCSP responder URL |

Arguments:
- None

### `xiqa:qa-ocsp-status`

- Module: `qa-shell`
- Class: `OcspQaStatusAction`
- Source: `shells/qa-shell/src/main/java/org/xipki/qa/shell/QaOcspActions.java`
- Description: request certificate status (QA)

Options:
| Name | Type | Variable | Required | Default | Description |
|---|---|---|---|---|---|
| `--no-sig-verify` | `Boolean` | `noSigVerify` | `false` | `Boolean.FALSE` | no verification of the signature |
| `--rev-time` | `List<String>` | `revTimeTexts` | `false` | `` | revocation time, UTC time of format yyyyMMddHHmmss |

Arguments:
- None

