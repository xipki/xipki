XiPKI CLI Commands
=====

For the usage of CLI commands, just use the option `--help`. Most XiPKI commands can
auto-complete the options and arguments by the `TAB` key.

Basic Commands
--
   * `base64`

     Base64 encode / decode

   * `xi:confirm`

     confirm an action

   * `xi:copy-dir`

     copy content of the directory to destination

   * `xi:copy-file`

     copy file

   * `xi:curl`

     transfer a URL

   * `xi:datetime`

     return date and time

   * `xi:file-exists`

     return whether a file or dir exists

   * `xi:mkdir`

     make directories

   * `xi:move-dir`

     move content of the directory to destination

   * `xi:move-file`

     move file

   * `xi:osinfo`

     return OS info

   * `xi:replace`

     replace text in file

   * `xi:rm`

     remove file or directory

Database Commands
-----

   * `ca:diff-digest`

     diff digest XiPKI databases

   * `ca:export-ca`

     export CA database

   * `ca:export-ocsp`

     export OCSP database

   * `ca:import-ca`

     import CA database

   * `ca:import-ocsp`

     import OCSP database

   * `ca:import-ocspfromca`

     reset and initialize the CA and OCSP databases

   * `ca:sql`

     Run SQL script

Security Commands
-----

   * `xi:cert-info`

     print certificate information

   * `xi:crl-info`

     print CRL information

   * `xi:convert-keystore`

     convert keystore

   * `xi:csr-p11`

     generate CSR with PKCS#11 device

   * `xi:csr-p12`

     generate CSR with PKCS#12 keystore

   * `xi:delete-key-p11`

     delete key and cert in PKCS#11 device

   * `xi:delete-objects-p11`

     delete objects in PKCS#11 device

   * `xi:deobfuscate`

     deobfuscate password

   * `xi:dsa-p11`

     generate DSA keypair in PKCS#11 device

   * `xi:dsa-p12`

     generate RSA keypair in PKCS#12 keystore

   * `xi:ec-p11`

     generate EC keypair in PKCS#11 device

   * `xi:ec-p12`

     generate EC keypair in PKCS#12 keystore

   * `xi:export-cert-p12`

     export certificate from PKCS#12 keystore

   * `xi:export-cert-p7m`

     export (the first) certificate from CMS signed data

   * `xi:export-keycert-est`

     export key and certificate from the response of EST's serverkeygen

   * `xi:import-cert`

     import certificates to a keystore

   * `xi:import-secretkey-p11`

     import secret key with given value in PKCS#11 device

   * `xi:key-exists-p11`

     return whether key and certs exist in PKCS#11 device

   * `xi:obfuscate`

     obfuscate password

   * `xi:pbe-dec`

     decrypt password with master password

   * `xi:pbe-enc`

     encrypt password with master password

   * `xi:pkcs12`

     export PKCS#12 key store, like the 'openssl pkcs12' command

   * `xi:rsa-p11`

     generate RSA keypair in PKCS#11 device

   * `xi:rsa-p12`

     generate RSA keypair in PKCS#12 keystore

   * `xi:secretkey-p11`

     generate secret key in PKCS#11 device

   * `xi:secretkey-p12`

     generate secret key in JCEKS (not PKCS#12) keystore

   * `xi:sm2-p11`

     generate SM2 keypair in PKCS#11 device

   * `xi:sm2-p12`

     generate SM2 keypair in PKCS#12 keystore

   * `xi:token-info-p11`

     list objects in PKCS#11 device

   * `xi:update-cert-p12`

     update certificate in PKCS#12 keystore

   * `xi:validate-csr`

     validate CSR

OCSP Management Commands
-----

   * `ocsp:restart-server`

     restart OCSP server

CA Management Commands
-----

   * `ca:ca-add`

     add CA

   * `ca:ca-info`

     show information of CA

   * `ca:ca-rm`

     remove CA

   * `ca:ca-revoke`

     revoke CA

   * `ca:ca-unrevoke`

     unrevoke CA

   * `ca:ca-up`

     update CA

   * `ca:caalias-add`

     add CA alias

   * `ca:caalias-info`

     show information of CA alias

   * `ca:caalias-rm`

     remove CA alias

   * `ca:caprofile-add`

     add certificate profile to CA

   * `ca:caprofile-info`

     show information of certificate profile in given CA

   * `ca:caprofile-rm`

     remove certificate profile from CA

   * `ca:capub-add`

     add publisher to CA

   * `ca:capub-info`

     show information of publisher in given CA

   * `ca:capub-rm`

     remove publisher from CA

   * `ca:careq-add`

     add requestor to CA

   * `ca:careq-info`

     show information of requestor in CA

   * `ca:careq-rm`

     remove requestor from CA

   * `ca:causer-add`

     add user to CA

   * `ca:causer-rm`

     remove user from CA

   * `ca:cert-status`

     show certificate status

   * `ca:clear-publishqueue`

     clear publish queue

   * `ca:dbschema-add`

     add a DB schema entry

   * `ca:dbschema-info`

     list DB schema entries

   * `ca:dbschema-rm`

     remove a DB schema entry

   * `ca:dbschema-up`

     change a DB schema entry

   * `ca:enroll-cert`

     enroll certificate

   * `ca:export-conf`

     export configuration to zip file

   * `ca:gen-crl`

     generate CRL

   * `ca:gen-rootca`

     generate selfsigned CA

   * `ca:get-cert`

     get certificate

   * `ca:get-crl`

     download CRL

   * `ca:list-cert`

     show a list of certificates

   * `ca:load-conf`

     load configuration

   * `ca:keypairgen-add`

     add keypair generation

   * `ca:keypairgen-info`

     show information of keypair generation

   * `ca:keypairgen-rm`

     remove keypair generation

   * `ca:keypairgen-up`

     change keypair generation

   * `ca:notify-change`

     notify the change of CA system

   * `ca:restart`

     restart CA system

   * `ca:system-status`

     show CA system status

   * `ca:unlock`

     unlock CA system

   * `ca:profile-add`

     add certificate profile

   * `ca:profile-export`

     export certificate profile configuration

   * `ca:profile-info`

     show information of certifiate profile

   * `ca:profile-rm`

     remove certifiate profile

   * `ca:profile-up`

     update certificate profile

   * `ca:publisher-add`

     add publisher

   * `ca:publisher-export`

     export publisher configuration

   * `ca:publisher-info`

     show information of publisher

   * `ca:publisher-rm`

     remove publisher

   * `ca:publisher-up`

     update publisher

   * `ca:republish`

     republish certificates

   * `ca:requestor-add`

     add requestor

   * `ca:requestor-info`

     show information of requestor

   * `ca:requestor-rm`

     remove requestor

   * `ca:requestor-up`

     update requestor

   * `ca:unsuspend-cert`

     unsuspend certificate

   * `ca:rm-cert`

     remove certificate

   * `ca:signer-add`

     add signer

   * `ca:signer-info`

     show information of signer

   * `ca:signer-rm`

     remove signer

   * `ca:signer-up`

     update signer

   * `ca:ca-token-info-p11`

     list objects in PKCS#11 device of the CA

   * `ca:unsuspend-cert`

     unsuspend certificate

   * `ca:user-add`

     add user

   * `ca:user-info`

     show information of user

   * `ca:user-rm`

     remove user

   * `ca:user-up`

     update user

CMP Client Commands
-----

   * `xi:cmp-cacert`

     get CA certificate

   * `xi:cmp-cacerts`

     get CA certificate chain

   * `xi:cmp-csr-enroll`

     enroll certificate via CSR

   * `xi:cmp-enroll-serverkeygen`

     enroll certificate (keypair will be generated by the CA)

   * `xi:cmp-enroll-p11`

     enroll certificate (PKCS#11 token)

   * `xi:cmp-enroll-p12`

     enroll certificate (PKCS#12 keystore)

   * `xi:cmp-get-crl`

     download CRL

   * `xi:cmp-revoke`

     revoke certificate

   * `xi:cmp-unsuspend`

     unsuspend certificate

   * `xi:cmp-update-serverkeygen`

     update certificate (keypair will be generated by the CA)

   * `xi:cmp-update-p11`

     update certificate (PKCS#11 token)

   * `xi:cmp-update-p12`

     update certificate (PKCS#12 token)

SCEP Client Commands
-----

   * `xi:scep-cacert`

     get CA certificate


   * `xi:scep-certpoll`

     poll certificate

   * `xi:scep-enroll`

     enroll certificate

   * `xi:scep-get-cert`

     download certificate

   * `xi:scep-get-crl`

     download CRL

