XiPKI Commands
=====

The karaf feature can be installed via the command `feature:install <feature name>` and uninstalled
in the OSGi console via the command `feature:uninstall <feature name>`. The possible feature can be
auto-completed by typing the `TAB` key.

Some features in XiPKI are listed below, a list of all available features can be retrieved via the
command `feature:list  | grep xipki` in OSGi console.

For the usage of OSGi commands, just use the option `--help`. Most XiPKI commands can 
auto-completing the options and arguments by the `TAB` key.

Feature xipki-shell-base
-----

   * `xipki-cmd:confirm`

     confirm an action

   * `xipki-cmd:copy-dir`

     copy content of the directory to destination

   * `xipki-cmd:copy-file`

     copy file

   * `xipki-cmd:ls`

     list directory contents

   * `xipki-cmd:rm`

     remove file or directory

   * `xipki-cmd:mkdir`

     make directories

   * `xipki-cmd:produce-password`

     produce password

   * `xipki-cmd:replace`

     replace text in file

   * `xipki-cmd:curl`

     transfer a URL

Feature xipki-database-tool
-----

   * `xipki-db:diff-digest-db`

     diff digest XiPKI/EJBCA databas

   * `xipki-db:digest-db`

     digest XiPKI/EJBCA database

   * `xipki-db:export-ca`

     export CA database

   * `xipki-db:export-ocsp`

     export OCSP database

   * `xipki-db:import-ca`

     import CA database

   * `xipki-db:import-ocsp`

     import OCSP database

   * `xipki-db:import-ocspfromca`

     reset and initialize the CA and OCSP databases

   * `xipki-db:initdb`

     reset and initialize database

   * `xipki-db:initdb-pki`

     reset and initialize the CA and OCSP databases

   * `xipki-db:initdb-ca`

     reset and initialize the CA database

   * `xipki-db:initdb-ocsp`

     reset and initialize the OCSP databases

   * `xipki-db:updatedb-ca`
     update the CA database schema

   * `xipki-db:updatedb-ocsp`

     update the OCSP database schema

Feature xipki-security-shell
-----

   * `xipki-tk:cert-info`

     print certificate information

   * `xipki-tk:crl-info`

     print CRL information

   * `xipki-tk:validate-csr`

     validate CSR

   * `xipki-tk:deobfuscate`

     deobfuscate password

   * `xipki-tk:extract-cert`

     extract certificates from CRL

   * `xipki-tk:obfuscate`

     obfuscate password

   * `xipki-tk:pbe-dec`

     decrypt password with master password

   * `xipki-tk:pbe-enc`

     encrypt password with master password

   * `xipki-tk:add-cert`

     add certificate to PKCS#11 device

   * `xipki-tk:rm-cert`

     remove certificate from PKCS#11 device

   * `xipki-tk:export-cert`

     export certificate from PKCS#11 device

   * `xipki-tk:export-cert-p12`

     export certificate from PKCS#12 keystore

   * `xipki-tk:req`

     generate CSR with PKCS#11 device

   * `xipki-tk:req-p12`

     generate CSR with PKCS#12 keystore

   * `xipki-tk:update-cert`

     update certificate in PKCS#11 device

   * `xipki-tk:update-cert-p12`

     update certificate in PKCS#12 keystore

   * `xipki-tk:dsa`

     generate DSA keypair in PKCS#11 device

   * `xipki-tk:dsa-p12`

     generate RSA keypair in PKCS#12 keystore

   * `xipki-tk:ec`

     generate EC keypair in PKCS#11 device

   * `xipki-tk:ec-p12`

     generate EC keypair in PKCS#12 keystore

   * `xipki-tk:delete-key`

     delete key and cert in PKCS#11 device

   * `xipki-tk:token-info`

     list objects in PKCS#11 device

   * `xipki-tk:delete-objects`

     delete objects in PKCS#11 device

   * `xipki-tk:provider-test`

     test the Xipki JCA/JCE provider

   * `xipki-tk:refresh`

     refresh PKCS#11 module
     
   * `xipki-tk:create-secretkey`
     
     create secret key with given value in PKCS#11 device

   * `xipki-tk:secretkey`
     
     generate secret key in PKCS#11 device
     
   * `xipki-tk:secretkey-p12`
     
     generate secret key in JCEKS (not PKCS#12) keystore
     
   * `xipki-tk:rsa`

     generate RSA keypair in PKCS#11 device

   * `xipki-tk:rsa-p12`

     generate RSA keypair in PKCS#12 keystore

   * `keystore-convert`
     convert the keystore format

   * `xipki-tk:speed-dsa-gen`

     performance test of PKCS#11 DSA key generation

   * `xipki-tk:speed-dsa-gen-p12`

     performance test of PKCS#12 DSA key generation

   * `xipki-tk:speed-dsa-sign`

     performance test of PKCS#11 DSA signature creation

   * `xipki-tk:speed-dsa-sign-p12`

     performance test of PKCS#12 DSA signature creation

   * `xipki-tk:speed-ec-gen`

     performance test of PKCS#11 EC key generation

   * `xipki-tk:speed-ec-gen-p12`

     performance test of PKCS#12 EC key generation

   * `xipki-tk:speed-ec-sign`

     performance test of PKCS#11 EC signature creation

   * `xipki-tk:speed-ec-sign-p12`

     performance test of PKCS#12 EC signature creation

   * `xipki-tk:speed-rsa-gen`

     performance test of PKCS#11 RSA key generation

   * `xipki-tk:speed-rsa-gen-p12`

     performance test of PKCS#12 RSA key generation

   * `xipki-tk:speed-rsa-sign`

     performance test of PKCS#11 RSA signature creation

   * `xipki-tk:speed-rsa-sign-p12`

     performance test of PKCS#12 RSA signature creation

   * `xipki-tk:bspeed-dsa-gen`

     performance test of PKCS#11 DSA key generation (batch)

   * `xipki-tk:bspeed-dsa-gen-p12`

     performance test of PKCS#12 DSA key generation (batch)

   * `xipki-tk:bspeed-dsa-sign`

     performance test of PKCS#11 DSA signature creation (batch)

   * `xipki-tk:bspeed-dsa-sign-p12`

     performance test of PKCS#12 DSA signature creation (batch)

   * `xipki-tk:bspeed-ec-gen`

     performance test of PKCS#11 EC key generation (batch)

   * `xipki-tk:bspeed-ec-gen-p12`

     performance test of PKCS#12 EC key generation (batch)

   * `xipki-tk:bspeed-ec-sign`

     performance test of PKCS#11 EC signature creation (batch)

   * `xipki-tk:bspeed-ec-sign-p12`

     performance test of PKCS#12 EC signature creation (batch)

   * `xipki-tk:bspeed-rsa-gen`

     performance test of PKCS#11 RSA key generation (batch)

   * `xipki-tk:bspeed-rsa-gen-p12`

     performance test of PKCS#12 RSA key generation (batch)

   * `xipki-tk:bspeed-rsa-sign`

     performance test of PKCS#11 RSA signature creation (batch)

   * `xipki-tk:bspeed-rsa-sign-p12`

     performance test of PKCS#12 RSA signature creation (batch)

Feature xipki-camgmt-shell
-----

   * `xipki-ca:ca-add`

     add CA

   * `xipki-ca:caalias-add`

     add CA alias

   * `xipki-ca:caalias-info`

     show information of CA alias

   * `xipki-ca:caalias-rm`

     remove CA alias

   * `xipki-ca:gen-rca`

     generate selfsigned CA

   * `xipki-ca:ca-info`

     show information of CA

   * `xipki-ca:caprofile-add`

     add certificate profile to CA

   * `xipki-ca:caprofile-info`

     show information of certificate profile in given CA

   * `xipki-ca:caprofile-rm`

     remove certificate profile from CA

   * `xipki-ca:capub-add`

     add publisher to CA

   * `xipki-ca:capub-info`

     show information of publisher in given CA

   * `xipki-ca:capub-rm`

     remove publisher from CA

   * `xipki-ca:ca-rm`

     remove CA

   * `xipki-ca:careq-add`

     add requestor to CA

   * `xipki-ca:careq-info`

     show information of requestor in CA

   * `xipki-ca:careq-rm`

     remove requestor from CA

   * `xipki-ca:causer-add`

     add user to CA

   * `xipki-ca:causer-info`

     show information of user in CA

   * `xipki-ca:causer-rm`

     remove user from CA

   * `xipki-ca:ca-revoke`

     revoke CA

   * `xipki-ca:export-conf`

     export configuration to zip file

   * `xipki-ca:load-conf`

     load configuration

   * `xipki-ca:notify-change`

     notify the change of CA system

   * `xipki-ca:restart`

     restart CA system

   * `xipki-ca:system-status`

     show CA system status

   * `xipki-ca:unlock`

     unlock CA system

   * `xipki-ca:ca-unrevoke`

     unrevoke CA

   * `xipki-ca:ca-up`

     update CA

   * `xipki-ca:clear-publishqueue`

     clear publish queue

   * `xipki-ca:cmpcontrol-add`

     add CMP control

   * `xipki-ca:cmpcontrol-info`

     show information of CMP control

   * `xipki-ca:cmpcontrol-rm`

     remove CMP control

   * `xipki-ca:cmpcontrol-up`

     update CMP control

   * `xipki-ca:crlsigner-add`

     add CRL signer

   * `xipki-ca:crlsigner-info`

     show information of CRL signer

   * `xipki-ca:crlsigner-rm`

     remove CRL signer

   * `xipki-ca:crlsigner-up`

     update CRL signer

   * `xipki-ca:env-add`

     add CA environment parameter

   * `xipki-ca:env-info`

     show information of CA environment parameter

   * `xipki-ca:env-rm`

     remove CA environment parameter

   * `xipki-ca:env-up`

     update CA environment parameter

   * `xipki-ca:profile-add`

     add certificate profile

   * `xipki-ca:profile-export`

     export certificate profile configuration

   * `xipki-ca:profile-info`

     show information of certifiate profile

   * `xipki-ca:profile-rm`

     remove certifiate profile

   * `xipki-ca:profile-up`

     update certificate profile

   * `xipki-ca:publisher-add`

     add publisher

   * `xipki-ca:publisher-export`

     export publisher configuration

   * `xipki-ca:publisher-info`

     show information of publisher

   * `xipki-ca:publisher-rm`

     remove publisher

   * `xipki-ca:publisher-up`

     update publisher

   * `xipki-ca:republish`

     republish certificates

   * `xipki-ca:requestor-add`

     add requestor

   * `xipki-ca:requestor-info`

     show information of requestor

   * `xipki-ca:requestor-rm`

     remove requestor

   * `xipki-ca:requestor-up`

     update requestor

   * `xipki-ca:responder-add`

     add responder

   * `xipki-ca:responder-info`

     show information of responder

   * `xipki-ca:responder-rm`

     remove responder

   * `xipki-ca:responder-up`

     update responder

   * `xipki-ca:scep-add`

     add SCEP

   * `xipki-ca:scep-info`

     show information of SCEP

   * `xipki-ca:scep-rm`

     remove SCEP

   * `xipki-ca:scep-up`

     update SCEP

   * `xipki-ca:user-add`

     add user

   * `xipki-ca:user-info`

     show information of user

   * `xipki-ca:user-rm`

      remove user

   * `xipki-ca:user-up`

     update user

   * `xipki-ca:cert-status`

     show certificate status

   * `xipki-ca:enroll-cert`

     enroll certificate

   * `xipki-ca:gencrl`

     generate CRL

   * `xipki-ca:getcrl`

     download CRL

   * `xipki-ca:remove-cert`

     remove certificate

   * `xipki-ca:revoke-cert`

     revoke certificate

   * `xipki-ca:unrevoke-cert`

     unrevoke certificate

   * `xipki-ca:list-cert`

     show a list of certificates

   * `xipki-ca:get-cert`

     get certificate

   * `xipki-ca:get-request`

     get certificate request

Feature xipki-camgmt-qa-shell
-----

   * `xipki-caqa:caalias-check`

     check CA aliases (QA)

   * `xipki-caqa:ca-check`

     check information of CAs (QA)

   * `xipki-caqa:caprofile-check`

     check information of certificate profiles in given CA (QA)

   * `xipki-caqa:capub-check`

     check information of publishers in given CA (QA)

   * `xipki-caqa:careq-check`

     check information of requestors in CA (QA)

   * `xipki-caqa:ccmpcontrol-check`

     show information of CMP control (QA)

   * `xipki-caqa:crlsigner-check`

     check information of CRL signers (QA)

   * `xipki-caqa:env-check`

     check information of CA environment parameters (QA)

   * `xipki-caqa:profile-check`

     check information of profiles (QA)

   * `xipki-caqa:publisher-check`

     check information of publishers (QA)

   * `xipki-caqa:requestor-check`

     check information of requestors (QA)

   * `xipki-caqa:responder-check`

     check information of responder (QA)

   * `xipki-caqa:neg-ca-add`

     add CA (negative, QA)

   * `xipki-caqa:neg-caalias-add`

     add CA alias (negative, QA)

   * `xipki-caqa:neg-caalias-rm`

     remove CA alias (negative, QA)

   * `xipki-caqa:neg-gen-rca`

     generate selfsigned CA (negative, QA)

   * `xipki-caqa:neg-caprofile-add`

     add certificate profiles to CA  (negative, QA)

   * `xipki-caqa:neg-caprofile-rm`

     remove certificate profile from CA (negative, QA)

   * `xipki-caqa:neg-capub-add`

     add publishers to CA (negative, QA)

   * `xipki-caqa:neg-capub-rm`

     remove publisher from CA (negative, QA)

   * `xipki-caqa:neg-ca-rm`

     remove CA (negative, QA)

   * `xipki-caqa:neg-careq-add`

     add requestor to CA (negative, QA)

   * `xipki-caqa:neg-careq-rm`

     remove requestor in CA (negative, QA)

   * `xipki-caqa:neg-ca-revoke`

     revoke CA (negative, QA)

   * `xipki-caqa:neg-ca-unrevoke`

     unrevoke CA (negative, QA)

   * `xipki-caqa:neg-ca-up`

     update CA (negative, QA)

   * `xipki-caqa:neg-clear-publishqueue`

     clear publish queue (negative, QA)

   * `xipki-caqa:neg-cmpcontrol-add`

     add CMP control (negative, QA)

   * `xipki-caqa:neg-cmpcontrol-rm`

     remove CMP control (negative, QA)

   * `xipki-caqa:neg-cmpcontrol-up`

     update CMP control (negative, QA)

   * `xipki-caqa:neg-crlsigner-add`

     add CRL signer (negative, QA)

   * `xipki-caqa:neg-crlsigner-rm`

     remove CRL signer (negative, QA)

   * `xipki-caqa:neg-crlsigner-up`

     update CRL signer (negative, QA)

   * `xipki-caqa:neg-env-add`

     add environment parameter (negative, QA)

   * `xipki-caqa:neg-env-rm`

     remove environment parameter (negative, QA)

   * `xipki-caqa:neg-env-up`

     update environment parameter (negative, QA)

   * `xipki-caqa:neg-profile-add`

     add certificate profile (negative, QA)

   * `xipki-caqa:neg-profile-rm`

     remove certificate profile (negative, QA)

   * `xipki-caqa:neg-profile-up`

     update certificate profile (negative, QA)

   * `xipki-caqa:neg-publisher-add`

     add publisher (negative, QA)

   * `xipki-caqa:neg-publisher-rm`

     remove publisher (negative, QA)

   * `xipki-caqa:neg-publisher-up`

     update publisher (negative, QA)

   * `xipki-caqa:neg-republish`

     republish certificates (negative, QA)

   * `xipki-caqa:neg-requestor-add`

     add requestor (negative, QA)

   * `xipki-caqa:neg-requestor-rm`

     remove requestor (negative, QA)

   * `xipki-caqa:neg-requestor-up`

     update requestor (negative, QA)

   * `xipki-caqa:neg-responder-add`

     add responder (negative, QA)

   * `xipki-caqa:neg-responder-rm`

     remove responder (negative, QA)

   * `xipki-caqa:neg-responder-up`

     update responder (negative, QA)

Feature xipki-caclient-shell
-----

   * `xipki-cli:gencrl`

     generate CRL

   * `xipki-cli:getcrl`

     download CRL

   * `xipki-cli:health`

     check healty status of CA

   * `xipki-cli:csr-enroll`

     enroll certificate via CSR

   * `xipki-cli:enroll`

     enroll certificate (PKCS#11 token)

   * `xipki-cli:enroll-p12`

     enroll certificate (PKCS#12 keystore)

   * `xipki-cli:remove-cert`

     remove certificate

   * `xipki-cli:revoke-cert`

     revoke certificate

   * `xipki-cli:unrevoke-cert`

     unrevoke certificate

   * `xipki-cli:benchmark-enroll`

     CA client enroll benchmark

   * `xipki-cli:benchmark-revoke`

     CA client revoke benchmark

   * `xipki-cli:benchmark-template-enroll`

     CA client template enroll benchmark

Feature xipki-caqa-shell
-----

   * `xipki-qa:check-cert`

     check the certificate

   * `xipki-qa:neg-gencrl`

     generate CRL (negative, for QA)

   * `xipki-qa:neg-getcrl`

     download CRL (negative, for QA)

   * `xipki-qa:neg-csr-enroll`

     enroll certificate via CSR (negative, for QA)

   * `xipki-qa:neg-enroll-p12`

     enroll certificate (PKCS#12 keystore, negative, for QA)

   * `xipki-qa:neg-revoke`

     revoke certificate (negative, for QA)

   * `xipki-qa:neg-unrevoke`

     unrevoke certificate (negative, for QA)

Feature xipki-scepclient-shell
-----

   * `xipki-scep:certpoll`

     poll certificate

   * `xipki-scep:enroll`

     enroll certificate via automic selected messageType

   * `xipki-scep:getcert`

     download certificate

   * `xipki-scep:getcert-qa`

     download certificate (only used for QA)

   * `xipki-scep:getcrl`

	 download CRL

   * `xipki-scep:pkcs-req`

	 enroll certificate via messageType PkcsReq

   * `xipki-scep:renewal-req`

	 enroll certificate via messageType RenewalReq

   * `xipki-scep:update-req`

	 enroll certificate via messageType UpdateReq

Feature xipki-jscepclient-shell
-----

   * `xipki-jscep:certpoll`
     poll certificate

   * `xipki-jscep:enroll`
     enroll certificate via automic selected messageType

   * `xipki-jscep:getcert`
     download certificate

   * `xipki-jscep:getcert-qa`
     download certificate (only used for QA)

   * `xipki-jscep:getcrl`
     download CRL

Feature xipki-ocspclient-shell
-----

   * `xipki-ocsp:status`

	 request certificate status

Feature xipki-ocspqa-shell
-----

   * `xipki-qa:ocsp-status`

	 request certificate status (QA)

   * `xipki-qa:benchmark-ocsp-status`

     OCSP Benchmark

	 