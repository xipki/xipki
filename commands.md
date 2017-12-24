XiPKI PKI Commands
=====

The karaf feature can be installed via the command `feature:install <feature name>` and uninstalled
in the OSGi console via the command `feature:uninstall <feature name>`. The possible feature can be
auto-completed by typing the `TAB` key.

Some features in XiPKI are listed below, a list of all available features can be retrieved via the
command `feature:list  | grep xipki` in OSGi console.

For the usage of OSGi commands, just use the option `--help`. Most XiPKI commands can 
auto-completing the options and arguments by the `TAB` key.

Feature xipki-shell-base (started by default)
-----

   * `xi:confirm`

     confirm an action

   * `xi:copy-dir`

     copy content of the directory to destination

   * `xi:copy-file`

     copy file

   * `xi:ls`

     list directory contents

   * `xi:rm`

     remove file or directory

   * `xi:mkdir`

     make directories

   * `xi:produce-password`

     produce password

   * `xi:replace`

     replace text in file

   * `xi:curl`

     transfer a URL

Feature xipki-database-tool (not started by default)
-----

   * `ca:diff-digest-db`

     diff digest XiPKI/EJBCA databas

   * `ca:digest-db`

     digest XiPKI/EJBCA database

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

   * `ca:initdb`

     reset and initialize database

   * `ca:initdb-pki`

     reset and initialize the CA and OCSP databases

   * `ca:initdb-ca`

     reset and initialize the CA database

   * `ca:initdb-ocsp`

     reset and initialize the OCSP databases

   * `ca:updatedb-ca`
     update the CA database schema

   * `ca:updatedb-ocsp`

     update the OCSP database schema

Feature xipki-security-shell (not started by default)
-----

   * `xi:cert-info`

     print certificate information

   * `xi:crl-info`

     print CRL information

   * `xi:validate-csr`

     validate CSR

   * `xi:deobfuscate`

     deobfuscate password

   * `xi:extract-cert`

     extract certificates from CRL

   * `xi:obfuscate`

     obfuscate password

   * `xi:pbe-dec`

     decrypt password with master password

   * `xi:pbe-enc`

     encrypt password with master password

   * `xi:add-cert-p11`

     add certificate to PKCS#11 device

   * `xi:rm-cert-p11`

     remove certificate from PKCS#11 device

   * `xi:export-cert-p11`

     export certificate from PKCS#11 device

   * `xi:export-cert-p12`

     export certificate from PKCS#12 keystore

   * `xi:req-p11`

     generate CSR with PKCS#11 device

   * `xi:req-p12`

     generate CSR with PKCS#12 keystore

   * `xi:update-cert-p11`

     update certificate in PKCS#11 device

   * `xi:update-cert-p12`

     update certificate in PKCS#12 keystore

   * `xi:dsa-p11`

     generate DSA keypair in PKCS#11 device

   * `xi:dsa-p12`

     generate RSA keypair in PKCS#12 keystore

   * `xi:ec-p11`

     generate EC keypair in PKCS#11 device

   * `xi:ec-p12`

     generate EC keypair in PKCS#12 keystore

   * `xi:sm2-p11`

     generate SM2 keypair in PKCS#11 device

   * `xi:sm2-p12`

     generate SM2 keypair in PKCS#12 keystore
   * `xi:delete-key-p11`

     delete key and cert in PKCS#11 device

   * `xi:token-info-p11`

     list objects in PKCS#11 device

   * `xi:delete-objects-p11`

     delete objects in PKCS#11 device

   * `xi:p11prov-test`

     test the Xipki PKCS#11 JCA/JCE provider

   * `xi:p11prov-sm2-test`

     test the SM2 implementation of the Xipki PKCS#11 JCA/JCE provider

   * `xi:refresh-p11`

     refresh PKCS#11 module
     
   * `xi:create-secretkey-p11`
     
     create secret key with given value in PKCS#11 device

   * `xi:secretkey-p11`
     
     generate secret key in PKCS#11 device
     
   * `xi:secretkey-p12`
     
     generate secret key in JCEKS (not PKCS#12) keystore
     
   * `xi:rsa-p11`

     generate RSA keypair in PKCS#11 device

   * `xi:rsa-p12`

     generate RSA keypair in PKCS#12 keystore

   * `keystore-convert`
     convert the keystore format

   * `xi:speed-dsa-gen-p11`

     performance test of PKCS#11 DSA key generation

   * `xi:speed-dsa-gen-p12`

     performance test of PKCS#12 DSA key generation

   * `xi:speed-dsa-sign-p11`

     performance test of PKCS#11 DSA signature creation

   * `xi:speed-dsa-sign-p12`

     performance test of PKCS#12 DSA signature creation

   * `xi:speed-ec-gen-p11`

     performance test of PKCS#11 EC key generation

   * `xi:speed-ec-gen-p12`

     performance test of PKCS#12 EC key generation

   * `xi:speed-ec-sign-p11`

     performance test of PKCS#11 EC signature creation

   * `xi:speed-ec-sign-p12`

     performance test of PKCS#12 EC signature creation

   * `xi:speed-sm2-gen-p11`

     performance test of PKCS#11 SM2 key generation

   * `xi:speed-sm2-gen-p12`

     performance test of PKCS#12 SM2 key generation

   * `xi:speed-sm2-sign-p11`

     performance test of PKCS#11 SM2 signature creation

   * `xi:speed-sm2-sign-p12`

     performance test of PKCS#12 SM2 signature creation

   * `xi:speed-rsa-gen-p11`

     performance test of PKCS#11 RSA key generation

   * `xi:speed-rsa-gen-p12`

     performance test of PKCS#12 RSA key generation

   * `xi:speed-rsa-sign-p11`

     performance test of PKCS#11 RSA signature creation

   * `xi:speed-rsa-sign-p12`

     performance test of PKCS#12 RSA signature creation

   * `xi:bspeed-dsa-gen-p11`

     performance test of PKCS#11 DSA key generation (batch)

   * `xi:bspeed-dsa-gen-p12`

     performance test of PKCS#12 DSA key generation (batch)

   * `xi:bspeed-dsa-sign-p11`

     performance test of PKCS#11 DSA signature creation (batch)

   * `xi:bspeed-dsa-sign-p12`

     performance test of PKCS#12 DSA signature creation (batch)

   * `xi:bspeed-ec-gen-p11`

     performance test of PKCS#11 EC key generation (batch)

   * `xi:bspeed-ec-gen-p12`

     performance test of PKCS#12 EC key generation (batch)

   * `xi:bspeed-ec-sign-p11`

     performance test of PKCS#11 EC signature creation (batch)

   * `xi:bspeed-ec-sign-p12`

     performance test of PKCS#12 EC signature creation (batch)

   * `xi:bspeed-rsa-gen-p11`

     performance test of PKCS#11 RSA key generation (batch)

   * `xi:bspeed-rsa-gen-p12`

     performance test of PKCS#12 RSA key generation (batch)

   * `xi:bspeed-rsa-sign-p11`

     performance test of PKCS#11 RSA signature creation (batch)

   * `xi:bspeed-rsa-sign-p12`

     performance test of PKCS#12 RSA signature creation (batch)

Feature xipki-camgmt-shell (started by default)
-----

   * `ca:ca-add`

     add CA

   * `ca:caalias-add`

     add CA alias

   * `ca:caalias-info`

     show information of CA alias

   * `ca:caalias-rm`

     remove CA alias

   * `ca:gen-rca`

     generate selfsigned CA

   * `ca:ca-info`

     show information of CA

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

   * `ca:ca-rm`

     remove CA

   * `ca:careq-add`

     add requestor to CA

   * `ca:careq-info`

     show information of requestor in CA

   * `ca:careq-rm`

     remove requestor from CA

   * `ca:causer-add`

     add user to CA

   * `ca:causer-info`

     show information of user in CA

   * `ca:causer-rm`

     remove user from CA

   * `ca:ca-revoke`

     revoke CA

   * `ca:export-conf`

     export configuration to zip file

   * `ca:load-conf`

     load configuration

   * `ca:notify-change`

     notify the change of CA system

   * `ca:restart`

     restart CA system

   * `ca:system-status`

     show CA system status

   * `ca:unlock`

     unlock CA system

   * `ca:ca-unrevoke`

     unrevoke CA

   * `ca:ca-up`

     update CA

   * `ca:clear-publishqueue`

     clear publish queue

   * `ca:cmpcontrol-add`

     add CMP control

   * `ca:cmpcontrol-info`

     show information of CMP control

   * `ca:cmpcontrol-rm`

     remove CMP control

   * `ca:cmpcontrol-up`

     update CMP control

   * `ca:crlsigner-add`

     add CRL signer

   * `ca:crlsigner-info`

     show information of CRL signer

   * `ca:crlsigner-rm`

     remove CRL signer

   * `ca:crlsigner-up`

     update CRL signer

   * `ca:env-add`

     add CA environment parameter

   * `ca:env-info`

     show information of CA environment parameter

   * `ca:env-rm`

     remove CA environment parameter

   * `ca:env-up`

     update CA environment parameter

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

   * `ca:responder-add`

     add responder

   * `ca:responder-info`

     show information of responder

   * `ca:responder-rm`

     remove responder

   * `ca:responder-up`

     update responder

   * `ca:scep-add`

     add SCEP

   * `ca:scep-info`

     show information of SCEP

   * `ca:scep-rm`

     remove SCEP

   * `ca:scep-up`

     update SCEP

   * `ca:user-add`

     add user

   * `ca:user-info`

     show information of user

   * `ca:user-rm`

      remove user

   * `ca:user-up`

     update user

   * `ca:cert-status`

     show certificate status

   * `ca:enroll-cert`

     enroll certificate

   * `ca:gencrl`

     generate CRL

   * `ca:getcrl`

     download CRL

   * `ca:remove-cert`

     remove certificate

   * `ca:revoke-cert`

     revoke certificate

   * `ca:unrevoke-cert`

     unrevoke certificate

   * `ca:list-cert`

     show a list of certificates

   * `ca:get-cert`

     get certificate

   * `ca:get-request`

     get certificate request

