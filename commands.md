XiPKI SDK Commands
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

   * `xi:add-cert`

     add certificate to PKCS#11 device

   * `xi:rm-cert`

     remove certificate from PKCS#11 device

   * `xi:export-cert`

     export certificate from PKCS#11 device

   * `xi:export-cert-p12`

     export certificate from PKCS#12 keystore

   * `xi:req`

     generate CSR with PKCS#11 device

   * `xi:req-p12`

     generate CSR with PKCS#12 keystore

   * `xi:update-cert`

     update certificate in PKCS#11 device

   * `xi:update-cert-p12`

     update certificate in PKCS#12 keystore

   * `xi:dsa`

     generate DSA keypair in PKCS#11 device

   * `xi:dsa-p12`

     generate RSA keypair in PKCS#12 keystore

   * `xi:ec`

     generate EC keypair in PKCS#11 device

   * `xi:ec-p12`

     generate EC keypair in PKCS#12 keystore

   * `xi:delete-key`

     delete key and cert in PKCS#11 device

   * `xi:token-info`

     list objects in PKCS#11 device

   * `xi:delete-objects`

     delete objects in PKCS#11 device

   * `xi:provider-test`

     test the Xipki JCA/JCE provider

   * `xi:refresh`

     refresh PKCS#11 module
     
   * `xi:create-secretkey`
     
     create secret key with given value in PKCS#11 device

   * `xi:secretkey`
     
     generate secret key in PKCS#11 device
     
   * `xi:secretkey-p12`
     
     generate secret key in JCEKS (not PKCS#12) keystore
     
   * `xi:rsa`

     generate RSA keypair in PKCS#11 device

   * `xi:rsa-p12`

     generate RSA keypair in PKCS#12 keystore

   * `keystore-convert`
     convert the keystore format

   * `xi:speed-dsa-gen`

     performance test of PKCS#11 DSA key generation

   * `xi:speed-dsa-gen-p12`

     performance test of PKCS#12 DSA key generation

   * `xi:speed-dsa-sign`

     performance test of PKCS#11 DSA signature creation

   * `xi:speed-dsa-sign-p12`

     performance test of PKCS#12 DSA signature creation

   * `xi:speed-ec-gen`

     performance test of PKCS#11 EC key generation

   * `xi:speed-ec-gen-p12`

     performance test of PKCS#12 EC key generation

   * `xi:speed-ec-sign`

     performance test of PKCS#11 EC signature creation

   * `xi:speed-ec-sign-p12`

     performance test of PKCS#12 EC signature creation

   * `xi:speed-rsa-gen`

     performance test of PKCS#11 RSA key generation

   * `xi:speed-rsa-gen-p12`

     performance test of PKCS#12 RSA key generation

   * `xi:speed-rsa-sign`

     performance test of PKCS#11 RSA signature creation

   * `xi:speed-rsa-sign-p12`

     performance test of PKCS#12 RSA signature creation

   * `xi:bspeed-dsa-gen`

     performance test of PKCS#11 DSA key generation (batch)

   * `xi:bspeed-dsa-gen-p12`

     performance test of PKCS#12 DSA key generation (batch)

   * `xi:bspeed-dsa-sign`

     performance test of PKCS#11 DSA signature creation (batch)

   * `xi:bspeed-dsa-sign-p12`

     performance test of PKCS#12 DSA signature creation (batch)

   * `xi:bspeed-ec-gen`

     performance test of PKCS#11 EC key generation (batch)

   * `xi:bspeed-ec-gen-p12`

     performance test of PKCS#12 EC key generation (batch)

   * `xi:bspeed-ec-sign`

     performance test of PKCS#11 EC signature creation (batch)

   * `xi:bspeed-ec-sign-p12`

     performance test of PKCS#12 EC signature creation (batch)

   * `xi:bspeed-rsa-gen`

     performance test of PKCS#11 RSA key generation (batch)

   * `xi:bspeed-rsa-gen-p12`

     performance test of PKCS#12 RSA key generation (batch)

   * `xi:bspeed-rsa-sign`

     performance test of PKCS#11 RSA signature creation (batch)

   * `xi:bspeed-rsa-sign-p12`

     performance test of PKCS#12 RSA signature creation (batch)

Feature xipki-caclient (started by default)
-----

   * `xi:cmp-gencrl`

     generate CRL

   * `xi:cmp-getcrl`

     download CRL

   * `xi:cmp-health`

     check healty status of CA

   * `xi:cmp-csr-enroll`

     enroll certificate via CSR

   * `xi:cmp-enroll`

     enroll certificate (PKCS#11 token)

   * `xi:cmp-enroll-p12`

     enroll certificate (PKCS#12 keystore)

   * `xi:cmp-remove-cert`

     remove certificate

   * `xi:cmp-revoke-cert`

     revoke certificate

   * `xi:cmp-unrevoke-cert`

     unrevoke certificate

   * `xi:cmp-benchmark-enroll`

     CA client enroll benchmark

   * `xi:cmp-benchmark-revoke`

     CA client revoke benchmark

   * `xi:cmp-benchmark-template-enroll`

     CA client template enroll benchmark

Feature xipki-scepclient (started by default)
-----

   * `xi:scep-certpoll`

     poll certificate

   * `xi:scep-enroll`

     enroll certificate

   * `xi:scep-getcert`

     download certificate

   * `xi:scep-getcert-qa`

     download certificate (only used for QA)

   * `xi:scep-getcrl`

	 download CRL

Feature xipki-ocspclient (started by default)
-----

   * `xi:ocsp-status`

	 request certificate status

